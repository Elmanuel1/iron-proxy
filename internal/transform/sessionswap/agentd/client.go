package agentd

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ironsh/iron-proxy/internal/transform/sessionswap"
)

const (
	apiVersion = "2023-06-01"
	apiBeta    = "managed-agents-2026-04-01"
	cacheTTL   = 60 * time.Second
	maxBody    = 1 << 20
)

// packageHosts are the registries agentd opens under `limited` networking
// when an environment sets allow_package_managers.
var packageHosts = []string{
	"pypi.org",
	"files.pythonhosted.org",
	"registry.npmjs.org",
	"deb.debian.org",
	"security.debian.org",
	"dl-cdn.alpinelinux.org",
	"crates.io",
	"index.crates.io",
	"static.crates.io",
}

// Client reads sessions and environments from agentd's Managed Agents API.
// It is the sessionswap.Callers and sessionswap.Policies adapter. Each answer
// is kept for 60 s: a caller's by the digest of its session and token, an
// environment's by its id.
type Client struct {
	base       *url.URL
	runtimeKey string
	http       *http.Client
	logger     *slog.Logger
	now        func() time.Time

	mu       sync.Mutex
	callers  map[[32]byte]cached[sessionswap.Caller]
	policies map[string]cached[sessionswap.Policy]
}

type cached[T any] struct {
	value   T
	refused bool
	expires time.Time
}

// NewClient reads environments with runtimeKey. base must be https: both
// the work token and the runtime key travel on it.
func NewClient(base, runtimeKey string, logger *slog.Logger, hc *http.Client) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("agentd url %q must be an https URL", base)
	}
	noRedirects := *hc
	// A redirect could carry the bearer to plain HTTP on the same host, and
	// agentd's API answers without one.
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		base:       u,
		runtimeKey: runtimeKey,
		http:       &noRedirects,
		logger:     logger,
		now:        time.Now,
		callers:    make(map[[32]byte]cached[sessionswap.Caller]),
		policies:   make(map[string]cached[sessionswap.Policy]),
	}, nil
}

// Check reads the session with its own work token. agentd answers only for
// the session the token was minted for, and only while its work item runs.
func (c *Client) Check(ctx context.Context, session, token string) (sessionswap.Caller, error) {
	if !idPattern.MatchString(session) {
		return sessionswap.Caller{}, sessionswap.ErrRefused
	}
	key := sha256.Sum256([]byte(session + ":" + token))
	hit, found := lookup(c, c.callers, key)
	if found && hit.refused {
		return sessionswap.Caller{}, sessionswap.ErrRefused
	}
	if found {
		return hit.value, nil
	}
	var body struct {
		ID            string `json:"id"`
		EnvironmentID string `json:"environment_id"`
	}
	err := c.get(ctx, "/v1/sessions/"+url.PathEscape(session), token, &body)
	if err == nil && (body.ID != session || body.EnvironmentID == "") {
		err = sessionswap.ErrRefused
	}
	caller := sessionswap.Caller{Session: body.ID, Environment: body.EnvironmentID}
	switch {
	case errors.Is(err, sessionswap.ErrRefused):
		store(c, c.callers, key, cached[sessionswap.Caller]{refused: true})
	case err == nil:
		store(c, c.callers, key, cached[sessionswap.Caller]{value: caller})
	}
	return caller, err
}

// Egress reads the environment's networking with the runtime key. An
// environment with no networking is unrestricted, as agentd defaults it; one
// whose networking does not parse allows no host, as agentd reads it.
func (c *Client) Egress(ctx context.Context, environment string) (sessionswap.Policy, error) {
	if hit, ok := lookup(c, c.policies, environment); ok {
		return hit.value, nil
	}
	var body struct {
		Config struct {
			Networking json.RawMessage `json:"networking"`
		} `json:"config"`
	}
	if err := c.get(ctx, "/v1/environments/"+url.PathEscape(environment), c.runtimeKey, &body); err != nil {
		return sessionswap.Policy{}, err
	}
	var n struct {
		Type                 string   `json:"type"`
		AllowedHosts         []string `json:"allowed_hosts"`
		AllowPackageManagers bool     `json:"allow_package_managers"`
	}
	raw := body.Config.Networking
	if len(raw) == 0 || string(raw) == "null" {
		n.Type = "unrestricted"
	}
	if n.Type == "" && json.Unmarshal(raw, &n) != nil {
		n.Type = "unreadable"
	}
	var policy sessionswap.Policy
	switch n.Type {
	case "unrestricted":
		policy.Unrestricted = true
	case "limited":
		policy.Hosts = append([]string(nil), n.AllowedHosts...)
	default:
		c.logger.Warn("environment networking unreadable, allowing no host",
			slog.String("environment", environment), slog.String("type", n.Type))
	}
	if n.Type == "limited" && n.AllowPackageManagers {
		policy.Hosts = append(policy.Hosts, packageHosts...)
	}
	store(c, c.policies, environment, cached[sessionswap.Policy]{value: policy})
	return policy, nil
}

// get decodes a 200 answer into out. A 401, 403 or 404 is ErrRefused; any
// other answer is an error, so the caller fails closed without caching it.
func (c *Client) get(ctx context.Context, path, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.JoinPath(path).String(), nil)
	if err != nil {
		return fmt.Errorf("building agentd request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("anthropic-version", apiVersion)
	req.Header.Set("anthropic-beta", apiBeta)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("agentd %s: %w", path, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return sessionswap.ErrRefused
	default:
		return fmt.Errorf("agentd %s: status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out); err != nil {
		return fmt.Errorf("decoding agentd %s: %w", path, err)
	}
	return nil
}

func lookup[K comparable, T any](c *Client, m map[K]cached[T], key K) (cached[T], bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hit, ok := m[key]
	if !ok || !c.now().Before(hit.expires) {
		return cached[T]{}, false
	}
	return hit, true
}

func store[K comparable, T any](c *Client, m map[K]cached[T], key K, v cached[T]) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, old := range m {
		if !now.Before(old.expires) {
			delete(m, k)
		}
	}
	v.expires = now.Add(cacheTTL)
	m[key] = v
}
