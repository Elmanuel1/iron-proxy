// Package agentd is the session_swap provider for agentd (`provider:
// agentd`): its signed placeholders, its Managed Agents API for sessions and
// environments, and its sealed credential secrets in Secrets Manager or
// Parameter Store.
package agentd

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform/secrets"
	"github.com/ironsh/iron-proxy/internal/transform/sessionswap"
)

// Name is the provider's name in the config.
const Name = "agentd"

const (
	placeholderKeysEnv = "AGENTD_PLACEHOLDER_KEYS"
	runtimeKeysEnv     = "AGENTD_RUNTIME_KEYS"
	apiTimeout         = 10 * time.Second
)

func init() {
	sessionswap.RegisterProvider(Name, provider)
}

type config struct {
	AgentdURL    string `yaml:"agentd_url"`
	Store        string `yaml:"store"`
	SecretPrefix string `yaml:"secret_prefix"`
	Region       string `yaml:"region,omitempty"`
	TTL          string `yaml:"ttl,omitempty"`
}

// defaultTTL is how long a value is kept before it is read again, the
// lifetime agentd's design gives a copy of a credential's sealed secret.
const defaultTTL = "5m"

func provider(node yaml.Node, logger *slog.Logger) (sessionswap.Options, error) {
	var cfg config
	if err := node.Decode(&cfg); err != nil {
		return sessionswap.Options{}, fmt.Errorf("parsing config: %w", err)
	}
	return build(cfg, os.Getenv, logger)
}

func build(cfg config, getenv func(string) string, logger *slog.Logger) (sessionswap.Options, error) {
	if cfg.SecretPrefix == "" {
		return sessionswap.Options{}, errors.New("requires \"secret_prefix\"")
	}
	ring, err := ParseRing(getenv(placeholderKeysEnv))
	if err != nil {
		return sessionswap.Options{}, fmt.Errorf("%s: %w", placeholderKeysEnv, err)
	}
	runtimeKey, _, _ := strings.Cut(getenv(runtimeKeysEnv), ",")
	runtimeKey = strings.TrimSpace(runtimeKey)
	if runtimeKey == "" {
		return sessionswap.Options{}, fmt.Errorf("%s: %w", runtimeKeysEnv, errors.New("no key"))
	}
	client, err := NewClient(cfg.AgentdURL, runtimeKey, logger, &http.Client{
		Timeout: apiTimeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: apiTimeout,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
		},
	})
	if err != nil {
		return sessionswap.Options{}, err
	}
	reader, err := secrets.NewReader(cfg.Store, cfg.Region, logger)
	if err != nil {
		return sessionswap.Options{}, err
	}
	if cfg.TTL == "" {
		cfg.TTL = defaultTTL
	}
	ttl, err := time.ParseDuration(cfg.TTL)
	if err != nil {
		return sessionswap.Options{}, fmt.Errorf("ttl: %w", err)
	}
	prefix := cfg.SecretPrefix
	if cfg.Store == "aws_ssm" && !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return sessionswap.Options{
		Placeholders: ring,
		Callers:      client,
		Policies:     client,
		Values:       NewStore(reader, ttl, prefix),
	}, nil
}
