// Package agentd adapts sessionswap to agentd: its signed placeholders, its
// Managed Agents API for sessions and environments, and its sealed
// credential secrets in Secrets Manager or Parameter Store.
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

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
	"github.com/ironsh/iron-proxy/internal/transform/sessionswap"
)

// Name is the transform's name in the config.
const Name = "agentd_session_swap"

const (
	placeholderKeysEnv = "AGENTD_PLACEHOLDER_KEYS"
	runtimeKeysEnv     = "AGENTD_RUNTIME_KEYS"
	apiTimeout         = 10 * time.Second
)

func init() {
	transform.Register(Name, factory)
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

func factory(node yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var cfg config
	if err := node.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing %s config: %w", Name, err)
	}
	return build(cfg, os.Getenv, logger)
}

func build(cfg config, getenv func(string) string, logger *slog.Logger) (*sessionswap.Swap, error) {
	if cfg.SecretPrefix == "" {
		return nil, fmt.Errorf("%s requires \"secret_prefix\"", Name)
	}
	ring, err := ParseRing(getenv(placeholderKeysEnv))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", placeholderKeysEnv, err)
	}
	runtimeKey, _, _ := strings.Cut(getenv(runtimeKeysEnv), ",")
	runtimeKey = strings.TrimSpace(runtimeKey)
	if runtimeKey == "" {
		return nil, fmt.Errorf("%s: %w", runtimeKeysEnv, errors.New("no key"))
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
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if cfg.Store != "aws_sm" && cfg.Store != "aws_ssm" {
		return nil, fmt.Errorf("%s: store %q is not aws_sm or aws_ssm", Name, cfg.Store)
	}
	if cfg.TTL == "" {
		cfg.TTL = defaultTTL
	}
	if _, err := time.ParseDuration(cfg.TTL); err != nil {
		return nil, fmt.Errorf("%s: ttl: %w", Name, err)
	}
	prefix := cfg.SecretPrefix
	if cfg.Store == "aws_ssm" && !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	if err := startMetrics(); err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	return sessionswap.New(sessionswap.Options{
		Name:         Name,
		Placeholders: ring,
		Callers:      client,
		Policies:     client,
		Values:       NewStore(secrets.NewSourceBuilder(logger), cfg.Store, cfg.Region, cfg.TTL, prefix),
		Logger:       logger,
	}), nil
}
