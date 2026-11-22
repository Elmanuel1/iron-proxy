// Package agentd adapts sessionswap to agentd as the agentd_session_swap
// transform: its signed placeholders, its Managed Agents API for sessions and
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
	opts, err := build(cfg, os.Getenv, logger)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if err := startMetrics(); err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	opts.Name = Name
	opts.Logger = logger
	return sessionswap.New(opts), nil
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
