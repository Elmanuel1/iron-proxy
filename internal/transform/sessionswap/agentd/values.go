package agentd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform/secrets"
	"github.com/ironsh/iron-proxy/internal/transform/sessionswap"
)

// Store reads a credential's sealed secret, which agentd writes as JSON
// holding the value beside its networking and injection_location. It is the
// sessionswap.Values adapter. Each secret is read through iron-proxy's own
// aws_sm or aws_ssm source, built the first time its name is seen, which
// keeps the value for ttl.
type Store struct {
	builder SourceBuilder
	store   string
	region  string
	ttl     string
	prefix  string

	mu      sync.Mutex
	sources map[string]secrets.Source
}

// SourceBuilder builds a secret source from its config.
type SourceBuilder interface {
	Build(node yaml.Node) (secrets.Source, error)
}

// NewStore reads secrets named `<prefix>/<workspace>/<vault>/<credential>`
// from store, aws_sm or aws_ssm. For aws_ssm, prefix carries its leading
// slash.
func NewStore(builder SourceBuilder, store, region, ttl, prefix string) *Store {
	return &Store{
		builder: builder,
		store:   store,
		region:  region,
		ttl:     ttl,
		prefix:  prefix,
		sources: make(map[string]secrets.Source),
	}
}

func (s *Store) source(name string) (secrets.Source, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if src, ok := s.sources[name]; ok {
		return src, nil
	}
	key := "secret_id"
	if s.store == "aws_ssm" {
		key = "name"
	}
	var node yaml.Node
	if err := node.Encode(map[string]string{"type": s.store, key: name, "region": s.region, "ttl": s.ttl}); err != nil {
		return nil, fmt.Errorf("encoding source config: %w", err)
	}
	src, err := s.builder.Build(node)
	if err != nil {
		return nil, err
	}
	s.sources[name] = src
	return src, nil
}

type sealed struct {
	Type        string `json:"type"`
	SecretValue string `json:"secret_value"`
	Networking  *struct {
		Type         string   `json:"type"`
		AllowedHosts []string `json:"allowed_hosts"`
	} `json:"networking"`
	InjectionLocation *struct {
		Body   bool `json:"body"`
		Header bool `json:"header"`
	} `json:"injection_location"`
}

// Read returns the credential's value and rules. The JSON error is not
// wrapped: it can quote the value it failed on.
func (s *Store) Read(ctx context.Context, claim sessionswap.Claim) (sessionswap.Value, error) {
	src, err := s.source(s.prefix + "/" + claim.Secret)
	if err != nil {
		return sessionswap.Value{}, err
	}
	raw, err := src.Get(ctx)
	if err != nil {
		return sessionswap.Value{}, err
	}
	var m sealed
	if json.Unmarshal([]byte(raw), &m) != nil {
		return sessionswap.Value{}, errors.New("sealed secret is not valid JSON")
	}
	if m.Type != "environment_variable" || m.SecretValue == "" {
		return sessionswap.Value{}, fmt.Errorf("sealed secret is not an environment_variable credential with a value")
	}
	v := sessionswap.Value{Secret: m.SecretValue, Header: true, Body: true}
	if m.InjectionLocation != nil {
		v.Header, v.Body = m.InjectionLocation.Header, m.InjectionLocation.Body
	}
	switch {
	case m.Networking == nil, m.Networking.Type == "unrestricted":
	case m.Networking.Type == "limited":
		v.Hosts = append([]string{}, m.Networking.AllowedHosts...)
	default:
		v.Hosts = []string{}
	}
	return v, nil
}
