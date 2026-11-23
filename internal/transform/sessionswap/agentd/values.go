package agentd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ironsh/iron-proxy/internal/transform/sessionswap"
)

// Store reads a credential's sealed secret, which agentd writes as JSON
// holding the value beside its networking and injection_location. It is the
// sessionswap.Values adapter. A secret read within ttl is reused; after ttl
// it is read again, and a failed read fails the request rather than reuse
// the old value, so a revoked credential stops being swapped.
type Store struct {
	reader Reader
	ttl    time.Duration
	prefix string
	now    func() time.Time

	mu    sync.Mutex
	reads map[string]read
}

type Reader interface {
	Read(ctx context.Context, name string) (string, error)
}

type read struct {
	raw     string
	expires time.Time
}

// NewStore reads secrets named `<prefix>/<workspace>/<vault>/<credential>`.
// For Parameter Store, prefix carries its leading slash.
func NewStore(reader Reader, ttl time.Duration, prefix string) *Store {
	return &Store{reader: reader, ttl: ttl, prefix: prefix, now: time.Now, reads: make(map[string]read)}
}

func (s *Store) raw(ctx context.Context, name string) (string, error) {
	s.mu.Lock()
	hit, ok := s.reads[name]
	s.mu.Unlock()
	if ok && s.now().Before(hit.expires) {
		return hit.raw, nil
	}
	raw, err := s.reader.Read(ctx, name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		delete(s.reads, name)
		return "", err
	}
	s.reads[name] = read{raw: raw, expires: s.now().Add(s.ttl)}
	return raw, nil
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
	raw, err := s.raw(ctx, s.prefix+"/"+claim.Secret)
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
