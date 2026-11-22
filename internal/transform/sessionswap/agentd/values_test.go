package agentd

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform/secrets"
	"github.com/ironsh/iron-proxy/internal/transform/sessionswap"
)

type fakeSource struct {
	value string
	err   error
}

func (f *fakeSource) Name() string { return "fake" }

func (f *fakeSource) Get(context.Context) (string, error) { return f.value, f.err }

type fakeBuilder struct {
	sources map[string]*fakeSource
	configs []map[string]string
}

func (f *fakeBuilder) Build(node yaml.Node) (secrets.Source, error) {
	var cfg map[string]string
	if err := node.Decode(&cfg); err != nil {
		return nil, err
	}
	f.configs = append(f.configs, cfg)
	name := cfg["secret_id"] + cfg["name"]
	src, ok := f.sources[name]
	if !ok {
		return nil, errors.New("no such source")
	}
	return src, nil
}

var claim = sessionswap.Claim{Session: "sesn_1", Credential: "cred_1", Secret: "wrkspc_1/vlt_1/cred_1"}

func TestStoreRead(t *testing.T) {
	const name = "agentd/wrkspc_1/vlt_1/cred_1"
	cases := []struct {
		name   string
		sealed string
		want   sessionswap.Value
		err    string
	}{
		{
			name:   "limited, header only",
			sealed: `{"type":"environment_variable","secret_name":"K","secret_value":"v1","networking":{"type":"limited","allowed_hosts":["*.x.com"]},"injection_location":{"body":false,"header":true}}`,
			want:   sessionswap.Value{Secret: "v1", Hosts: []string{"*.x.com"}, Header: true},
		},
		{
			name:   "unrestricted, both locations",
			sealed: `{"type":"environment_variable","secret_value":"v1","networking":{"type":"unrestricted"},"injection_location":{"body":true,"header":true}}`,
			want:   sessionswap.Value{Secret: "v1", Header: true, Body: true},
		},
		{
			name:   "no location defaults to both",
			sealed: `{"type":"environment_variable","secret_value":"v1","networking":{"type":"unrestricted"}}`,
			want:   sessionswap.Value{Secret: "v1", Header: true, Body: true},
		},
		{
			name:   "limited with no hosts",
			sealed: `{"type":"environment_variable","secret_value":"v1","networking":{"type":"limited"}}`,
			want:   sessionswap.Value{Secret: "v1", Hosts: []string{}, Header: true, Body: true},
		},
		{
			name:   "unknown networking allows no host",
			sealed: `{"type":"environment_variable","secret_value":"v1","networking":{"type":"open"}}`,
			want:   sessionswap.Value{Secret: "v1", Hosts: []string{}, Header: true, Body: true},
		},
		{name: "another credential type", sealed: `{"type":"static_bearer","token":"t-1"}`, err: "not an environment_variable"},
		{name: "no value", sealed: `{"type":"environment_variable","secret_value":""}`, err: "not an environment_variable"},
		{name: "not json", sealed: `secret-value-in-the-clear`, err: "not valid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &fakeBuilder{sources: map[string]*fakeSource{name: {value: tc.sealed}}}
			got, err := NewStore(b, "aws_sm", "us-west-2", "5m", "agentd").Read(context.Background(), claim)
			require.Equal(t, []map[string]string{{"type": "aws_sm", "secret_id": name, "region": "us-west-2", "ttl": "5m"}}, b.configs)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				require.NotContains(t, err.Error(), "secret-value-in-the-clear")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestStoreBuildsOneSourcePerSecret(t *testing.T) {
	const name = "/agentd/wrkspc_1/vlt_1/cred_1"
	src := &fakeSource{value: `{"type":"environment_variable","secret_value":"v"}`}
	b := &fakeBuilder{sources: map[string]*fakeSource{name: src}}
	s := NewStore(b, "aws_ssm", "", "1m", "/agentd")
	for range 2 {
		_, err := s.Read(context.Background(), claim)
		require.NoError(t, err)
	}
	require.Equal(t, []map[string]string{{"type": "aws_ssm", "name": name, "region": "", "ttl": "1m"}}, b.configs)

	src.err = errors.New("throttled")
	_, err := s.Read(context.Background(), claim)
	require.ErrorContains(t, err, "throttled")
}

func TestStoreUnknownSecret(t *testing.T) {
	_, err := NewStore(&fakeBuilder{}, "aws_sm", "", "5m", "agentd").Read(context.Background(), claim)
	require.ErrorContains(t, err, "no such source")
}
