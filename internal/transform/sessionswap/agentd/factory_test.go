package agentd

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

func TestBuild(t *testing.T) {
	env := map[string]string{
		placeholderKeysEnv: "k1:" + keyHex,
		runtimeKeysEnv:     "sk-ant-oat01-first, sk-ant-oat01-second",
	}
	good := config{AgentdURL: "https://agentd.internal", Store: "aws_sm", SecretPrefix: "agentd", Region: "us-west-2"}
	cases := []struct {
		name string
		cfg  config
		env  map[string]string
		err  string
	}{
		{"secrets manager", good, env, ""},
		{"parameter store", config{AgentdURL: good.AgentdURL, Store: "aws_ssm", SecretPrefix: "agentd"}, env, ""},
		{"no prefix", config{AgentdURL: good.AgentdURL, Store: "aws_sm"}, env, "secret_prefix"},
		{"unknown store", config{AgentdURL: good.AgentdURL, Store: "env", SecretPrefix: "agentd"}, env, "is not aws_sm or aws_ssm"},
		{"bad ttl", config{AgentdURL: good.AgentdURL, Store: "aws_sm", SecretPrefix: "agentd", TTL: "soon"}, env, "ttl"},
		{"bad url", config{AgentdURL: "agentd", Store: "aws_sm", SecretPrefix: "agentd"}, env, "must be an https URL"},
		{"no placeholder keys", good, map[string]string{runtimeKeysEnv: "k"}, placeholderKeysEnv},
		{"no runtime key", good, map[string]string{placeholderKeysEnv: "k1:" + keyHex}, runtimeKeysEnv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := build(tc.cfg, func(k string) string { return tc.env[k] }, slog.Default())
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				require.NotContains(t, err.Error(), keyHex)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, opts.Placeholders)
			require.NotNil(t, opts.Callers)
			require.NotNil(t, opts.Policies)
			require.NotNil(t, opts.Values)
		})
	}
}

func TestRegistered(t *testing.T) {
	factory, err := transform.Lookup(Name)
	require.NoError(t, err)
	t.Setenv(placeholderKeysEnv, "k1:"+keyHex)
	t.Setenv(runtimeKeysEnv, "sk-ant-oat01-x")
	var node yaml.Node
	require.NoError(t, node.Encode(map[string]string{
		"agentd_url": "https://agentd.internal", "store": "aws_sm", "secret_prefix": "agentd",
	}))
	tr, err := factory(node, slog.Default())
	require.NoError(t, err)
	require.Equal(t, Name, tr.Name())
}
