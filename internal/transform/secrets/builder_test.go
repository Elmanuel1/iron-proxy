package secrets

import (
	"context"
	"log/slog"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func node(t *testing.T, cfg map[string]string) yaml.Node {
	t.Helper()
	var n yaml.Node
	require.NoError(t, n.Encode(cfg))
	return n
}

func TestSourceBuilderBuild(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]string
		err  string
	}{
		{"aws_sm", map[string]string{"type": "aws_sm", "secret_id": "a/b", "region": "us-west-2", "ttl": "5m"}, ""},
		{"aws_ssm", map[string]string{"type": "aws_ssm", "name": "/a/b", "ttl": "5m"}, ""},
		{"unknown type", map[string]string{"type": "nope"}, `unsupported source type "nope"`},
		{"bad ttl", map[string]string{"type": "aws_sm", "secret_id": "a/b", "ttl": "soon"}, "parsing ttl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, err := NewSourceBuilder(slog.Default()).Build(node(t, tc.cfg))
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, src)
		})
	}
}

func TestSourceBuilderSharesItsClients(t *testing.T) {
	b := NewSourceBuilder(slog.Default())
	var built []string
	sm := b.registry["aws_sm"].(*awsSMBuilder)
	sm.clientFor = func(_ context.Context, region string) (smClient, error) {
		built = append(built, region)
		return staticSMClient(&secretsmanager.GetSecretValueOutput{SecretString: aws.String("v")}, nil), nil
	}
	for _, id := range []string{"a", "b"} {
		src, err := b.Build(node(t, map[string]string{"type": "aws_sm", "secret_id": id, "region": "us-west-2"}))
		require.NoError(t, err)
		got, err := src.Get(context.Background())
		require.NoError(t, err)
		require.Equal(t, "v", got)
	}
	require.Equal(t, []string{"us-west-2", "us-west-2"}, built, "every source asks the one builder's client cache")
}
