package secrets

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stretchr/testify/require"
)

func TestReaderReadsEveryCall(t *testing.T) {
	var calls int
	var fail bool
	sm := &mockSMClient{fn: func(_ context.Context, in *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		calls++
		if fail {
			return nil, errors.New("unreachable")
		}
		return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(aws.ToString(in.SecretId) + "-v")}, nil
	}}
	ssmc := &mockSSMClient{fn: func(_ context.Context, in *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
		calls++
		if fail {
			return nil, errors.New("unreachable")
		}
		require.True(t, aws.ToBool(in.WithDecryption))
		return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(aws.ToString(in.Name) + "-v")}}, nil
	}}
	readers := map[string]*Reader{
		"aws_sm": {read: func(ctx context.Context, name string) (string, error) {
			return newTestAWSSMBuilder(sm).fetchSecret(ctx, awsSMConfig{SecretID: name})
		}},
		"aws_ssm": {read: func(ctx context.Context, name string) (string, error) {
			return newTestAWSSSMBuilder(ssmc).fetchParameter(ctx, awsSSMConfig{Name: name})
		}},
	}
	for name, r := range readers {
		t.Run(name, func(t *testing.T) {
			calls, fail = 0, false
			for range 2 {
				got, err := r.Read(context.Background(), "a/b")
				require.NoError(t, err)
				require.Equal(t, "a/b-v", got)
			}
			require.Equal(t, 2, calls, "no value is kept")
			fail = true
			_, err := r.Read(context.Background(), "a/b")
			require.ErrorContains(t, err, "unreachable")
		})
	}
}

func TestNewReader(t *testing.T) {
	for _, store := range []string{"aws_sm", "aws_ssm"} {
		r, err := NewReader(store, "us-west-2", slog.Default())
		require.NoError(t, err)
		require.NotNil(t, r)
	}
	_, err := NewReader("env", "", slog.Default())
	require.ErrorContains(t, err, `store "env" is not aws_sm or aws_ssm`)
}
