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
	answer := func(ctx context.Context, name string) (string, error) {
		calls++
		_, hasDeadline := ctx.Deadline()
		require.True(t, hasDeadline, "every read is bounded")
		if fail {
			return "", errors.New("unreachable")
		}
		return name + "-v", nil
	}
	sm := &mockSMClient{fn: func(ctx context.Context, in *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		v, err := answer(ctx, aws.ToString(in.SecretId))
		if err != nil {
			return nil, err
		}
		return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(v)}, nil
	}}
	ssmc := &mockSSMClient{fn: func(ctx context.Context, in *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
		require.True(t, aws.ToBool(in.WithDecryption))
		v, err := answer(ctx, aws.ToString(in.Name))
		if err != nil {
			return nil, err
		}
		return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(v)}}, nil
	}}
	readers := map[string]*Reader{}
	for _, store := range []string{"aws_sm", "aws_ssm"} {
		r, err := NewReader(store, "us-west-2", slog.Default())
		require.NoError(t, err)
		readers[store] = r
	}
	readers["aws_sm"].sm.clientFor = func(_ context.Context, region string) (smClient, error) {
		require.Equal(t, "us-west-2", region)
		return sm, nil
	}
	readers["aws_ssm"].ssm.clientFor = func(_ context.Context, region string) (ssmClient, error) {
		require.Equal(t, "us-west-2", region)
		return ssmc, nil
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

func TestNewReaderUnknownStore(t *testing.T) {
	_, err := NewReader("env", "", slog.Default())
	require.ErrorContains(t, err, `store "env" is not aws_sm or aws_ssm`)
}
