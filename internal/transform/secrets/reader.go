package secrets

import (
	"context"
	"fmt"
	"log/slog"
)

// Reader reads aws_sm or aws_ssm secrets by name on every call, with one
// AWS client per region. It keeps no value, so a caller that caches decides
// what a failed read means.
type Reader struct {
	read func(ctx context.Context, name string) (string, error)
}

// NewReader returns a Reader for store, aws_sm or aws_ssm.
func NewReader(store, region string, logger *slog.Logger) (*Reader, error) {
	switch store {
	case "aws_sm":
		b := newAWSSMBuilder(logger)
		return &Reader{read: func(ctx context.Context, name string) (string, error) {
			return b.fetchSecret(ctx, awsSMConfig{SecretID: name, Region: region})
		}}, nil
	case "aws_ssm":
		b := newAWSSSMBuilder(logger)
		return &Reader{read: func(ctx context.Context, name string) (string, error) {
			return b.fetchParameter(ctx, awsSSMConfig{Name: name, Region: region})
		}}, nil
	default:
		return nil, fmt.Errorf("store %q is not aws_sm or aws_ssm", store)
	}
}

func (r *Reader) Read(ctx context.Context, name string) (string, error) {
	return r.read(ctx, name)
}
