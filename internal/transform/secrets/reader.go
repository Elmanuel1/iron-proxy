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
	region string
	sm     *awsSMBuilder
	ssm    *awsSSMBuilder
}

// NewReader returns a Reader for store, aws_sm or aws_ssm.
func NewReader(store, region string, logger *slog.Logger) (*Reader, error) {
	switch store {
	case "aws_sm":
		return &Reader{region: region, sm: newAWSSMBuilder(logger)}, nil
	case "aws_ssm":
		return &Reader{region: region, ssm: newAWSSSMBuilder(logger)}, nil
	default:
		return nil, fmt.Errorf("store %q is not aws_sm or aws_ssm", store)
	}
}

// Read is bounded by fetchTimeout, as the cached sources are, because the
// request context it is given carries no deadline.
func (r *Reader) Read(ctx context.Context, name string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	if r.sm != nil {
		return r.sm.fetchSecret(ctx, awsSMConfig{SecretID: name, Region: r.region})
	}
	return r.ssm.fetchParameter(ctx, awsSSMConfig{Name: name, Region: r.region})
}
