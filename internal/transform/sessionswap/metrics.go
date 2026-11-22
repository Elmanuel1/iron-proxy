package sessionswap

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "github.com/ironsh/iron-proxy/internal/transform/sessionswap"

// metrics are read from the global meter provider, which stays a no-op
// unless the process exports metrics over OTLP.
type metrics struct {
	swaps        metric.Int64Counter
	refusals     metric.Int64Counter
	readFailures metric.Int64Counter
}

func newMetrics() metrics {
	m := otel.Meter(meterName)
	// Each call returns a usable no-op instrument alongside any error, so an
	// error is reported and the instrument kept.
	swaps, swapsErr := m.Int64Counter("proxy_swaps",
		metric.WithDescription("Placeholders replaced with a credential value."))
	refusals, refusalsErr := m.Int64Counter("proxy_refusals",
		metric.WithDescription("Requests refused, by reason."))
	readFailures, readErr := m.Int64Counter("proxy_read_failures",
		metric.WithDescription("Credential values that could not be read."))
	if err := errors.Join(swapsErr, refusalsErr, readErr); err != nil {
		otel.Handle(err)
	}
	return metrics{swaps: swaps, refusals: refusals, readFailures: readFailures}
}

func (m metrics) refuse(ctx context.Context, reason string) {
	m.refusals.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
}
