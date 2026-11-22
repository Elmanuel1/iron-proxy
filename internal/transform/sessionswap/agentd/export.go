package agentd

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"

	iotel "github.com/ironsh/iron-proxy/internal/otel"
)

// startMetrics starts OTLP metric export once, with the first transform
// built, so a proxy that does not configure this transform exports nothing
// new. The exporter runs for the life of the process.
var startMetrics = sync.OnceValue(exportMetrics)

// exportMetrics sets the global meter provider to export over OTLP when an
// endpoint is set in the environment. Instruments created before it still
// report through it.
func exportMetrics() error {
	if !iotel.MetricsEnabled() {
		return nil
	}
	provider, err := iotel.NewMeterProvider(context.Background())
	if err != nil {
		return err
	}
	otel.SetMeterProvider(provider)
	return nil
}
