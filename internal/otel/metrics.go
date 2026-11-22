package otel

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// MetricsEnabled reports whether an OTLP metrics endpoint is set in the
// environment. Metrics follow only the OTEL_* variables, never the managed
// mode log defaults, which point at a logs-only ingest.
func MetricsEnabled() bool {
	return os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") != "" ||
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != ""
}

// NewMeterProvider creates an OTEL MeterProvider exporting over OTLP,
// configured by the standard OTEL_* environment variables.
func NewMeterProvider(ctx context.Context) (*sdkmetric.MeterProvider, error) {
	protocol := os.Getenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL")
	if protocol == "" {
		protocol = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}
	if protocol == "" {
		protocol = "http/protobuf"
	}

	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "iron-proxy"
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTEL resource: %w", err)
	}

	// The resource is built first: an exporter made before a failing step
	// would hold its connection with nothing to shut it down.
	var exporter sdkmetric.Exporter
	switch protocol {
	case "http/protobuf":
		exporter, err = otlpmetrichttp.New(ctx)
	case "grpc":
		exporter, err = otlpmetricgrpc.New(ctx)
	default:
		return nil, fmt.Errorf("unsupported OTLP metrics protocol: %q (expected \"http/protobuf\" or \"grpc\")", protocol)
	}
	if err != nil {
		return nil, fmt.Errorf("creating OTLP metric exporter: %w", err)
	}

	return sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
		sdkmetric.WithResource(res),
	), nil
}
