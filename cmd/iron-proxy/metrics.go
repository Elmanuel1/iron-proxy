package main

import (
	"context"
	"log/slog"
	"os"

	"go.opentelemetry.io/otel"

	iotel "github.com/ironsh/iron-proxy/internal/otel"
)

// Metric export starts before main so main stays as it is. It sends every
// 60 s, and a stop drops what it counted since the last send.
func init() {
	startMetrics(context.Background(), slog.Default())
}

// startMetrics sets the global meter provider to export over OTLP when an
// endpoint is set in the environment. Instruments created before it still
// report through it.
func startMetrics(ctx context.Context, logger *slog.Logger) {
	if !iotel.MetricsEnabled() {
		return
	}
	provider, err := iotel.NewMeterProvider(ctx)
	if err != nil {
		logger.Error("initializing OTEL meter provider", slog.String("error", err.Error()))
		os.Exit(1)
	}
	otel.SetMeterProvider(provider)
}
