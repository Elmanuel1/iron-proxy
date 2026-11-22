package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func TestStartMetrics(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	startMetrics(context.Background(), slog.Default())
	_, isSDK := otel.GetMeterProvider().(*sdkmetric.MeterProvider)
	require.False(t, isSDK, "no endpoint leaves the no-op provider")

	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", collector.URL+"/v1/metrics")
	startMetrics(context.Background(), slog.Default())
	mp, isSDK := otel.GetMeterProvider().(*sdkmetric.MeterProvider)
	require.True(t, isSDK)
	require.NoError(t, mp.Shutdown(context.Background()))
}
