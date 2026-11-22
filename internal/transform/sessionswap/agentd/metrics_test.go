package agentd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func TestExportMetrics(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	require.NoError(t, exportMetrics())
	_, isSDK := otel.GetMeterProvider().(*sdkmetric.MeterProvider)
	require.False(t, isSDK, "no endpoint leaves the no-op provider")

	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "http/json")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "http://127.0.0.1:1/v1/metrics")
	require.ErrorContains(t, exportMetrics(), "unsupported OTLP metrics protocol")

	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", collector.URL+"/v1/metrics")
	require.NoError(t, exportMetrics())
	mp, isSDK := otel.GetMeterProvider().(*sdkmetric.MeterProvider)
	require.True(t, isSDK)
	require.NoError(t, mp.Shutdown(context.Background()))
}
