package sessionswap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestMetrics(t *testing.T) {
	// The transform is built before the meter provider is set, as the proxy
	// builds its pipeline before it starts telemetry.
	h := newHarness(Policy{Hosts: []string{"api.example.com"}}, everywhere())
	reader := sdkmetric.NewManualReader()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))

	tunnel := h.bound(t)
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	req.Header.Set("X-Api-Key", ownPlaceholder)
	_, _, err := h.inner(t, tunnel, req, true)
	require.NoError(t, err)

	_, _, err = h.connect(t, "api.example.com:443", "")
	require.NoError(t, err)
	_, _, err = h.connect(t, "evil.example.org:443", basic("sesn_a", "tok_a"))
	require.NoError(t, err)

	h.values.err = errDown
	req = httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	req.Header.Set("X-Api-Key", ownPlaceholder)
	_, _, err = h.inner(t, tunnel, req, true)
	require.Error(t, err)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				key := m.Name
				if reason, ok := dp.Attributes.Value(attribute.Key("reason")); ok {
					key += "/" + reason.AsString()
				}
				got[key] += dp.Value
			}
		}
	}
	require.Equal(t, map[string]int64{
		"proxy_swaps":                  1,
		"proxy_refusals/proxy_auth":    1,
		"proxy_refusals/egress_policy": 1,
		"proxy_read_failures":          1,
	}, got)
}
