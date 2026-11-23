package otel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestMetricsEnabled(t *testing.T) {
	cases := []struct {
		name, endpoint, metricsEndpoint string
		want                            bool
	}{
		{"no endpoint", "", "", false},
		{"shared endpoint", "https://collector", "", true},
		{"metrics endpoint", "", "https://collector/v1/metrics", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", tc.endpoint)
			t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", tc.metricsEndpoint)
			require.Equal(t, tc.want, MetricsEnabled())
		})
	}
}

func TestNewMeterProviderProtocol(t *testing.T) {
	cases := []struct {
		name, protocol, metricsProtocol, err string
	}{
		{"default http/protobuf", "", "", ""},
		{"grpc", "grpc", "", ""},
		{"metrics protocol wins", "bogus", "http/protobuf", ""},
		{"unsupported", "", "http/json", `unsupported OTLP metrics protocol: "http/json"`},
	}
	httpCollector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpCollector.Close()
	grpcCollector := newGRPCCollector(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := httpCollector.URL
			if tc.protocol == "grpc" {
				endpoint = grpcCollector
			}
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)
			t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
			t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", tc.protocol)
			t.Setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", tc.metricsProtocol)
			mp, err := NewMeterProvider(context.Background())
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, mp.Shutdown(ctx))
		})
	}
}

// newGRPCCollector accepts every gRPC call with an empty answer, which
// decodes as an empty OTLP export response.
func newGRPCCollector(t *testing.T) string {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		if err := stream.RecvMsg(&emptypb.Empty{}); err != nil {
			return err
		}
		return stream.SendMsg(&emptypb.Empty{})
	}))
	// Serve returns once Stop closes the listener; its error says only that.
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return "http://" + lis.Addr().String()
}

func TestNewMeterProviderExportsOverOTLP(t *testing.T) {
	var posts atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/metrics" {
			posts.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "")

	mp, err := NewMeterProvider(context.Background())
	require.NoError(t, err)
	counter, err := mp.Meter("test").Int64Counter("proxy_swaps")
	require.NoError(t, err)
	counter.Add(context.Background(), 1)
	require.NoError(t, mp.Shutdown(context.Background()))
	require.GreaterOrEqual(t, posts.Load(), int32(1))
}
