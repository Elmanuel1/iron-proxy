package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/sessionswap"
)

type swapPorts struct{}

var swapPattern = regexp.MustCompile(`ph-[a-z]+`)

func (swapPorts) Find(text string) []string { return swapPattern.FindAllString(text, -1) }

func (swapPorts) Verify(p string) (sessionswap.Claim, bool) {
	if p != "ph-own" {
		return sessionswap.Claim{}, false
	}
	return sessionswap.Claim{Session: "sesn_a", Credential: "cred_a", Secret: "s"}, true
}

func (swapPorts) Fingerprint(string) string { return "fp" }

func (swapPorts) Check(_ context.Context, session, token string) (sessionswap.Caller, error) {
	if session != "sesn_a" || token != "tok_a" {
		return sessionswap.Caller{}, sessionswap.ErrRefused
	}
	return sessionswap.Caller{Session: session, Environment: "env_a"}, nil
}

func (swapPorts) Egress(context.Context, string) (sessionswap.Policy, error) {
	return sessionswap.Policy{Unrestricted: true}, nil
}

func (swapPorts) Read(context.Context, sessionswap.Claim) (sessionswap.Value, error) {
	return sessionswap.Value{Secret: "real-value", Header: true, Body: true}, nil
}

func newSwapTransform() transform.Transformer {
	return sessionswap.New(sessionswap.Options{
		Name:         "agentd_session_swap",
		Placeholders: swapPorts{},
		Callers:      swapPorts{},
		Policies:     swapPorts{},
		Values:       swapPorts{},
		Logger:       testLogger(),
	})
}

func proxyBasic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// dialProxy dials the tunnel listener under the test's context, with a
// deadline on every read and write.
func dialProxy(t *testing.T, tunnelAddr string) net.Conn {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", tunnelAddr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	return conn
}

func TestSessionSwap_CONNECTWithoutCredentialsIs407(t *testing.T) {
	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{newSwapTransform()})
	for _, auth := range []string{"", "Proxy-Authorization: " + proxyBasic("sesn_a", "wrong") + "\r\n"} {
		conn := dialProxy(t, tunnelAddr)
		_, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n%s\r\n", auth)
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err)
		_ = resp.Body.Close()
		_ = conn.Close()
		require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	}
}

// swapThroughTunnel CONNECTs as sesn_a to host, sends one request over TLS
// with the placeholder in a header and another session's credentials in an
// inner Proxy-Authorization, and returns the proxy's response.
func swapThroughTunnel(t *testing.T, p *Proxy, tunnelAddr string, caPool *x509.CertPool, host string) *http.Response {
	t.Helper()
	conn := dialProxy(t, tunnelAddr)
	t.Cleanup(func() { _ = conn.Close() })
	_, err := fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: %s\r\n\r\n",
		host, host, proxyBasic("sesn_a", "tok_a"))
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tlsConn := tls.Client(conn, &tls.Config{RootCAs: caPool, ServerName: host})
	require.NoError(t, tlsConn.HandshakeContext(t.Context()))
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/v1", nil)
	require.NoError(t, err)
	req.Header.Set("X-Api-Key", "ph-own")
	req.Header.Set("X-Other", "ph-forged")
	req.Header.Set("Proxy-Authorization", proxyBasic("sesn_b", "tok_b"))
	require.NoError(t, req.Write(tlsConn))
	out, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Body.Close() })
	return out
}

// upstreamTransport is the proxy's real transport, dialing the test
// upstream for every host, trusting roots.
func upstreamTransport(t *testing.T, addr string, roots *x509.CertPool) *http.Transport {
	t.Helper()
	guard, err := dnsguard.New(nil)
	require.NoError(t, err)
	tr := buildTransport(nil, guard, 0, nil)
	tr.TLSClientConfig.RootCAs = roots
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}
	return tr
}

func TestSessionSwap_SwapsOverTLSAndStripsProxyAuthorization(t *testing.T) {
	var got http.Header
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p, tunnelAddr, caPool := startTunnelProxy(t, []transform.Transformer{newSwapTransform()})
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	p.transport = upstreamTransport(t, upstream.Listener.Addr().String(), roots)

	// httptest's certificate names example.com.
	resp := swapThroughTunnel(t, p, tunnelAddr, caPool, "example.com")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "real-value", got.Get("X-Api-Key"))
	require.Equal(t, "ph-forged", got.Get("X-Other"))
	require.Empty(t, got.Get("Proxy-Authorization"))
}

func TestSessionSwap_UpstreamCertificateIsVerified(t *testing.T) {
	var reached atomic.Bool
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	trusted := x509.NewCertPool()
	trusted.AddCert(upstream.Certificate())

	cases := []struct {
		name  string
		roots *x509.CertPool
		host  string
	}{
		{"certificate from an unknown authority", nil, "example.com"},
		{"host name the certificate does not name", trusted, "api.example.org"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached.Store(false)
			p, tunnelAddr, caPool := startTunnelProxy(t, []transform.Transformer{newSwapTransform()})
			p.transport = upstreamTransport(t, upstream.Listener.Addr().String(), tc.roots)
			resp := swapThroughTunnel(t, p, tunnelAddr, caPool, tc.host)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusBadGateway, resp.StatusCode, string(body))
			require.False(t, reached.Load(), "no request reaches an unverified upstream")
		})
	}
}
