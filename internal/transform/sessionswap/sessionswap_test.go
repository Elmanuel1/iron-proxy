package sessionswap

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

func TestConnectAuthentication(t *testing.T) {
	cases := []struct {
		name   string
		auth   string
		status int
	}{
		{"no header", "", http.StatusProxyAuthRequired},
		{"not basic", "Bearer tok_a", http.StatusProxyAuthRequired},
		{"bad base64", "Basic !!!", http.StatusProxyAuthRequired},
		{"no colon", "Basic " + "c2Vzbl9h", http.StatusProxyAuthRequired},
		{"wrong token", basic("sesn_a", "tok_b"), http.StatusProxyAuthRequired},
		{"other session", basic("sesn_b", "tok_a"), http.StatusProxyAuthRequired},
		{"valid pair", basic("sesn_a", "tok_a"), 0},
		{"empty token", basic("sesn_a", ""), http.StatusProxyAuthRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(unrestricted(), everywhere())
			res, tunnel, err := h.connect(t, "api.example.com:443", tc.auth)
			require.NoError(t, err)
			if tc.status == 0 {
				require.Equal(t, transform.ActionContinue, res.Action)
				require.Equal(t, "sesn_a", tunnel.RequestTransforms[0].Annotations[annotationSession])
				require.Equal(t, "env_a", tunnel.RequestTransforms[0].Annotations[annotationEnvironment])
				return
			}
			require.Equal(t, transform.ActionReject, res.Action)
			require.Equal(t, tc.status, res.Response.StatusCode)
			require.Equal(t, `Basic realm="iron-proxy"`, res.Response.Header.Get("Proxy-Authenticate"))
		})
	}
}

func TestCallersUnavailableFailsClosed(t *testing.T) {
	h := newHarness(unrestricted(), everywhere())
	h.callers.err = errDown
	_, _, err := h.connect(t, "api.example.com:443", basic("sesn_a", "tok_a"))
	require.ErrorIs(t, err, errDown)
}

func TestInnerRequestUsesTunnelIdentity(t *testing.T) {
	h := newHarness(unrestricted(), everywhere())
	tunnel := h.bound(t)

	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	req.Header.Set("Proxy-Authorization", basic("sesn_b", "tok_b"))
	req.Header.Set("Authorization", "Bearer "+ownPlaceholder)
	res, _, err := h.inner(t, tunnel, req, true)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer "+realValue, req.Header.Get("Authorization"))
	require.Empty(t, req.Header.Values("Proxy-Authorization"), "the ignored inner header is removed")
	require.Equal(t, 1, h.callers.calls, "the tunnel is checked once, at CONNECT")

	unbound := &transform.TunnelInfo{Target: "api.example.com:443"}
	req = httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	req.Header.Set("Proxy-Authorization", basic("sesn_a", "tok_a"))
	res, _, err = h.inner(t, unbound, req, true)
	require.NoError(t, err)
	require.Equal(t, http.StatusProxyAuthRequired, res.Response.StatusCode)
}

func TestAbsoluteFormHTTPAuthenticatesItself(t *testing.T) {
	h := newHarness(unrestricted(), everywhere())
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/v1", nil)
	req.Header.Set("Authorization", "Bearer "+ownPlaceholder)
	res, _, err := h.inner(t, nil, req, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusProxyAuthRequired, res.Response.StatusCode)

	req.Header.Set("Proxy-Authorization", basic("sesn_a", "tok_a"))
	res, _, err = h.inner(t, nil, req, false)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer "+ownPlaceholder, req.Header.Get("Authorization"), "plain HTTP is never swapped")
}

func TestSwapDecisions(t *testing.T) {
	cases := []struct {
		name        string
		value       Value
		host        string
		placeholder string
		tls         bool
		swapped     bool
	}{
		{"own placeholder over TLS", everywhere(), "api.example.com", ownPlaceholder, true, true},
		{"another session's placeholder", everywhere(), "api.example.com", otherPlaceholder, true, false},
		{"bad signature", everywhere(), "api.example.com", forgedPlaceholder, true, false},
		{"plain HTTP", everywhere(), "api.example.com", ownPlaceholder, false, false},
		{"allowed host glob", Value{Secret: realValue, Header: true, Hosts: []string{"*.example.com"}}, "api.example.com", ownPlaceholder, true, true},
		{"host outside the credential's list", Value{Secret: realValue, Header: true, Hosts: []string{"api.github.com"}}, "api.example.com", ownPlaceholder, true, false},
		{"empty host list", Value{Secret: realValue, Header: true, Hosts: []string{}}, "api.example.com", ownPlaceholder, true, false},
		{"header not allowed", Value{Secret: realValue, Body: true}, "api.example.com", ownPlaceholder, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(unrestricted(), tc.value)
			tunnel := h.bound(t)
			scheme := "http"
			if tc.tls {
				scheme = "https"
			}
			req := httptest.NewRequest(http.MethodGet, scheme+"://"+tc.host+"/v1", nil)
			req.Header.Set("X-Api-Key", tc.placeholder)
			_, tctx, err := h.inner(t, tunnel, req, tc.tls)
			require.NoError(t, err)
			want := tc.placeholder
			if tc.swapped {
				want = realValue
			}
			require.Equal(t, want, req.Header.Get("X-Api-Key"))
			_, annotated := tctx.DrainAnnotations()["swapped"]
			require.Equal(t, tc.swapped, annotated)
		})
	}
}

func TestSwapLocations(t *testing.T) {
	body := `{"key":"` + ownPlaceholder + `"}`
	cases := []struct {
		name       string
		value      Value
		wantHeader string
		wantBody   string
	}{
		{"header and body", everywhere(), realValue, `{"key":"` + realValue + `"}`},
		{"header only", Value{Secret: realValue, Header: true}, realValue, body},
		{"body only", Value{Secret: realValue, Body: true}, ownPlaceholder, `{"key":"` + realValue + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(unrestricted(), tc.value)
			tunnel := h.bound(t)
			req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1", strings.NewReader(body))
			req.Header.Set("X-Api-Key", ownPlaceholder)
			_, _, err := h.inner(t, tunnel, req, true)
			require.NoError(t, err)
			require.Equal(t, tc.wantHeader, req.Header.Get("X-Api-Key"))
			got, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			require.Equal(t, tc.wantBody, string(got))
			require.Equal(t, int64(len(tc.wantBody)), req.ContentLength)
		})
	}
}

func TestBodyIsReadWholeAndOnlyUpToTheCap(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		swapped bool
	}{
		{"longer than the proxy's buffer", ownPlaceholder + " " + strings.Repeat("x", 64), true},
		{"over the cap", ownPlaceholder + " " + strings.Repeat("x", maxBodyBytes), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(unrestricted(), everywhere())
			tunnel := h.bound(t)
			req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1", strings.NewReader(tc.body))
			req.Body = transform.NewBufferedBody(req.Body, 16)
			_, err := h.swap.TransformRequest(t.Context(), &transform.TransformContext{Tunnel: tunnel}, req)
			require.NoError(t, err)
			got, err := io.ReadAll(transform.RequireBufferedBody(req.Body).StreamingReader())
			require.NoError(t, err)
			want := tc.body
			if tc.swapped {
				want = strings.Replace(tc.body, ownPlaceholder, realValue, 1)
			}
			require.Equal(t, want, string(got), "the body is never cut")
		})
	}
}

func TestUnreadableValueFailsTheRequest(t *testing.T) {
	h := newHarness(unrestricted(), everywhere())
	h.values.err = errDown
	tunnel := h.bound(t)
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	req.Header.Set("X-Api-Key", ownPlaceholder)
	_, _, err := h.inner(t, tunnel, req, true)
	require.ErrorIs(t, err, errDown)
	require.Contains(t, h.logs.String(), `"credential":"cred_own"`)

	req = httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	req.Header.Set("X-Api-Key", otherPlaceholder)
	_, _, err = h.inner(t, tunnel, req, true)
	require.NoError(t, err, "a placeholder the caller does not own is never read")
}

func TestValueIsReadOnEverySwap(t *testing.T) {
	h := newHarness(unrestricted(), everywhere())
	tunnel := h.bound(t)
	for _, v := range []string{"first-value", "rotated-value"} {
		h.values.value.Secret = v
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
		req.Header.Set("X-Api-Key", ownPlaceholder)
		_, _, err := h.inner(t, tunnel, req, true)
		require.NoError(t, err)
		require.Equal(t, v, req.Header.Get("X-Api-Key"))
	}
	require.Equal(t, 2, h.values.reads)
}

func TestEgressPolicy(t *testing.T) {
	cases := []struct {
		name    string
		policy  Policy
		host    string
		allowed bool
	}{
		{"unrestricted reaches any public host", unrestricted(), "anything.example.org", true},
		{"limited allows a listed host", Policy{Hosts: []string{"api.example.com"}}, "api.example.com", true},
		{"limited allows a glob", Policy{Hosts: []string{"*.example.com"}}, "deep.api.example.com", true},
		{"limited refuses an unlisted host", Policy{Hosts: []string{"api.example.com"}}, "evil.example.org", false},
		{"limited with no hosts refuses all", Policy{}, "api.example.com", false},
		{"non-canonical host is refused", Policy{Hosts: []string{"*"}}, "exämple.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(tc.policy, everywhere())
			res, _, err := h.connect(t, tc.host+":443", basic("sesn_a", "tok_a"))
			require.NoError(t, err)
			if tc.allowed {
				require.Equal(t, transform.ActionContinue, res.Action)
				return
			}
			require.Equal(t, transform.ActionReject, res.Action)
			require.Equal(t, http.StatusForbidden, res.Response.StatusCode)
		})
	}
}

func TestInnerHostIsCheckedAgainstPolicy(t *testing.T) {
	h := newHarness(Policy{Hosts: []string{"api.example.com"}}, everywhere())
	tunnel := h.bound(t)
	req := httptest.NewRequest(http.MethodGet, "https://evil.example.org/v1", nil)
	res, _, err := h.inner(t, tunnel, req, true)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, res.Response.StatusCode)
}

func TestPolicyUnavailableFailsClosed(t *testing.T) {
	h := newHarness(unrestricted(), everywhere())
	h.swap.opts.Policies = fakePolicies{err: errDown}
	_, _, err := h.connect(t, "api.example.com:443", basic("sesn_a", "tok_a"))
	require.ErrorIs(t, err, errDown)
}

func TestSwapLogsIDAndFingerprintNeverValue(t *testing.T) {
	h := newHarness(unrestricted(), everywhere())
	tunnel := h.bound(t)
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	req.Header.Set("X-Api-Key", ownPlaceholder)
	_, _, err := h.inner(t, tunnel, req, true)
	require.NoError(t, err)
	logs := h.logs.String()
	require.Contains(t, logs, `"level":"INFO"`)
	require.Contains(t, logs, `"msg":"credential swapped"`)
	require.Contains(t, logs, `"credential":"cred_own"`)
	require.Contains(t, logs, `"fingerprint":"fp-`)
	require.NotContains(t, logs, realValue)
}
