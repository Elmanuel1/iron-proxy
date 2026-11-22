package sessionswap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

const (
	ownPlaceholder    = "ph-own"
	otherPlaceholder  = "ph-other"
	forgedPlaceholder = "ph-forged"
	realValue         = "real-secret-value"
)

var fakePattern = regexp.MustCompile(`ph-[a-z]+`)

type fakePlaceholders struct{ claims map[string]Claim }

func (f fakePlaceholders) Find(text string) []string { return fakePattern.FindAllString(text, -1) }

func (f fakePlaceholders) Verify(p string) (Claim, bool) {
	c, ok := f.claims[p]
	return c, ok
}

func (f fakePlaceholders) Fingerprint(v string) string { return "fp-" + strings.Repeat("x", len(v)%7) }

type fakeCallers struct {
	err   error
	calls int
}

func (f *fakeCallers) Check(_ context.Context, session, token string) (Caller, error) {
	f.calls++
	if f.err != nil {
		return Caller{}, f.err
	}
	if session != "sesn_a" || token != "tok_a" {
		return Caller{}, ErrRefused
	}
	return Caller{Session: "sesn_a", Environment: "env_a"}, nil
}

type fakePolicies struct {
	policy Policy
	err    error
}

func (f fakePolicies) Egress(context.Context, string) (Policy, error) { return f.policy, f.err }

type fakeValues struct {
	mu    sync.Mutex
	value Value
	err   error
	reads int
}

func (f *fakeValues) Read(context.Context, Claim) (Value, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	return f.value, f.err
}

type harness struct {
	swap    *Swap
	callers *fakeCallers
	values  *fakeValues
	logs    *bytes.Buffer
}

func newHarness(policy Policy, value Value) *harness {
	logs := &bytes.Buffer{}
	h := &harness{
		callers: &fakeCallers{},
		values:  &fakeValues{value: value},
		logs:    logs,
	}
	h.swap = New(Options{
		Name: "agentd_session_swap",
		Placeholders: fakePlaceholders{claims: map[string]Claim{
			ownPlaceholder:   {Session: "sesn_a", Credential: "cred_own", Secret: "ws/vlt/cred_own"},
			otherPlaceholder: {Session: "sesn_b", Credential: "cred_other", Secret: "ws/vlt/cred_other"},
		}},
		Callers:  h.callers,
		Policies: fakePolicies{policy: policy},
		Values:   h.values,
		Logger:   slog.New(slog.NewJSONHandler(logs, nil)),
	})
	return h
}

func everywhere() Value { return Value{Secret: realValue, Header: true, Body: true} }

func unrestricted() Policy { return Policy{Unrestricted: true} }

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// connect runs a CONNECT through the transform and returns the tunnel it
// would bind, as the proxy builds it from the CONNECT's traces.
func (h *harness) connect(t *testing.T, target, auth string) (*transform.TransformResult, *transform.TunnelInfo, error) {
	t.Helper()
	req := httptest.NewRequest(http.MethodConnect, "http://"+target, nil)
	req.Host = target
	if auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	tctx := &transform.TransformContext{}
	res, err := h.swap.TransformRequest(context.Background(), tctx, req)
	tunnel := &transform.TunnelInfo{
		Target:            target,
		RequestTransforms: []transform.TransformTrace{{Name: h.swap.Name(), Annotations: tctx.DrainAnnotations()}},
	}
	return res, tunnel, err
}

// inner runs a request carried inside tunnel; tlsOn says whether the client
// spoke TLS to the proxy.
func (h *harness) inner(t *testing.T, tunnel *transform.TunnelInfo, req *http.Request, tlsOn bool) (*transform.TransformResult, *transform.TransformContext, error) {
	t.Helper()
	if tlsOn {
		req.TLS = &tls.ConnectionState{ServerName: req.Host}
	}
	if req.Body != nil {
		req.Body = transform.NewBufferedBody(req.Body, 1<<20)
	}
	tctx := &transform.TransformContext{Tunnel: tunnel}
	res, err := h.swap.TransformRequest(context.Background(), tctx, req)
	return res, tctx, err
}

func (h *harness) bound(t *testing.T) *transform.TunnelInfo {
	t.Helper()
	res, tunnel, err := h.connect(t, "api.example.com:443", basic("sesn_a", "tok_a"))
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	return tunnel
}

var errDown = errors.New("store down")
