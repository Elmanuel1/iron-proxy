package agentd

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform/sessionswap"
)

type fakeAgentd struct {
	hits   atomic.Int32
	status atomic.Int32
	body   string
}

func (f *fakeAgentd) serve(t *testing.T, wantPath, wantBearer string) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if r.URL.Path != wantPath || r.Header.Get("Authorization") != "Bearer "+wantBearer ||
			r.Header.Get("anthropic-version") != apiVersion || r.Header.Get("anthropic-beta") != apiBeta {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if s := f.status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		_, _ = w.Write([]byte(f.body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestClient(t *testing.T, srv *httptest.Server, now *time.Time) *Client {
	t.Helper()
	return newLoggingClient(t, srv, now, io.Discard)
}

func newLoggingClient(t *testing.T, srv *httptest.Server, now *time.Time, logs io.Writer) *Client {
	t.Helper()
	c, err := NewClient(srv.URL, "sk-ant-oat01-runtime", slog.New(slog.NewJSONHandler(logs, nil)), srv.Client())
	require.NoError(t, err)
	c.now = func() time.Time { return *now }
	return c
}

func TestCheck(t *testing.T) {
	f := &fakeAgentd{body: `{"id":"sesn_1","environment_id":"env_1","status":"running"}`}
	srv := f.serve(t, "/v1/sessions/sesn_1", "agentd-wt-good")
	now := time.Unix(1000, 0)
	c := newTestClient(t, srv, &now)
	ctx := context.Background()

	caller, err := c.Check(ctx, "sesn_1", "agentd-wt-good")
	require.NoError(t, err)
	require.Equal(t, sessionswap.Caller{Session: "sesn_1", Environment: "env_1"}, caller)

	_, err = c.Check(ctx, "sesn_1", "agentd-wt-good")
	require.NoError(t, err)
	require.EqualValues(t, 1, f.hits.Load(), "a checked pair is kept")

	_, err = c.Check(ctx, "sesn_1", "agentd-wt-bad")
	require.ErrorIs(t, err, sessionswap.ErrRefused)
	_, err = c.Check(ctx, "sesn_1", "agentd-wt-bad")
	require.ErrorIs(t, err, sessionswap.ErrRefused)
	require.EqualValues(t, 2, f.hits.Load(), "a refusal is kept too")

	now = now.Add(cacheTTL)
	f.status.Store(http.StatusNotFound)
	_, err = c.Check(ctx, "sesn_1", "agentd-wt-good")
	require.ErrorIs(t, err, sessionswap.ErrRefused, "an ended session is refused within 60 s")
	require.EqualValues(t, 3, f.hits.Load())
}

func TestCheckFailures(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		refused bool
	}{
		{"server error", http.StatusInternalServerError, "", false},
		{"unauthorized", http.StatusUnauthorized, "", true},
		{"forbidden", http.StatusForbidden, "", true},
		{"another session", 0, `{"id":"sesn_2","environment_id":"env_1"}`, true},
		{"no environment", 0, `{"id":"sesn_1"}`, true},
		{"bad json", 0, `{`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeAgentd{body: tc.body}
			f.status.Store(int32(tc.status))
			srv := f.serve(t, "/v1/sessions/sesn_1", "tok")
			now := time.Unix(1000, 0)
			c := newTestClient(t, srv, &now)
			_, err := c.Check(context.Background(), "sesn_1", "tok")
			require.Error(t, err)
			require.Equal(t, tc.refused, err == sessionswap.ErrRefused)
			if !tc.refused {
				_, err = c.Check(context.Background(), "sesn_1", "tok")
				require.Error(t, err)
				require.EqualValues(t, 2, f.hits.Load(), "a failure to answer is not kept")
			}
		})
	}
}

func TestCheckRefusesMalformedSessionIDWithoutACall(t *testing.T) {
	f := &fakeAgentd{body: `{}`}
	srv := f.serve(t, "/v1/sessions/sesn_1", "tok")
	now := time.Unix(1000, 0)
	c := newTestClient(t, srv, &now)
	for _, id := range []string{"../environments/env_1", "sesn_1?x=1", "sesn 1"} {
		_, err := c.Check(context.Background(), id, "tok")
		require.ErrorIs(t, err, sessionswap.ErrRefused)
	}
	require.EqualValues(t, 0, f.hits.Load())
}

func TestEgress(t *testing.T) {
	cases := []struct {
		name string
		body string
		want sessionswap.Policy
		warn string
	}{
		{"unrestricted", `{"config":{"type":"cloud","networking":{"type":"unrestricted"}}}`, sessionswap.Policy{Unrestricted: true}, ""},
		{"no networking", `{"config":{"type":"self_hosted"}}`, sessionswap.Policy{Unrestricted: true}, ""},
		{"limited", `{"config":{"networking":{"type":"limited","allowed_hosts":["api.example.com"]}}}`,
			sessionswap.Policy{Hosts: []string{"api.example.com"}}, ""},
		{"limited with registries", `{"config":{"networking":{"type":"limited","allowed_hosts":["a.com"],"allow_package_managers":true}}}`,
			sessionswap.Policy{Hosts: append([]string{"a.com"}, packageHosts...)}, ""},
		{"unknown type", `{"config":{"networking":{"type":"open"}}}`, sessionswap.Policy{}, "open"},
		{"unreadable", `{"config":{"networking":{"type":"limited","allowed_hosts":"all"}}}`, sessionswap.Policy{}, "unreadable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeAgentd{body: tc.body}
			srv := f.serve(t, "/v1/environments/env_1", "sk-ant-oat01-runtime")
			now := time.Unix(1000, 0)
			logs := &bytes.Buffer{}
			c := newLoggingClient(t, srv, &now, logs)
			got, err := c.Egress(context.Background(), "env_1")
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			if tc.warn == "" {
				require.Empty(t, logs.String())
				return
			}
			require.Contains(t, logs.String(), `"level":"WARN"`)
			require.Contains(t, logs.String(), `"environment":"env_1"`)
			require.Contains(t, logs.String(), `"type":"`+tc.warn+`"`)
		})
	}
}

func TestEgressCachedFor60Seconds(t *testing.T) {
	f := &fakeAgentd{body: `{"config":{"networking":{"type":"unrestricted"}}}`}
	srv := f.serve(t, "/v1/environments/env_1", "sk-ant-oat01-runtime")
	now := time.Unix(1000, 0)
	c := newTestClient(t, srv, &now)
	ctx := context.Background()
	for range 3 {
		_, err := c.Egress(ctx, "env_1")
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, f.hits.Load())
	now = now.Add(cacheTTL - time.Second)
	_, err := c.Egress(ctx, "env_1")
	require.NoError(t, err)
	require.EqualValues(t, 1, f.hits.Load())
	now = now.Add(time.Second)
	_, err = c.Egress(ctx, "env_1")
	require.NoError(t, err)
	require.EqualValues(t, 2, f.hits.Load())

	f.status.Store(http.StatusBadGateway)
	now = now.Add(cacheTTL)
	_, err = c.Egress(ctx, "env_1")
	require.Error(t, err)
}

func TestNewClientURL(t *testing.T) {
	cases := []struct {
		url string
		ok  bool
	}{
		{"https://agentd.internal", true},
		{"https://127.0.0.1:8443", true},
		{"http://agentd.internal", false},
		{"http://127.0.0.1:8080", false},
		{"", false},
		{"agentd.internal", false},
		{"https://", false},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			_, err := NewClient(tc.url, "k", slog.Default(), http.DefaultClient)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "must be an https URL")
		})
	}
}
