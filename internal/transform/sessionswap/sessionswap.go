// Package sessionswap swaps per-session placeholders for real credential
// values in one proxy shared by many sessions. Each tunnel authenticates as
// one session with Proxy-Authorization, its environment's egress policy
// decides which hosts it reaches, and only a placeholder minted for that
// session is replaced, over TLS, where the credential's own rules allow.
//
// The session store, the placeholder format and the value store sit behind
// the ports declared here; package agentd holds the adapters for agentd.
package sessionswap

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// ErrRefused is returned by Callers.Check when the session store refuses the
// pair, as opposed to failing to answer.
var ErrRefused = errors.New("caller refused")

// Caller is an authenticated session and the environment it runs in.
type Caller struct {
	Session     string
	Environment string
}

// Policy is an environment's egress policy. A limited policy reaches only
// Hosts; an unrestricted one reaches every host the dialer allows.
type Policy struct {
	Unrestricted bool
	Hosts        []string
}

// Claim is what a verified placeholder stands for.
type Claim struct {
	Session    string
	Credential string
	// Secret names where the credential's sealed secret is stored.
	Secret string
}

// Value is a credential's value with the rules sealed beside it.
type Value struct {
	Secret string
	// Hosts lists the hosts the value may be sent to; nil means any host.
	Hosts  []string
	Header bool
	Body   bool
}

// Placeholders finds and verifies placeholders.
type Placeholders interface {
	Find(text string) []string
	// Verify reports false for a placeholder that does not verify.
	Verify(placeholder string) (Claim, bool)
	// Fingerprint identifies a value in logs without revealing it.
	Fingerprint(value string) string
}

// Callers checks a session and its token against the session store.
type Callers interface {
	Check(ctx context.Context, session, token string) (Caller, error)
}

// Policies reads an environment's egress policy.
type Policies interface {
	Egress(ctx context.Context, environment string) (Policy, error)
}

// Values reads a credential's sealed secret from its store, with no cache.
type Values interface {
	Read(ctx context.Context, claim Claim) (Value, error)
}

// Options are the ports a Swap uses.
type Options struct {
	Name         string
	Placeholders Placeholders
	Callers      Callers
	Policies     Policies
	Values       Values
	Logger       *slog.Logger
}

type Swap struct {
	opts    Options
	metrics metrics
}

func New(opts Options) *Swap {
	return &Swap{opts: opts, metrics: newMetrics()}
}

func (s *Swap) Name() string { return s.opts.Name }

// TransformRequest authenticates the request's session, applies its egress
// policy and, inside TLS, swaps its own placeholders.
func (s *Swap) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	caller, resp, err := s.caller(ctx, tctx, req)
	if err != nil {
		s.metrics.refuse(ctx, "caller_unavailable")
		return nil, err
	}
	if resp != nil {
		s.metrics.refuse(ctx, "proxy_auth")
		return &transform.TransformResult{Action: transform.ActionReject, Response: resp}, nil
	}
	tctx.Annotate(annotationSession, caller.Session)
	tctx.Annotate(annotationEnvironment, caller.Environment)

	host := hostmatch.StripPort(req.Host)
	policy, err := s.opts.Policies.Egress(ctx, caller.Environment)
	if err != nil {
		s.metrics.refuse(ctx, "policy_unavailable")
		return nil, err
	}
	if !policy.Unrestricted && !matches(policy.Hosts, host) {
		s.metrics.refuse(ctx, "egress_policy")
		return &transform.TransformResult{Action: transform.ActionReject, Response: textResponse(http.StatusForbidden, http.Header{})}, nil
	}

	if req.Method == http.MethodConnect || req.TLS == nil {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	if err := s.swap(ctx, tctx, req, caller, host); err != nil {
		return nil, err
	}
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (s *Swap) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// matches reports whether host matches one of the domain globs, as the
// allowlist matches them.
func matches(patterns []string, host string) bool {
	m, err := hostmatch.New(patterns, nil)
	return err == nil && m.Matches(host)
}
