package sessionswap

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/ironsh/iron-proxy/internal/transform"
)

const (
	annotationSession     = "session"
	annotationEnvironment = "environment"
)

// caller returns the request's session. Inside a tunnel it is the identity
// this transform annotated on the tunnel's CONNECT, and any
// Proxy-Authorization on the inner request is removed. The tunnel's traces
// come from the proxy's own CONNECT pipeline run, never from the client.
// Elsewhere (CONNECT itself, absolute-form HTTP) the request's own header is
// checked. A refusal comes back as a 407 response; an error means the
// session store did not answer.
func (s *Swap) caller(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (Caller, *http.Response, error) {
	inTunnel := tctx.Tunnel != nil && req.Method != http.MethodConnect
	bound := -1
	if inTunnel {
		bound = slices.IndexFunc(tctx.Tunnel.RequestTransforms, func(trace transform.TransformTrace) bool {
			session, _ := trace.Annotations[annotationSession].(string)
			return trace.Name == s.opts.Name && session != ""
		})
	}
	if inTunnel && bound < 0 {
		return Caller{}, proxyAuthRequired(), nil
	}
	if inTunnel {
		// Ignored, so never searched for placeholders either.
		req.Header.Del("Proxy-Authorization")
		annotations := tctx.Tunnel.RequestTransforms[bound].Annotations
		session, _ := annotations[annotationSession].(string)
		environment, _ := annotations[annotationEnvironment].(string)
		return Caller{Session: session, Environment: environment}, nil, nil
	}

	// net/http parses Basic credentials only from Authorization.
	asAuthorization := &http.Request{Header: http.Header{"Authorization": req.Header.Values("Proxy-Authorization")}}
	session, token, ok := asAuthorization.BasicAuth()
	if !ok || session == "" || token == "" {
		return Caller{}, proxyAuthRequired(), nil
	}
	c, err := s.opts.Callers.Check(ctx, session, token)
	if errors.Is(err, ErrRefused) {
		return Caller{}, proxyAuthRequired(), nil
	}
	if err != nil {
		return Caller{}, nil, err
	}
	return c, nil, nil
}

func proxyAuthRequired() *http.Response {
	return textResponse(http.StatusProxyAuthRequired, http.Header{
		"Proxy-Authenticate": {`Basic realm="iron-proxy"`},
	})
}

func textResponse(status int, header http.Header) *http.Response {
	body := http.StatusText(status) + "\n"
	header.Set("Content-Type", "text/plain; charset=utf-8")
	return &http.Response{
		StatusCode:    status,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}
