package sessionswap

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// swap replaces each placeholder the caller's session owns with its value,
// in the locations and for the hosts the value's rules allow. Any other
// placeholder is left as it is.
func (s *Swap) swap(ctx context.Context, tctx *transform.TransformContext, req *http.Request, caller Caller, host string) error {
	body, scanned, err := readBody(req)
	if err != nil {
		return fmt.Errorf("reading request body: %w", err)
	}
	values, err := s.resolve(ctx, s.candidates(req.Header, body), caller, host)
	if err != nil {
		return err
	}
	var swapped []string
	for placeholder, v := range values {
		var locations []string
		if v.value.Header && replaceHeaders(req.Header, placeholder, v.value.Secret) {
			locations = append(locations, "header")
		}
		if v.value.Body && strings.Contains(body, placeholder) {
			body = strings.ReplaceAll(body, placeholder, v.value.Secret)
			locations = append(locations, "body")
		}
		if len(locations) == 0 {
			continue
		}
		swapped = append(swapped, v.claim.Credential)
		s.metrics.swaps.Add(ctx, 1)
		s.opts.Logger.Info("credential swapped",
			slog.String("credential", v.claim.Credential),
			slog.String("fingerprint", s.opts.Placeholders.Fingerprint(v.value.Secret)),
			slog.String("session", caller.Session),
			slog.String("host", host),
			slog.Any("locations", locations),
		)
	}
	if scanned {
		req.Body = transform.NewBufferedBodyFromBytes([]byte(body))
		req.ContentLength = int64(len(body))
	}
	if len(swapped) > 0 {
		slices.Sort(swapped)
		tctx.Annotate("swapped", swapped)
	}
	return nil
}

type resolved struct {
	claim Claim
	value Value
}

// resolve verifies each candidate and reads the value of each one the caller
// owns and the host may receive. A value that cannot be read fails the
// request rather than sending the placeholder on.
func (s *Swap) resolve(ctx context.Context, candidates []string, caller Caller, host string) (map[string]resolved, error) {
	out := make(map[string]resolved)
	for _, p := range candidates {
		claim, ok := s.opts.Placeholders.Verify(p)
		if !ok || claim.Session != caller.Session {
			continue
		}
		v, err := s.opts.Values.Read(ctx, claim)
		if err != nil {
			s.metrics.readFailures.Add(ctx, 1)
			s.opts.Logger.Error("credential value unreadable",
				slog.String("credential", claim.Credential),
				slog.String("session", caller.Session),
				slog.String("error", err.Error()),
			)
			return nil, fmt.Errorf("reading credential %s: %w", claim.Credential, err)
		}
		if v.Hosts != nil && !matches(v.Hosts, host) {
			continue
		}
		out[p] = resolved{claim: claim, value: v}
	}
	return out, nil
}

// candidates returns each distinct placeholder in the headers and body.
func (s *Swap) candidates(h http.Header, body string) []string {
	var found []string
	for _, vals := range h {
		for _, v := range vals {
			found = append(found, s.opts.Placeholders.Find(v)...)
		}
	}
	found = append(found, s.opts.Placeholders.Find(body)...)
	slices.Sort(found)
	return slices.Compact(found)
}

// maxBodyBytes is the largest body searched for placeholders. A larger one,
// or one of unknown length, is streamed untouched with its placeholders.
const maxBodyBytes = 1 << 20

// readBody reads a body of known length up to maxBodyBytes. It reads the
// unread body through StreamingReader, since reading the BufferedBody itself
// would cut it at the proxy's max_request_body_bytes.
func readBody(req *http.Request) (string, bool, error) {
	bb, ok := req.Body.(*transform.BufferedBody)
	if !ok || req.ContentLength <= 0 || req.ContentLength > maxBodyBytes {
		return "", false, nil
	}
	bb.Reset()
	data, err := io.ReadAll(io.LimitReader(bb.StreamingReader(), maxBodyBytes))
	if err != nil {
		return "", false, err
	}
	return string(data), true, nil
}

func replaceHeaders(h http.Header, placeholder, value string) bool {
	hit := false
	for _, vals := range h {
		for i, v := range vals {
			if !strings.Contains(v, placeholder) {
				continue
			}
			vals[i] = strings.ReplaceAll(v, placeholder, value)
			hit = true
		}
	}
	return hit
}
