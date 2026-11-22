package agentd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ironsh/iron-proxy/internal/transform/sessionswap"
)

// placeholderPrefix starts every placeholder agentd mints:
// agentd-ph-<key id>.<base64url JSON claims>.<base64url HMAC-SHA256>.
const placeholderPrefix = "agentd-ph-"

var (
	placeholderPattern = regexp.MustCompile(`agentd-ph-[A-Za-z0-9]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}`)
	idPattern          = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// Ring verifies agentd's placeholders under the key ring agentd signs them
// with (AGENTD_PLACEHOLDER_KEYS). It is the sessionswap.Placeholders adapter.
type Ring struct {
	keys        map[string][]byte
	fingerprint []byte
}

// ParseRing reads a ring written `<id>:<hex>,…`, the signing key first.
// Each key is derived for placeholders as agentd derives it. An error names
// an entry by its position, never its text, which may hold a key.
func ParseRing(raw string) (*Ring, error) {
	r := &Ring{keys: make(map[string][]byte)}
	for i, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, hexKey, ok := strings.Cut(entry, ":")
		key, err := hex.DecodeString(hexKey)
		if !ok || err != nil || len(key) < 16 || !isAlnum(id) {
			return nil, fmt.Errorf("entry %d is not `<id>:<hex of at least 16 bytes>`", i+1)
		}
		if _, seen := r.keys[id]; seen {
			return nil, fmt.Errorf("entry %d repeats an earlier id", i+1)
		}
		r.keys[id] = mac(key, "placeholder")
		if r.fingerprint == nil {
			r.fingerprint = mac(key, "fingerprint")
		}
	}
	if len(r.keys) == 0 {
		return nil, errors.New("no key")
	}
	return r, nil
}

func (r *Ring) Find(text string) []string {
	if !strings.Contains(text, placeholderPrefix) {
		return nil
	}
	return placeholderPattern.FindAllString(text, -1)
}

type claims struct {
	Session    string `json:"session"`
	Workspace  string `json:"ws"`
	Vault      string `json:"vault"`
	Credential string `json:"credential"`
}

// Verify checks a placeholder's MAC under the key it names and returns its
// claims. Claim.Secret is `<workspace>/<vault>/<credential>`, the path agentd
// stores the credential's sealed secret under, below its prefix.
func (r *Ring) Verify(placeholder string) (sessionswap.Claim, bool) {
	rest, ok := strings.CutPrefix(placeholder, placeholderPrefix)
	if !ok {
		return sessionswap.Claim{}, false
	}
	dot := strings.LastIndexByte(rest, '.')
	if dot < 0 {
		return sessionswap.Claim{}, false
	}
	signed, sig := rest[:dot], rest[dot+1:]
	id, body, ok := strings.Cut(signed, ".")
	key, known := r.keys[id]
	if !ok || !known {
		return sessionswap.Claim{}, false
	}
	given, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(given, mac(key, signed)) {
		return sessionswap.Claim{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return sessionswap.Claim{}, false
	}
	var c claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return sessionswap.Claim{}, false
	}
	for _, v := range []string{c.Session, c.Workspace, c.Vault, c.Credential} {
		if !idPattern.MatchString(v) {
			return sessionswap.Claim{}, false
		}
	}
	return sessionswap.Claim{
		Session:    c.Session,
		Credential: c.Credential,
		Secret:     c.Workspace + "/" + c.Vault + "/" + c.Credential,
	}, true
}

// Fingerprint is keyed so that a logged fingerprint cannot be used to test
// guesses of a short value offline.
func (r *Ring) Fingerprint(value string) string {
	return hex.EncodeToString(mac(r.fingerprint, value)[:8])
}

func mac(key []byte, message string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return h.Sum(nil)
}

func isAlnum(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}
