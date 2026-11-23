package agentd

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform/sessionswap"
)

const (
	keyHex = "000102030405060708090a0b0c0d0e0f"
	// golden is agentd's placeholder for {sesn_1, wrkspc_1, vlt_1, cred_1}
	// under k1:keyHex, computed apart from this package from hash.rs.
	golden = "agentd-ph-k1.eyJzZXNzaW9uIjoic2Vzbl8xIiwid3MiOiJ3cmtzcGNfMSIsInZhdWx0Ijoidmx0XzEiLCJjcmVkZW50aWFsIjoiY3JlZF8xIn0.jiEZauVtbkU25vjCvIPuhXrjXEfTuy6tIo6_CozqNZw"
)

// sign mints a placeholder as agentd's Signer does.
func sign(t *testing.T, id, hexKey string, c claims) string {
	t.Helper()
	key, err := hex.DecodeString(hexKey)
	require.NoError(t, err)
	body, err := json.Marshal(c)
	require.NoError(t, err)
	signed := id + "." + base64.RawURLEncoding.EncodeToString(body)
	sig := base64.RawURLEncoding.EncodeToString(mac(mac(key, "placeholder"), signed))
	return placeholderPrefix + signed + "." + sig
}

func ringOf(t *testing.T, raw string) *Ring {
	t.Helper()
	r, err := ParseRing(raw)
	require.NoError(t, err)
	return r
}

func TestVerifyGolden(t *testing.T) {
	claim, ok := ringOf(t, "k1:"+keyHex).Verify(golden)
	require.True(t, ok)
	require.Equal(t, sessionswap.Claim{Session: "sesn_1", Credential: "cred_1", Secret: "wrkspc_1/vlt_1/cred_1"}, claim)
}

func TestVerify(t *testing.T) {
	other := "ffeeddccbbaa99887766554433221100"
	c := claims{Session: "sesn_1", Workspace: "wrkspc_1", Vault: "vlt_1", Credential: "cred_1"}
	tampered := []byte(golden)
	at := len(placeholderPrefix + "k1.")
	tampered[at] ^= 1
	cases := []struct {
		name        string
		ring        string
		placeholder string
		ok          bool
	}{
		{"signed by the first key", "k1:" + keyHex, golden, true},
		{"signed by a later key in the ring", "k2:" + other + ",k1:" + keyHex, golden, true},
		{"key id not in the ring", "k2:" + other, golden, false},
		{"same id, other key", "k1:" + other, golden, false},
		{"tampered claims", "k1:" + keyHex, string(tampered), false},
		{"truncated mac", "k1:" + keyHex, golden[:len(golden)-1], false},
		{"no prefix", "k1:" + keyHex, strings.TrimPrefix(golden, placeholderPrefix), false},
		{"work token prefix", "k1:" + keyHex, "agentd-wt-" + strings.TrimPrefix(golden, placeholderPrefix), false},
		{"id with a path", "k1:" + keyHex, sign(t, "k1", keyHex, claims{Session: "s", Workspace: "../x", Vault: "v", Credential: "c"}), false},
		{"empty credential", "k1:" + keyHex, sign(t, "k1", keyHex, claims{Session: "s", Workspace: "w", Vault: "v"}), false},
		{"fresh signature", "k1:" + keyHex, sign(t, "k1", keyHex, c), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := ringOf(t, tc.ring).Verify(tc.placeholder)
			require.Equal(t, tc.ok, ok)
		})
	}
}

func TestFind(t *testing.T) {
	r := ringOf(t, "k1:"+keyHex)
	require.Nil(t, r.Find("no placeholder here"))
	require.Equal(t, []string{golden, golden}, r.Find("Bearer "+golden+`","x":"`+golden+`"`))
}

func TestParseRingErrorsNeverQuoteKeys(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"empty", "", "no key"},
		{"short key", "k1:00ff", "entry 1 is not"},
		{"not hex", "k1:" + strings.Repeat("zz", 16), "entry 1 is not"},
		{"swapped fields", keyHex + ":k1", "entry 1 is not"},
		{"bad id", "k-1:" + keyHex, "entry 1 is not"},
		{"repeated id", "k1:" + keyHex + ",k1:" + keyHex, "entry 2 repeats"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRing(tc.raw)
			require.ErrorContains(t, err, tc.want)
			require.NotContains(t, err.Error(), keyHex)
		})
	}
}

func TestFingerprintIsKeyedAndStable(t *testing.T) {
	a := ringOf(t, "k1:"+keyHex)
	b := ringOf(t, "k1:ffeeddccbbaa99887766554433221100")
	require.Equal(t, a.Fingerprint("v"), a.Fingerprint("v"))
	require.NotEqual(t, a.Fingerprint("v"), a.Fingerprint("w"))
	require.NotEqual(t, a.Fingerprint("v"), b.Fingerprint("v"))
	require.Len(t, a.Fingerprint("v"), 16)
}
