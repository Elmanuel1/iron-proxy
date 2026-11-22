package agentd

import (
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	proxyconfig "github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/dnsguard"
)

func loadExample(t *testing.T) *proxyconfig.Config {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "..", "..", "examples", "agentd", "iron-proxy.yaml"))
	require.NoError(t, err)
	defer f.Close()
	cfg, err := proxyconfig.Load(f)
	require.NoError(t, err)
	return cfg
}

func TestExampleDeniesInternalAddresses(t *testing.T) {
	guard, err := dnsguard.New(loadExample(t).Proxy.UpstreamDenyCIDRs.Values)
	require.NoError(t, err)
	cases := []struct {
		addr   string
		denied bool
	}{
		{"169.254.169.254", true},
		{"169.254.170.2", true},
		{"10.0.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"100.64.0.1", true},
		{"127.0.0.1", true},
		{"0.0.0.0", true},
		{"::1", true},
		{"::", true},
		{"fe80::1", true},
		{"fd00:ec2::254", true},
		{"::ffff:10.0.0.1", true},
		{"93.184.216.34", false},
		{"2606:2800:220:1:248:1893:25c8:1946", false},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			require.Equal(t, tc.denied, guard.IsDenied(netip.MustParseAddr(tc.addr)))
		})
	}
}

func TestExampleTransformBuilds(t *testing.T) {
	cfg := loadExample(t)
	require.Len(t, cfg.Transforms, 1)
	require.Equal(t, Name, cfg.Transforms[0].Name)
	var c config
	require.NoError(t, cfg.Transforms[0].Config.Decode(&c))
	env := map[string]string{placeholderKeysEnv: "k1:" + keyHex, runtimeKeysEnv: "sk-ant-oat01-x"}
	_, err := build(c, func(k string) string { return env[k] }, slog.Default())
	require.NoError(t, err)
}
