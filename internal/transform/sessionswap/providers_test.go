package sessionswap

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

func TestFactory(t *testing.T) {
	RegisterProvider("test-ok", func(yaml.Node, *slog.Logger) (Options, error) {
		h := newHarness(unrestricted(), everywhere())
		return h.swap.opts, nil
	})
	RegisterProvider("test-fail", func(yaml.Node, *slog.Logger) (Options, error) {
		return Options{}, errors.New("bad config")
	})
	factory, err := transform.Lookup(Name)
	require.NoError(t, err)
	cases := []struct {
		provider, err string
	}{
		{"test-ok", ""},
		{"test-fail", "session_swap: provider test-fail: bad config"},
		{"nope", `session_swap: unknown provider "nope"`},
		{"", `session_swap: unknown provider ""`},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			var node yaml.Node
			require.NoError(t, node.Encode(map[string]string{"provider": tc.provider}))
			tr, err := factory(node, slog.Default())
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, Name, tr.Name())
		})
	}
}
