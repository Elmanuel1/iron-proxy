package agentd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform/sessionswap"
)

type fakeReader struct {
	values map[string]string
	err    error
	names  []string
}

func (f *fakeReader) Read(_ context.Context, name string) (string, error) {
	f.names = append(f.names, name)
	if f.err != nil {
		return "", f.err
	}
	v, ok := f.values[name]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

var claim = sessionswap.Claim{Session: "sesn_1", Credential: "cred_1", Secret: "wrkspc_1/vlt_1/cred_1"}

func TestStoreRead(t *testing.T) {
	const name = "agentd/wrkspc_1/vlt_1/cred_1"
	cases := []struct {
		name   string
		sealed string
		want   sessionswap.Value
		err    string
	}{
		{
			name:   "limited, header only",
			sealed: `{"type":"environment_variable","secret_name":"K","secret_value":"v1","networking":{"type":"limited","allowed_hosts":["*.x.com"]},"injection_location":{"body":false,"header":true}}`,
			want:   sessionswap.Value{Secret: "v1", Hosts: []string{"*.x.com"}, Header: true},
		},
		{
			name:   "unrestricted, both locations",
			sealed: `{"type":"environment_variable","secret_value":"v1","networking":{"type":"unrestricted"},"injection_location":{"body":true,"header":true}}`,
			want:   sessionswap.Value{Secret: "v1", Header: true, Body: true},
		},
		{
			name:   "no location defaults to both",
			sealed: `{"type":"environment_variable","secret_value":"v1","networking":{"type":"unrestricted"}}`,
			want:   sessionswap.Value{Secret: "v1", Header: true, Body: true},
		},
		{
			name:   "limited with no hosts",
			sealed: `{"type":"environment_variable","secret_value":"v1","networking":{"type":"limited"}}`,
			want:   sessionswap.Value{Secret: "v1", Hosts: []string{}, Header: true, Body: true},
		},
		{
			name:   "unknown networking allows no host",
			sealed: `{"type":"environment_variable","secret_value":"v1","networking":{"type":"open"}}`,
			want:   sessionswap.Value{Secret: "v1", Hosts: []string{}, Header: true, Body: true},
		},
		{name: "another credential type", sealed: `{"type":"static_bearer","token":"t-1"}`, err: "not an environment_variable"},
		{name: "no value", sealed: `{"type":"environment_variable","secret_value":""}`, err: "not an environment_variable"},
		{name: "not json", sealed: `secret-value-in-the-clear`, err: "not valid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeReader{values: map[string]string{name: tc.sealed}}
			got, err := NewStore(r, 5*time.Minute, "agentd").Read(context.Background(), claim)
			require.Equal(t, []string{name}, r.names)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				require.NotContains(t, err.Error(), "secret-value-in-the-clear")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestStoreTTL(t *testing.T) {
	const name = "/agentd/wrkspc_1/vlt_1/cred_1"
	sealed := func(v string) string { return `{"type":"environment_variable","secret_value":"` + v + `"}` }
	r := &fakeReader{values: map[string]string{name: sealed("first")}}
	now := time.Unix(1000, 0)
	s := NewStore(r, time.Minute, "/agentd")
	s.now = func() time.Time { return now }
	value := func() (string, error) {
		v, err := s.Read(context.Background(), claim)
		return v.Secret, err
	}

	got, err := value()
	require.NoError(t, err)
	require.Equal(t, "first", got)

	r.values[name] = sealed("rotated")
	now = now.Add(time.Minute - time.Second)
	got, err = value()
	require.NoError(t, err)
	require.Equal(t, "first", got, "kept within the ttl")
	require.Len(t, r.names, 1)

	now = now.Add(time.Second)
	got, err = value()
	require.NoError(t, err)
	require.Equal(t, "rotated", got, "read again once the ttl passes")

	r.err = errors.New("throttled")
	now = now.Add(time.Minute)
	_, err = value()
	require.ErrorContains(t, err, "throttled", "an expired value is never reused when its read fails")

	r.err = nil
	got, err = value()
	require.NoError(t, err)
	require.Equal(t, "rotated", got)
	require.Len(t, r.names, 4)
}
