package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// The last LocalStack line that runs without an account token.
	localstackImage = "localstack/localstack:3.8"
	swapKeyHex      = "000102030405060708090a0b0c0d0e0f"
	swapRuntimeKey  = "sk-ant-oat01-integration"
)

// TestAgentdSessionSwap runs the proxy against LocalStack's Secrets Manager
// and a fake agentd, and drives a real HTTP client through it with
// Proxy-Authorization from the proxy URL, as a sandbox does.
func TestAgentdSessionSwap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	endpoint := startLocalStack(t, ctx)
	sm := secretsmanager.NewFromConfig(aws.Config{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	})
	putCredential(t, ctx, sm, "cred_1", "first-value", []string{"localhost"})
	putCredential(t, ctx, sm, "cred_2", "github-only-value", []string{"api.github.com"})

	upstream, certFile, serverTLS := startLocalhostUpstream(t)
	plain := httptest.NewServer(echoHandler())
	t.Cleanup(plain.Close)
	agentd := fakeAgentdAPI(t, serverTLS)

	cfgPath := renderConfig(t, t.TempDir(), "agentd_session_swap.yaml", map[string]string{"AgentdURL": agentd})
	proxy := startProxy(t, proxyBinary(t), cfgPath, []string{
		"AGENTD_PLACEHOLDER_KEYS=k1:" + swapKeyHex,
		"AGENTD_RUNTIME_KEYS=" + swapRuntimeKey,
		"AWS_ENDPOINT_URL=" + endpoint,
		"AWS_ACCESS_KEY_ID=test",
		"AWS_SECRET_ACCESS_KEY=test",
		"AWS_SESSION_TOKEN=",
		"AWS_REGION=us-east-1",
		"SSL_CERT_FILE=" + certFile,
	})
	tunnel := proxy.AddrFor(t, "tunnel proxy starting")
	target := "https://localhost:" + upstream + "/echo"

	own := swapPlaceholder(t, "sesn_a", "cred_1")
	t.Run("own placeholder is swapped and Proxy-Authorization stripped", func(t *testing.T) {
		got := sendThrough(t, tunnel, "sesn_a:tok_a", target, own)
		require.Equal(t, http.StatusOK, got.status)
		require.Equal(t, "first-value", got.key)
		require.Empty(t, got.proxyAuth)
	})

	t.Run("a rotated value is used once the ttl passes", func(t *testing.T) {
		_, err := sm.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
			SecretId:     aws.String("agentd/wrkspc_1/vlt_1/cred_1"),
			SecretString: aws.String(sealedCredential("rotated-value", []string{"localhost"})),
		})
		require.NoError(t, err)
		time.Sleep(1100 * time.Millisecond)
		require.Equal(t, "rotated-value", sendThrough(t, tunnel, "sesn_a:tok_a", target, own).key)
	})

	unchanged := []struct{ name, placeholder string }{
		{"another session's placeholder", swapPlaceholder(t, "sesn_b", "cred_1")},
		{"a host the credential does not allow", swapPlaceholder(t, "sesn_a", "cred_2")},
		{"a bad signature", own[:len(own)-2] + "AA"},
	}
	for _, tc := range unchanged {
		t.Run(tc.name+" is sent unchanged", func(t *testing.T) {
			got := sendThrough(t, tunnel, "sesn_a:tok_a", target, tc.placeholder)
			require.Equal(t, http.StatusOK, got.status)
			require.Equal(t, tc.placeholder, got.key)
		})
	}

	t.Run("an unreadable value is 502", func(t *testing.T) {
		got := sendThrough(t, tunnel, "sesn_a:tok_a", target, swapPlaceholder(t, "sesn_a", "cred_missing"))
		require.Equal(t, http.StatusBadGateway, got.status)
	})

	refused := []struct {
		name, auth, url string
		status          int
	}{
		{"no Proxy-Authorization", "", target, http.StatusProxyAuthRequired},
		{"a wrong work token", "sesn_a:tok_wrong", target, http.StatusProxyAuthRequired},
		{"a host outside the limited list", "sesn_a:tok_a", plain.URL + "/echo", http.StatusForbidden},
		// Each passes the unrestricted policy and is refused at dial time, after resolution.
		{"the metadata address", "sesn_open:tok_open", "http://169.254.169.254/latest/meta-data/", http.StatusBadGateway},
		{"a private address", "sesn_open:tok_open", "http://10.0.0.1/", http.StatusBadGateway},
	}
	for _, tc := range refused {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			got := sendThrough(t, tunnel, tc.auth, tc.url, own)
			require.Equal(t, tc.status, got.status)
			require.Empty(t, got.key, "the request never reached an upstream")
		})
	}

	t.Run("an unrestricted environment reaches a host outside any list", func(t *testing.T) {
		got := sendThrough(t, tunnel, "sesn_open:tok_open", plain.URL+"/echo", own)
		require.Equal(t, http.StatusOK, got.status)
		require.Equal(t, own, got.key, "plain HTTP is never swapped")
	})
}

func startLocalStack(t *testing.T, ctx context.Context) string {
	t.Helper()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        localstackImage,
			ExposedPorts: []string{"4566/tcp"},
			Env:          map[string]string{"SERVICES": "secretsmanager", "DISABLE_EVENTS": "1", "SKIP_SSL_CERT_DOWNLOAD": "1"},
			WaitingFor:   wait.ForHTTP("/_localstack/health").WithPort("4566/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Skipf("localstack testcontainers unavailable (is Docker running?): %v", err)
	}
	testcontainers.CleanupContainer(t, container)
	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "4566/tcp")
	require.NoError(t, err)
	return "http://" + net.JoinHostPort(host, port.Port())
}

func sealedCredential(value string, hosts []string) string {
	b, _ := json.Marshal(map[string]any{
		"type":               "environment_variable",
		"secret_name":        "API_KEY",
		"secret_value":       value,
		"networking":         map[string]any{"type": "limited", "allowed_hosts": hosts},
		"injection_location": map[string]bool{"header": true, "body": true},
	})
	return string(b)
}

func putCredential(t *testing.T, ctx context.Context, sm *secretsmanager.Client, credential, value string, hosts []string) {
	t.Helper()
	_, err := sm.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String("agentd/wrkspc_1/vlt_1/" + credential),
		SecretString: aws.String(sealedCredential(value, hosts)),
	})
	require.NoError(t, err)
}

// swapPlaceholder signs a placeholder as agentd does.
func swapPlaceholder(t *testing.T, session, credential string) string {
	t.Helper()
	key, err := hex.DecodeString(swapKeyHex)
	require.NoError(t, err)
	derived := hmac.New(sha256.New, key)
	derived.Write([]byte("placeholder"))
	body, err := json.Marshal(map[string]string{"session": session, "ws": "wrkspc_1", "vault": "vlt_1", "credential": credential})
	require.NoError(t, err)
	signed := "k1." + base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, derived.Sum(nil))
	mac.Write([]byte(signed))
	return "agentd-ph-" + signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func fakeAgentdAPI(t *testing.T, serverTLS *tls.Config) string {
	t.Helper()
	sessions := map[string]struct{ token, env string }{
		"sesn_a":    {"tok_a", "env_limited"},
		"sesn_open": {"tok_open", "env_open"},
	}
	envs := map[string]string{
		"env_limited": `{"config":{"type":"cloud","networking":{"type":"limited","allowed_hosts":["localhost"]}}}`,
		"env_open":    `{"config":{"type":"cloud","networking":{"type":"unrestricted"}}}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		s, ok := sessions[r.PathValue("id")]
		if !ok || r.Header.Get("Authorization") != "Bearer "+s.token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprintf(w, `{"id":%q,"environment_id":%q}`, r.PathValue("id"), s.env)
	})
	mux.HandleFunc("GET /v1/environments/{id}", func(w http.ResponseWriter, r *http.Request) {
		body, ok := envs[r.PathValue("id")]
		if !ok || r.Header.Get("Authorization") != "Bearer "+swapRuntimeKey {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, body)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = serverTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	return "https://localhost:" + port
}

// startLocalhostUpstream serves TLS for localhost and 127.0.0.1 under a
// certificate written to a file the proxy trusts through SSL_CERT_FILE.
// Returns its port, the certificate's file, and its TLS config, which the
// fake agentd serves with too.
func startLocalhostUpstream(t *testing.T) (string, string, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certFile := filepath.Join(t.TempDir(), "upstream.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))

	serverTLS := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv := httptest.NewUnstartedServer(echoHandler())
	srv.TLS = serverTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	return port, certFile, serverTLS
}

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key":        r.Header.Get("X-Api-Key"),
			"proxy_auth": r.Header.Get("Proxy-Authorization"),
		})
	})
}

type echoed struct {
	status    int
	key       string
	proxyAuth string
}

// sendThrough sends one GET to target through the tunnel listener with auth
// (`session:token`, or empty) in the proxy URL, as HTTPS_PROXY carries it.
func sendThrough(t *testing.T, tunnel, auth, target, apiKey string) echoed {
	t.Helper()
	proxyURL := &url.URL{Scheme: "http", Host: tunnel}
	if auth != "" {
		user, pass, _ := strings.Cut(auth, ":")
		proxyURL.User = url.UserPassword(user, pass)
	}
	caPEM, err := os.ReadFile(filepath.Join(repoRoot(t), "tmp", "ca.crt"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))
	var connectStatus int
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: roots},
			OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, resp *http.Response) error {
				connectStatus = resp.StatusCode
				return nil
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)
	req.Header.Set("X-Api-Key", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		require.NotZero(t, connectStatus, "only a refused CONNECT may fail the request: %v", err)
		require.NotEqual(t, http.StatusOK, connectStatus)
		return echoed{status: connectStatus}
	}
	defer resp.Body.Close()
	var body struct {
		Key       string `json:"key"`
		ProxyAuth string `json:"proxy_auth"`
	}
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	}
	return echoed{status: resp.StatusCode, key: body.Key, proxyAuth: body.ProxyAuth}
}
