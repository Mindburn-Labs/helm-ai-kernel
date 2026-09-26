package main

// quantum_posture: generates classical ECDSA test certificates for the TLS
// listener; no post-quantum claim.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

func TestDevInsecureListenRefusesAnythingButLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8443", "[::1]:8443", "127.0.0.2:0"} {
		if _, err := parseServeFlags([]string{"--dev-insecure-listen", address}, io.Discard); err != nil {
			t.Fatalf("%s: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8443", ":8443", "10.0.0.5:8443", "localhost:8443", "example.com:80", "[::]:8443", "127.0.0.1"} {
		if _, err := parseServeFlags([]string{"--dev-insecure-listen", address}, io.Discard); err == nil {
			t.Fatalf("%s: accepted a non-loopback plain-HTTP listener", address)
		}
	}
}

func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

var identityEnv = map[string]string{
	"HELM_CP_IDENTITY_JWKS_URL": "https://control-plane.test/jwks",
	"HELM_CP_IDENTITY_ISSUER":   "https://control-plane.test",
	"HELM_CP_IDENTITY_AUDIENCE": "helm-gateway:test",
	"HELM_CP_IDENTITY_ACTOR":    "spiffe://helm/control-plane",
}

func with(base map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func TestServeRefusesToStartWithoutItsConfiguration(t *testing.T) {
	ctx := context.Background()
	for name, test := range map[string]struct {
		args []string
		env  map[string]string
		want string
	}{
		"no token configuration":   {[]string{"serve"}, map[string]string{"HELM_GATEWAY_DATABASE_URL": "postgres://x"}, "HELM_CP_IDENTITY_JWKS_URL"},
		"partial token config":     {[]string{"serve"}, map[string]string{"HELM_CP_IDENTITY_ISSUER": "x"}, "must be set together"},
		"no TLS":                   {[]string{"serve"}, with(identityEnv, map[string]string{"HELM_GATEWAY_DATABASE_URL": "postgres://x"}), "HELM_TLS_CERT_FILE"},
		"no database":              {[]string{"serve", "--dev-insecure-listen", "127.0.0.1:0"}, identityEnv, "HELM_GATEWAY_DATABASE_URL"},
		"bad permit TTL":           {[]string{"serve", "--dev-insecure-listen", "127.0.0.1:0"}, with(identityEnv, map[string]string{"HELM_GATEWAY_PERMIT_TTL": "-1s"}), "HELM_GATEWAY_PERMIT_TTL"},
		"client auth without a CA": {[]string{"serve"}, with(identityEnv, map[string]string{"HELM_TLS_CLIENT_AUTH": "require"}), "HELM_TLS"},
		"unknown command":          {[]string{"dispatch"}, nil, "unknown command"},
		"migrate without database": {[]string{"migrate"}, nil, "HELM_GATEWAY_DATABASE_URL"},
	} {
		err := run(ctx, test.args, env(test.env), io.Discard)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: err = %v, want one naming %s", name, err, test.want)
		}
	}
}

func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// startServe runs serve until the test ends and waits for its health port.
func startServe(t *testing.T, args []string, values map[string]string) string {
	t.Helper()
	health := freeAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, append([]string{"serve", "--health-listen", health}, args...), env(values), io.Discard)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if resp, err := http.Get("http://" + health + "/healthz"); err == nil {
			_ = resp.Body.Close()
			return health
		}
	}
	t.Fatal("serve did not start")
	return ""
}

func TestServeOverDevInsecureLoopbackAnswersGRPC(t *testing.T) {
	api := freeAddress(t)
	startServe(t, []string{"--dev-insecure-listen", api}, with(identityEnv, map[string]string{"HELM_GATEWAY_DATABASE_URL": "postgres://127.0.0.1:1/none?sslmode=disable"}))
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	h2c := &http.Client{Transport: &http.Transport{Protocols: protocols}}
	client := gatewayv1.NewEffectGatewayServiceClient(h2c, "http://"+api, connect.WithGRPC())
	_, err := client.GetAttempt(context.Background(), connect.NewRequest(&gatewayv1.GetAttemptRequest{AttemptId: "x"}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("an unauthenticated gRPC call = %v, want unauthenticated", err)
	}
}

type pki struct {
	dir                           string
	ca                            *x509.Certificate
	caKey                         *ecdsa.PrivateKey
	caFile, certFile, keyFile     string
	clientCertFile, clientKeyFile string
}

func issue(t *testing.T, p *pki, name string, server bool) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(p.dir, name+".crt"), filepath.Join(p.dir, name+".key")
	writePEM(t, certFile, "CERTIFICATE", der)
	writePEM(t, keyFile, "EC PRIVATE KEY", keyDER)
	return certFile, keyFile
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{dir: t.TempDir()}
	var err error
	if p.caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &p.caKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	if p.ca, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	p.caFile = filepath.Join(p.dir, "ca.crt")
	writePEM(t, p.caFile, "CERTIFICATE", der)
	p.certFile, p.keyFile = issue(t, p, "gateway", true)
	p.clientCertFile, p.clientKeyFile = issue(t, p, "control-plane", false)
	return p
}

func TestServeRequiresAClientCertificateWhenConfigured(t *testing.T) {
	p := newPKI(t)
	api := freeAddress(t)
	startServe(t, []string{"--listen", api}, with(identityEnv, map[string]string{
		"HELM_GATEWAY_DATABASE_URL": "postgres://127.0.0.1:1/none?sslmode=disable",
		"HELM_TLS_CERT_FILE":        p.certFile, "HELM_TLS_KEY_FILE": p.keyFile,
		"HELM_TLS_CLIENT_AUTH": "require", "HELM_TLS_CLIENT_CA_FILE": p.caFile,
	}))
	roots := x509.NewCertPool()
	roots.AddCert(p.ca)
	call := func(certs []tls.Certificate) error {
		client := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certs, MinVersion: tls.VersionTLS12}}}
		_, err := gatewayv1.NewEffectGatewayServiceClient(client, "https://"+api, connect.WithGRPC()).
			GetAttempt(context.Background(), connect.NewRequest(&gatewayv1.GetAttemptRequest{AttemptId: "x"}))
		return err
	}
	// Known bad: no client certificate, no handshake.
	if err := call(nil); connect.CodeOf(err) == connect.CodeUnauthenticated || err == nil {
		t.Fatalf("a client without a certificate reached the API: %v", err)
	}
	// Known good: the Control Plane's certificate reaches the token check.
	pair, err := tls.LoadX509KeyPair(p.clientCertFile, p.clientKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := call([]tls.Certificate{pair}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("a client with a certificate = %v, want the token check's unauthenticated", err)
	}
}

func TestPostgresGatewayMigrateAndReadiness(t *testing.T) {
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the gateway readiness proof")
	}
	schema := fmt.Sprintf("helm_gateway_cmd_%d", time.Now().UnixNano())
	admin, err := sqlOpen(base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) }()
	parsed, _ := url.Parse(base)
	q := parsed.Query()
	q.Set("search_path", schema)
	parsed.RawQuery = q.Encode()
	values := with(identityEnv, map[string]string{"HELM_GATEWAY_DATABASE_URL": parsed.String()})

	health := startServe(t, []string{"--dev-insecure-listen", freeAddress(t)}, values)
	ready := func() (int, string) {
		resp, err := http.Get("http://" + health + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	// Known bad: no schema yet.
	if code, body := ready(); code != http.StatusServiceUnavailable || !strings.Contains(body, "migrate") {
		t.Fatalf("readyz before migrate = %d %q", code, body)
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"migrate"}, env(values), &out); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"migrate"}, env(values), &out); err != nil {
		t.Fatalf("a second migrate: %v", err)
	}
	// Known good: at head.
	if code, body := ready(); code != http.StatusOK {
		t.Fatalf("readyz after migrate = %d %q", code, body)
	}
	if _, err := admin.Exec(`INSERT INTO ` + schema + `.gateway_schema_migrations (version, name) VALUES (999, 'future')`); err != nil {
		t.Fatal(err)
	}
	if code, _ := ready(); code != http.StatusServiceUnavailable {
		t.Fatal("readyz is ready on a schema newer than the binary")
	}
	if err := run(context.Background(), []string{"migrate"}, env(values), &out); err == nil {
		t.Fatal("migrate accepted a newer schema")
	}
}

func sqlOpen(dsn string) (*sql.DB, error) { return sql.Open("postgres", dsn) }
