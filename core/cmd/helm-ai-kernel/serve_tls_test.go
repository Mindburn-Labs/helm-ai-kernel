package main

// quantum_posture: test-only ECDSA P-256 certificates for the classical TLS
// listener; nothing here claims post-quantum transport.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

type testTLSAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestTLSAuthority(t *testing.T, name string) testTLSAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testTLSAuthority{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns a PEM certificate and key signed by the authority.
func (a testTLSAuthority) issue(t *testing.T, serial int64, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "helm-kernel-test"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func (a testTLSAuthority) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.cert)
	return pool
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// setServeTLSEnv writes a server pair (and optional client CA) and points the
// HELM_TLS_* variables at it. It returns the cert and key paths.
func setServeTLSEnv(t *testing.T, serverCA testTLSAuthority, clientCA *testTLSAuthority, clientAuth string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certPEM, keyPEM := serverCA.issue(t, 2, x509.ExtKeyUsageServerAuth)
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeTestFile(t, certFile, certPEM)
	writeTestFile(t, keyFile, keyPEM)
	t.Setenv(serveTLSCertFileEnv, certFile)
	t.Setenv(serveTLSKeyFileEnv, keyFile)
	t.Setenv(serveTLSClientCAFileEnv, "")
	t.Setenv(serveTLSClientAuthEnv, clientAuth)
	if clientCA != nil {
		caFile := filepath.Join(dir, "ca.crt")
		writeTestFile(t, caFile, clientCA.pem)
		t.Setenv(serveTLSClientCAFileEnv, caFile)
	}
	return certFile, keyFile
}

// serveTLSForTest serves handler over a listener built from the HELM_TLS_*
// environment, the same way serve does.
func serveTLSForTest(t *testing.T, handler http.Handler) string {
	t.Helper()
	config, err := serveTLSConfigFromEnv()
	if err != nil || config == nil {
		t.Fatalf("serveTLSConfigFromEnv = %v, %v", config, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, TLSConfig: config, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	return "https://" + listener.Addr().String()
}

func tlsTestClient(roots *x509.CertPool, certs []tls.Certificate, maxVersion uint16) *http.Client {
	config := &tls.Config{
		RootCAs:    roots,
		MaxVersion: maxVersion,
		MinVersion: tls.VersionTLS10, // lets the test offer a version below the server's floor
	}
	if len(certs) > 0 {
		// Present the certificate even when its issuer is not among the
		// server's acceptable CAs; crypto/tls would otherwise send none.
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &certs[0], nil }
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: config}}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
}

func TestServeTLSConfigRefusesPartialConfiguration(t *testing.T) {
	serverCA := newTestTLSAuthority(t, "server-ca")
	certFile, keyFile := setServeTLSEnv(t, serverCA, nil, "")
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	writeTestFile(t, caFile, serverCA.pem)
	notPEM := filepath.Join(t.TempDir(), "junk.crt")
	writeTestFile(t, notPEM, []byte("not a certificate"))

	for name, env := range map[string]map[string]string{
		"cert without key":                {serveTLSCertFileEnv: certFile, serveTLSKeyFileEnv: ""},
		"key without cert":                {serveTLSCertFileEnv: "", serveTLSKeyFileEnv: keyFile},
		"client CA without a server pair": {serveTLSCertFileEnv: "", serveTLSKeyFileEnv: "", serveTLSClientCAFileEnv: caFile},
		"client auth without a pair":      {serveTLSCertFileEnv: "", serveTLSKeyFileEnv: "", serveTLSClientAuthEnv: serveTLSClientAuthRequire},
		"client auth without a CA":        {serveTLSClientAuthEnv: serveTLSClientAuthRequire},
		"client CA without a mode":        {serveTLSClientCAFileEnv: caFile},
		"unknown client auth mode":        {serveTLSClientCAFileEnv: caFile, serveTLSClientAuthEnv: "optional"},
		"client CA holds no certificate":  {serveTLSClientCAFileEnv: notPEM, serveTLSClientAuthEnv: serveTLSClientAuthRequire},
		"unreadable certificate":          {serveTLSCertFileEnv: notPEM},
		"missing key file":                {serveTLSKeyFileEnv: filepath.Join(t.TempDir(), "absent.key")},
	} {
		t.Run(name, func(t *testing.T) {
			setServeTLSEnv(t, serverCA, nil, "")
			for key, value := range env {
				t.Setenv(key, value)
			}
			if config, err := serveTLSConfigFromEnv(); err == nil {
				t.Fatalf("accepted a partial configuration: %+v", config)
			}
		})
	}

	t.Run("unset stays plain HTTP", func(t *testing.T) {
		for _, key := range []string{serveTLSCertFileEnv, serveTLSKeyFileEnv, serveTLSClientCAFileEnv, serveTLSClientAuthEnv} {
			t.Setenv(key, "")
		}
		if config, err := serveTLSConfigFromEnv(); config != nil || err != nil {
			t.Fatalf("serveTLSConfigFromEnv = %v, %v; want nil, nil", config, err)
		}
	})
}

func TestServeTLSHandshakeEnforcesMinimumVersion(t *testing.T) {
	serverCA := newTestTLSAuthority(t, "server-ca")
	setServeTLSEnv(t, serverCA, nil, "")
	base := serveTLSForTest(t, okHandler())

	resp, err := tlsTestClient(serverCA.pool(), nil, 0).Get(base)
	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("negotiated %+v", resp.TLS)
	}

	if _, err := tlsTestClient(serverCA.pool(), nil, tls.VersionTLS11).Get(base); err == nil {
		t.Fatal("a TLS 1.1 client completed a handshake")
	}
	if resp, err := tlsTestClient(serverCA.pool(), nil, tls.VersionTLS12).Get(base); err != nil {
		t.Fatalf("a TLS 1.2 client was refused: %v", err)
	} else {
		_ = resp.Body.Close()
	}
}

func TestServeTLSRequiredClientCertificate(t *testing.T) {
	serverCA := newTestTLSAuthority(t, "server-ca")
	clientCA := newTestTLSAuthority(t, "client-ca")
	setServeTLSEnv(t, serverCA, &clientCA, serveTLSClientAuthRequire)

	var peer *x509.Certificate
	base := serveTLSForTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peer = r.TLS.PeerCertificates[0]
		}
		_, _ = io.WriteString(w, "ok")
	}))
	clientPair := func(ca testTLSAuthority) []tls.Certificate {
		certPEM, keyPEM := ca.issue(t, 3, x509.ExtKeyUsageClientAuth)
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return []tls.Certificate{pair}
	}

	if _, err := tlsTestClient(serverCA.pool(), nil, 0).Get(base); err == nil {
		t.Fatal("a client without a certificate was served")
	}
	if _, err := tlsTestClient(serverCA.pool(), clientPair(serverCA), 0).Get(base); err == nil {
		t.Fatal("a client certificate from an untrusted CA was served")
	}

	accepted := clientPair(clientCA)
	resp, err := tlsTestClient(serverCA.pool(), accepted, 0).Get(base)
	if err != nil {
		t.Fatalf("a client with a trusted certificate was refused: %v", err)
	}
	_ = resp.Body.Close()
	// The peer certificate is what the ADR-0005 cnf check compares.
	sum := sha256.Sum256(accepted[0].Certificate[0])
	if !mcppkg.CertificateMatchesThumbprint(peer, base64.RawURLEncoding.EncodeToString(sum[:])) {
		t.Fatal("the handler did not see the verified client certificate")
	}
}

func TestServeTLSVerifyIfGivenClientCertificate(t *testing.T) {
	serverCA := newTestTLSAuthority(t, "server-ca")
	clientCA := newTestTLSAuthority(t, "client-ca")
	setServeTLSEnv(t, serverCA, &clientCA, serveTLSClientAuthVerifyIfGiven)
	base := serveTLSForTest(t, okHandler())

	resp, err := tlsTestClient(serverCA.pool(), nil, 0).Get(base)
	if err != nil {
		t.Fatalf("verify-if-given refused a client without a certificate: %v", err)
	}
	_ = resp.Body.Close()
	certPEM, keyPEM := serverCA.issue(t, 4, x509.ExtKeyUsageClientAuth)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tlsTestClient(serverCA.pool(), []tls.Certificate{pair}, 0).Get(base); err == nil {
		t.Fatal("verify-if-given accepted a certificate from an untrusted CA")
	}
}

func TestServeTLSPicksUpARotatedCertificate(t *testing.T) {
	serverCA := newTestTLSAuthority(t, "server-ca")
	certFile, keyFile := setServeTLSEnv(t, serverCA, nil, "")
	base := serveTLSForTest(t, okHandler())
	serial := func() int64 {
		t.Helper()
		// A fresh transport per call forces a new handshake.
		resp, err := tlsTestClient(serverCA.pool(), nil, 0).Get(base)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.TLS.PeerCertificates[0].SerialNumber.Int64()
	}
	if got := serial(); got != 2 {
		t.Fatalf("initial serial = %d, want 2", got)
	}

	certPEM, keyPEM := serverCA.issue(t, 77, x509.ExtKeyUsageServerAuth)
	writeTestFile(t, certFile, certPEM)
	writeTestFile(t, keyFile, keyPEM)
	later := time.Now().Add(time.Minute)
	for _, path := range []string{certFile, keyFile} {
		if err := os.Chtimes(path, later, later); err != nil {
			t.Fatal(err)
		}
	}
	if got := serial(); got != 77 {
		t.Fatalf("serial after rotation = %d, want 77", got)
	}

	// A half-written rotation keeps the last good pair.
	writeTestFile(t, keyFile, []byte("truncated"))
	if err := os.Chtimes(keyFile, later.Add(time.Minute), later.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := serial(); got != 77 {
		t.Fatalf("serial after a broken rotation = %d, want the previous 77", got)
	}
}

// TestServeListensOverTLSWhenConfigured runs serve itself: the API listener
// speaks only TLS and serves the receipt keyring over it.
func TestServeListensOverTLSWhenConfigured(t *testing.T) {
	serverCA := newTestTLSAuthority(t, "server-ca")
	setServeTLSEnv(t, serverCA, nil, "")
	base := strings.Replace(startInProcessServeForTest(t, t.TempDir()), "http://", "https://", 1)

	resp, err := tlsTestClient(serverCA.pool(), nil, 0).Get(base + receiptKeyringPath)
	if err != nil {
		t.Fatalf("GET keyring over TLS: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"keyring_version":"kernel-evaluate-receipt-keyring.v1"`)) {
		t.Fatalf("keyring over TLS: %d %s", resp.StatusCode, body)
	}

	plain := &http.Client{Timeout: 10 * time.Second}
	if resp, err := plain.Get(strings.Replace(base, "https://", "http://", 1) + "/healthz"); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("the TLS listener answered plain HTTP")
		}
	}
}

func TestServeRefusesToStartWithPartialTLS(t *testing.T) {
	chdirTempDir(t)
	serverCA := newTestTLSAuthority(t, "server-ca")
	setServeTLSEnv(t, serverCA, nil, "")
	t.Setenv(serveTLSKeyFileEnv, "")
	err := runServerWithOptions(serverOptions{Mode: "serve", BindAddr: "127.0.0.1", Port: freeServeTestPort(t), DataDir: t.TempDir(), Stdout: io.Discard, Stderr: io.Discard})
	if err == nil || !strings.Contains(err.Error(), serveTLSCertFileEnv) {
		t.Fatalf("serve started with a partial TLS configuration: %v", err)
	}
}
