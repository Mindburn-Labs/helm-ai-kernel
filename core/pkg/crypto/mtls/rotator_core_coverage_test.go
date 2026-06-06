package mtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCA_LoadExistingCAAndRejectsMalformedMaterial(t *testing.T) {
	source, err := NewCA(CAConfig{Organization: "LoadedOrg"})
	require.NoError(t, err)

	keyPEM := caKeyPEM(t, source)
	loaded, err := NewCA(CAConfig{
		Organization: "ReloadedOrg",
		CertTTL:      3 * time.Hour,
		RenewBefore:  30 * time.Minute,
		CACert:       source.CACertPEM(),
		CAKey:        keyPEM,
	})
	require.NoError(t, err)

	assert.True(t, bytes.Equal(source.caCert.Raw, loaded.caCert.Raw))
	assert.Equal(t, source.caKey.D, loaded.caKey.D)
	assert.Equal(t, "ReloadedOrg", loaded.organization)
	assert.Equal(t, 3*time.Hour, loaded.certTTL)
	assert.Equal(t, 30*time.Minute, loaded.renewBefore)

	_, err = NewCA(CAConfig{CACert: []byte("not-pem"), CAKey: keyPEM})
	require.ErrorContains(t, err, "failed to decode CA certificate PEM")

	invalidCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-der")})
	_, err = NewCA(CAConfig{CACert: invalidCertPEM, CAKey: keyPEM})
	require.ErrorContains(t, err, "parse CA certificate")

	_, err = NewCA(CAConfig{CACert: source.CACertPEM(), CAKey: []byte("not-pem")})
	require.ErrorContains(t, err, "failed to decode CA key PEM")

	invalidKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not-der")})
	_, err = NewCA(CAConfig{CACert: source.CACertPEM(), CAKey: invalidKeyPEM})
	require.ErrorContains(t, err, "parse CA key")
}

func TestNewMutualTLSConfigRejectsInvalidCA(t *testing.T) {
	cfg, err := NewMutualTLSConfig(&IssuedCertificate{CACertPEM: []byte("not a certificate")})

	assert.Nil(t, cfg)
	require.ErrorContains(t, err, "failed to add CA certificate to pool")
}

func TestNewCertRotatorDefaultsAndTLSConfig(t *testing.T) {
	ca, err := NewCA(CAConfig{})
	require.NoError(t, err)

	rotator, err := NewCertRotator(RotatorConfig{
		CA:       ca,
		Identity: "proxy",
	})
	require.NoError(t, err)

	assert.Equal(t, 4*time.Hour, rotator.renewBefore)
	assert.Equal(t, time.Hour, rotator.checkInterval)
	assert.Same(t, ca, rotator.ca)
	assert.Equal(t, "proxy", rotator.identity)

	cert, err := rotator.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.NotEmpty(t, cert.Certificate)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, "proxy", leaf.Subject.CommonName)

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: ca.CACertPool(),
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	})
	require.NoError(t, err)

	peer, err := ca.IssueCertificate(context.Background(), "rotating-peer")
	require.NoError(t, err)

	cfg := NewRotatingTLSConfig(rotator, ca, WithExpectedPeerSPIFFEID(peer.SPIFFEID))
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.True(t, cfg.InsecureSkipVerify)
	assert.NotNil(t, cfg.RootCAs)
	assert.NotNil(t, cfg.ClientCAs)
	require.NotNil(t, cfg.GetCertificate)
	require.NotNil(t, cfg.VerifyConnection)
	require.NoError(t, cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafFromIssued(t, peer)}}))

	wrongPeer, err := ca.IssueCertificate(context.Background(), "wrong-rotating-peer")
	require.NoError(t, err)
	err = cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafFromIssued(t, wrongPeer)}})
	require.ErrorContains(t, err, "peer SPIFFE ID not allowed")

	failClosed := NewRotatingTLSConfig(rotator, ca)
	err = failClosed.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafFromIssued(t, peer)}})
	require.ErrorContains(t, err, "expected peer SPIFFE ID required")

	fromConfig, err := cfg.GetCertificate(nil)
	require.NoError(t, err)
	assert.Same(t, cert, fromConfig)
}

func TestNewCertRotatorPropagatesInitialIssueError(t *testing.T) {
	ca, err := NewCA(CAConfig{})
	require.NoError(t, err)

	rotator, err := NewCertRotator(RotatorConfig{
		CA:       ca,
		Identity: "",
		Logger:   mtlsDiscardLogger(),
	})

	assert.Nil(t, rotator)
	require.ErrorContains(t, err, "identity required")
}

func TestCertRotatorRotateReplacesCurrentCertificate(t *testing.T) {
	ca, err := NewCA(CAConfig{})
	require.NoError(t, err)

	rotator, err := NewCertRotator(RotatorConfig{
		CA:       ca,
		Identity: "proxy",
		Logger:   mtlsDiscardLogger(),
	})
	require.NoError(t, err)

	first, err := rotator.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, first)

	require.NoError(t, rotator.rotate())
	second, err := rotator.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, second)

	assert.NotEqual(t, first.Certificate[0], second.Certificate[0])
}

func TestCertRotatorStartRecreatesMissingCertificate(t *testing.T) {
	ca, err := NewCA(CAConfig{})
	require.NoError(t, err)

	rotator, err := NewCertRotator(RotatorConfig{
		CA:            ca,
		Identity:      "proxy",
		CheckInterval: 5 * time.Millisecond,
		Logger:        mtlsDiscardLogger(),
	})
	require.NoError(t, err)

	rotator.mu.Lock()
	rotator.current = nil
	rotator.mu.Unlock()

	rotator.Start()
	waitForMTLSCondition(t, func() bool {
		cert, err := rotator.GetCertificate(nil)
		return err == nil && parseableTLSCert(cert)
	})
	rotator.Stop()
	time.Sleep(10 * time.Millisecond)
}

func TestCertRotatorStartReplacesUnparseableCertificate(t *testing.T) {
	ca, err := NewCA(CAConfig{})
	require.NoError(t, err)

	rotator, err := NewCertRotator(RotatorConfig{
		CA:            ca,
		Identity:      "proxy",
		CheckInterval: 5 * time.Millisecond,
		Logger:        mtlsDiscardLogger(),
	})
	require.NoError(t, err)

	rotator.mu.Lock()
	rotator.current = &tls.Certificate{Certificate: [][]byte{[]byte("not-der")}}
	rotator.mu.Unlock()

	rotator.Start()
	waitForMTLSCondition(t, func() bool {
		cert, err := rotator.GetCertificate(nil)
		return err == nil && parseableTLSCert(cert)
	})
	rotator.Stop()
	time.Sleep(10 * time.Millisecond)
}

func TestCertRotatorStartRenewsNearExpiryCertificate(t *testing.T) {
	ca, err := NewCA(CAConfig{CertTTL: time.Hour})
	require.NoError(t, err)

	rotator, err := NewCertRotator(RotatorConfig{
		CA:            ca,
		Identity:      "proxy",
		RenewBefore:   2 * time.Hour,
		CheckInterval: 5 * time.Millisecond,
		Logger:        mtlsDiscardLogger(),
	})
	require.NoError(t, err)

	first, err := rotator.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, first)
	firstDER := append([]byte(nil), first.Certificate[0]...)

	rotator.Start()
	waitForMTLSCondition(t, func() bool {
		cert, err := rotator.GetCertificate(nil)
		return err == nil && cert != nil && len(cert.Certificate) > 0 && !bytes.Equal(firstDER, cert.Certificate[0])
	})
	rotator.Stop()
	time.Sleep(10 * time.Millisecond)
}

func TestCertRotatorStartLogsFailedRenewal(t *testing.T) {
	handler := &recordingSlogHandler{}
	ca, err := NewCA(CAConfig{CertTTL: time.Hour})
	require.NoError(t, err)

	rotator, err := NewCertRotator(RotatorConfig{
		CA:            ca,
		Identity:      "proxy",
		RenewBefore:   2 * time.Hour,
		CheckInterval: 5 * time.Millisecond,
		Logger:        slog.New(handler),
	})
	require.NoError(t, err)

	rotator.identity = ""
	rotator.Start()
	waitForMTLSCondition(t, func() bool {
		return handler.saw("mtls: rotation failed")
	})
	rotator.Stop()
	time.Sleep(10 * time.Millisecond)
}

func caKeyPEM(t *testing.T, ca *CertificateAuthority) []byte {
	t.Helper()

	keyDER, err := x509.MarshalECPrivateKey(ca.caKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func mtlsDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func waitForMTLSCondition(t *testing.T, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Fatal("condition was not met before deadline")
}

func parseableTLSCert(cert *tls.Certificate) bool {
	if cert == nil || len(cert.Certificate) == 0 {
		return false
	}
	_, err := x509.ParseCertificate(cert.Certificate[0])
	return err == nil
}

type recordingSlogHandler struct {
	mu       sync.Mutex
	messages []string
}

func (h *recordingSlogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *recordingSlogHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.messages = append(h.messages, record.Message)
	return nil
}

func (h *recordingSlogHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *recordingSlogHandler) WithGroup(string) slog.Handler {
	return h
}

func (h *recordingSlogHandler) saw(message string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, candidate := range h.messages {
		if candidate == message {
			return true
		}
	}
	return false
}
