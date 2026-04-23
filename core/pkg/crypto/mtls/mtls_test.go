package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCA_SelfSigned(t *testing.T) {
	ca, err := NewCA(CAConfig{
		Organization: "TestOrg",
	})
	require.NoError(t, err)

	assert.Equal(t, "HELM Internal CA", ca.caCert.Subject.CommonName)
	assert.True(t, ca.caCert.IsCA)
	assert.Equal(t, 24*time.Hour, ca.certTTL)
}

func TestNewCA_Defaults(t *testing.T) {
	ca, err := NewCA(CAConfig{})
	require.NoError(t, err)

	assert.Equal(t, "HELM", ca.organization)
	assert.Equal(t, 24*time.Hour, ca.certTTL)
	assert.Equal(t, 2*time.Hour, ca.renewBefore)
}

func TestIssueCertificate(t *testing.T) {
	ca, err := NewCA(CAConfig{
		Organization: "TestOrg",
		CertTTL:      1 * time.Hour,
	})
	require.NoError(t, err)

	cert, err := ca.IssueCertificate(context.Background(), "proxy")
	require.NoError(t, err)

	assert.NotEmpty(t, cert.CertPEM)
	assert.NotEmpty(t, cert.KeyPEM)
	assert.NotEmpty(t, cert.CACertPEM)
	assert.Equal(t, "spiffe://helm.local/proxy", cert.SPIFFEID)
	assert.WithinDuration(t, time.Now().Add(1*time.Hour), cert.NotAfter, 5*time.Second)
	assert.NotNil(t, cert.TLSCert)

	// Verify the certificate was signed by the CA.
	certPool := x509.NewCertPool()
	require.True(t, certPool.AppendCertsFromPEM(cert.CACertPEM))

	leaf, err := x509.ParseCertificate(cert.TLSCert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, "proxy", leaf.Subject.CommonName)

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: certPool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	})
	assert.NoError(t, err, "certificate should verify against CA")
}

func TestIssueCertificate_EmptyIdentity(t *testing.T) {
	ca, _ := NewCA(CAConfig{})
	_, err := ca.IssueCertificate(context.Background(), "")
	assert.Error(t, err, "should reject empty identity")
}

func TestNeedsRenewal(t *testing.T) {
	ca, err := NewCA(CAConfig{
		CertTTL:     4 * time.Hour,
		RenewBefore: 2 * time.Hour,
	})
	require.NoError(t, err)

	// Fresh cert should not need renewal.
	freshCert := &IssuedCertificate{
		NotAfter: time.Now().Add(4 * time.Hour),
	}
	assert.False(t, ca.NeedsRenewal(freshCert), "fresh cert should not need renewal")

	// Cert about to expire should need renewal.
	expiringCert := &IssuedCertificate{
		NotAfter: time.Now().Add(1 * time.Hour), // Within renewal window (2h before expiry)
	}
	assert.True(t, ca.NeedsRenewal(expiringCert), "cert within renewal window should need renewal")
}

func TestNewMutualTLSConfig(t *testing.T) {
	ca, err := NewCA(CAConfig{})
	require.NoError(t, err)

	cert, err := ca.IssueCertificate(context.Background(), "test-service")
	require.NoError(t, err)

	cfg, err := NewMutualTLSConfig(cert)
	require.NoError(t, err)

	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.Len(t, cfg.Certificates, 1)
	assert.NotNil(t, cfg.RootCAs)
	assert.NotNil(t, cfg.ClientCAs)
}

func TestMultipleCertificates(t *testing.T) {
	ca, err := NewCA(CAConfig{})
	require.NoError(t, err)

	// Issue multiple certificates — they should all be unique and valid.
	certs := make([]*IssuedCertificate, 5)
	for i := 0; i < 5; i++ {
		cert, err := ca.IssueCertificate(context.Background(), "service-"+string(rune('a'+i)))
		require.NoError(t, err)
		certs[i] = cert
	}

	// All should be different.
	for i := 0; i < len(certs); i++ {
		for j := i + 1; j < len(certs); j++ {
			assert.NotEqual(t, certs[i].CertPEM, certs[j].CertPEM, "certificates should be unique")
		}
	}
}

func TestCACertPEM(t *testing.T) {
	ca, err := NewCA(CAConfig{})
	require.NoError(t, err)

	pemBytes := ca.CACertPEM()
	assert.Contains(t, string(pemBytes), "BEGIN CERTIFICATE")
	assert.Contains(t, string(pemBytes), "END CERTIFICATE")

	// Should be parseable.
	pool := x509.NewCertPool()
	assert.True(t, pool.AppendCertsFromPEM(pemBytes))
}
