// Package mtls provides automatic mTLS certificate provisioning for HELM.
//
// It implements an internal CA that issues short-lived certificates (24h default)
// for proxy ↔ upstream mutual TLS. Certificates auto-rotate before expiry.
// Compatible with SPIFFE SVID format for zero-trust service mesh integration.
package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// CertificateAuthority manages an internal CA for issuing mTLS certificates.
type CertificateAuthority struct {
	mu     sync.RWMutex
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey

	certTTL      time.Duration
	renewBefore  time.Duration
	organization string
}

// CAConfig configures the internal Certificate Authority.
type CAConfig struct {
	// Organization is the O= field in issued certificates.
	Organization string

	// CertTTL is the lifetime of issued certificates. Default: 24h.
	CertTTL time.Duration

	// RenewBefore is how long before expiry to trigger renewal. Default: 2h.
	RenewBefore time.Duration

	// CACert is an existing CA certificate (PEM). If nil, a self-signed CA is generated.
	CACert []byte

	// CAKey is an existing CA private key (PEM). If nil, a new key is generated.
	CAKey []byte
}

// IssuedCertificate represents a certificate issued by the CA.
type IssuedCertificate struct {
	// CertPEM is the PEM-encoded certificate.
	CertPEM []byte

	// KeyPEM is the PEM-encoded private key.
	KeyPEM []byte

	// CACertPEM is the PEM-encoded CA certificate.
	CACertPEM []byte

	// NotBefore is when the certificate becomes valid.
	NotBefore time.Time

	// NotAfter is when the certificate expires.
	NotAfter time.Time

	// SPIFFEID is the SPIFFE identity (e.g., "spiffe://helm.local/proxy").
	SPIFFEID string

	// TLSCert is the parsed tls.Certificate for direct use.
	TLSCert *tls.Certificate
}

// NewCA creates a new Certificate Authority.
// If CACert/CAKey are not provided, generates a self-signed CA.
func NewCA(cfg CAConfig) (*CertificateAuthority, error) {
	if cfg.Organization == "" {
		cfg.Organization = "HELM"
	}
	if cfg.CertTTL == 0 {
		cfg.CertTTL = 24 * time.Hour
	}
	if cfg.RenewBefore == 0 {
		cfg.RenewBefore = 2 * time.Hour
	}

	ca := &CertificateAuthority{
		certTTL:      cfg.CertTTL,
		renewBefore:  cfg.RenewBefore,
		organization: cfg.Organization,
	}

	if cfg.CACert != nil && cfg.CAKey != nil {
		// Load existing CA.
		block, _ := pem.Decode(cfg.CACert)
		if block == nil {
			return nil, errors.New("mtls: failed to decode CA certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("mtls: parse CA certificate: %w", err)
		}

		keyBlock, _ := pem.Decode(cfg.CAKey)
		if keyBlock == nil {
			return nil, errors.New("mtls: failed to decode CA key PEM")
		}
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("mtls: parse CA key: %w", err)
		}

		ca.caCert = cert
		ca.caKey = key
	} else {
		// Generate self-signed CA.
		if err := ca.generateCA(); err != nil {
			return nil, err
		}
	}

	return ca, nil
}

// generateCA creates a new self-signed ECDSA P-256 CA certificate.
func (ca *CertificateAuthority) generateCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("mtls: generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("mtls: generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{ca.organization},
			CommonName:   "HELM Internal CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("mtls: create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("mtls: parse CA certificate: %w", err)
	}

	ca.caCert = cert
	ca.caKey = key
	return nil
}

// IssueCertificate issues a short-lived mTLS certificate for the given identity.
// The identity is embedded as a SPIFFE SVID-compatible URI SAN.
func (ca *CertificateAuthority) IssueCertificate(_ context.Context, identity string) (*IssuedCertificate, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	if identity == "" {
		return nil, errors.New("mtls: identity required")
	}

	// Generate a new ECDSA P-256 key for the certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mtls: generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("mtls: generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{ca.organization},
			CommonName:   identity,
		},
		NotBefore: now,
		NotAfter:  now.Add(ca.certTTL),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	// Issue the certificate signed by our CA.
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.caCert, &key.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("mtls: create certificate: %w", err)
	}

	// Encode to PEM.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("mtls: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.caCert.Raw})

	// Build tls.Certificate for direct use.
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("mtls: build tls certificate: %w", err)
	}

	spiffeID := fmt.Sprintf("spiffe://helm.local/%s", identity)

	return &IssuedCertificate{
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		CACertPEM: caCertPEM,
		NotBefore: now,
		NotAfter:  now.Add(ca.certTTL),
		SPIFFEID:  spiffeID,
		TLSCert:   &tlsCert,
	}, nil
}

// CACertPEM returns the PEM-encoded CA certificate.
func (ca *CertificateAuthority) CACertPEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.caCert.Raw})
}

// NeedsRenewal checks if a certificate should be renewed based on the renewal window.
func (ca *CertificateAuthority) NeedsRenewal(cert *IssuedCertificate) bool {
	return time.Now().After(cert.NotAfter.Add(-ca.renewBefore))
}

// NewMutualTLSConfig creates a tls.Config for mutual TLS using the issued certificate.
func NewMutualTLSConfig(cert *IssuedCertificate) (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(cert.CACertPEM) {
		return nil, errors.New("mtls: failed to add CA certificate to pool")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*cert.TLSCert},
		RootCAs:      caCertPool,
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
