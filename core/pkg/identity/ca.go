// Package identity implements agent identity certificates for HELM.
//
// Provides a lightweight Certificate Authority (CA) that issues Ed25519
// identity certificates to agents, enabling verifiable attribution of
// governance receipts to authenticated agents.
//
// Extends existing pkg/certification/attestation.go and
// pkg/substrate/identity/passport.go.
package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AgentCertificate is an Ed25519 identity certificate for an AI agent.
type AgentCertificate struct {
	CertID        string    `json:"cert_id"`
	AgentID       string    `json:"agent_id"`
	AgentName     string    `json:"agent_name"`
	PublicKey     string    `json:"public_key"`     // Hex-encoded Ed25519 public key
	IssuerID      string    `json:"issuer_id"`      // CA identifier
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Capabilities  []string  `json:"capabilities"`   // Allowed effect levels: ["E0", "E1", "E2"]
	MaxDelegation int       `json:"max_delegation"` // Max delegation chain depth
	Signature     string    `json:"signature"`       // CA's Ed25519 signature over cert
	Revoked       bool      `json:"revoked"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

// CertificateRequest is a request to issue an agent certificate.
type CertificateRequest struct {
	AgentID       string   `json:"agent_id"`
	AgentName     string   `json:"agent_name"`
	PublicKey     string   `json:"public_key"`
	Capabilities  []string `json:"capabilities"`
	MaxDelegation int      `json:"max_delegation"`
	ValidityDays  int      `json:"validity_days"`
}

// CertificateAuthority issues and manages agent identity certificates.
type CertificateAuthority struct {
	mu         sync.RWMutex
	caID       string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	certs      map[string]*AgentCertificate // certID → cert
	agentIndex map[string]string            // agentID → certID
	crl        map[string]time.Time         // revoked certIDs
}

// CAConfig configures the Certificate Authority.
type CAConfig struct {
	CAID       string
	PrivateKey ed25519.PrivateKey
}

// NewCertificateAuthority creates a new CA with the given key.
func NewCertificateAuthority(cfg CAConfig) (*CertificateAuthority, error) {
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("identity: CA private key required")
	}
	return &CertificateAuthority{
		caID:       cfg.CAID,
		privateKey: cfg.PrivateKey,
		publicKey:  cfg.PrivateKey.Public().(ed25519.PublicKey),
		certs:      make(map[string]*AgentCertificate),
		agentIndex: make(map[string]string),
		crl:        make(map[string]time.Time),
	}, nil
}

// IssueCertificate creates and signs a new agent identity certificate.
func (ca *CertificateAuthority) IssueCertificate(_ context.Context, req CertificateRequest) (*AgentCertificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if req.AgentID == "" {
		return nil, fmt.Errorf("identity: agent_id required")
	}
	if req.PublicKey == "" {
		return nil, fmt.Errorf("identity: public_key required")
	}

	// Validate public key format.
	pubBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity: invalid Ed25519 public key")
	}

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = 365
	}

	now := time.Now().UTC()
	cert := &AgentCertificate{
		CertID:        generateCertID(),
		AgentID:       req.AgentID,
		AgentName:     req.AgentName,
		PublicKey:     req.PublicKey,
		IssuerID:      ca.caID,
		IssuedAt:      now,
		ExpiresAt:     now.AddDate(0, 0, validityDays),
		Capabilities:  req.Capabilities,
		MaxDelegation: req.MaxDelegation,
	}

	// Sign the certificate.
	certBytes, err := json.Marshal(struct {
		CertID        string   `json:"cert_id"`
		AgentID       string   `json:"agent_id"`
		PublicKey     string   `json:"public_key"`
		IssuerID      string   `json:"issuer_id"`
		IssuedAt      string   `json:"issued_at"`
		ExpiresAt     string   `json:"expires_at"`
		Capabilities  []string `json:"capabilities"`
		MaxDelegation int      `json:"max_delegation"`
	}{
		CertID:        cert.CertID,
		AgentID:       cert.AgentID,
		PublicKey:     cert.PublicKey,
		IssuerID:      cert.IssuerID,
		IssuedAt:      cert.IssuedAt.Format(time.RFC3339),
		ExpiresAt:     cert.ExpiresAt.Format(time.RFC3339),
		Capabilities:  cert.Capabilities,
		MaxDelegation: cert.MaxDelegation,
	})
	if err != nil {
		return nil, fmt.Errorf("identity: failed to marshal cert for signing: %w", err)
	}

	sig := ed25519.Sign(ca.privateKey, certBytes)
	cert.Signature = hex.EncodeToString(sig)

	ca.certs[cert.CertID] = cert
	ca.agentIndex[cert.AgentID] = cert.CertID

	return cert, nil
}

// VerifyCertificate validates a certificate's signature and expiry.
func (ca *CertificateAuthority) VerifyCertificate(_ context.Context, cert *AgentCertificate) error {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	// Check revocation.
	if _, revoked := ca.crl[cert.CertID]; revoked || cert.Revoked {
		return fmt.Errorf("identity: certificate %s is revoked", cert.CertID)
	}

	// Check expiry.
	if time.Now().After(cert.ExpiresAt) {
		return fmt.Errorf("identity: certificate %s expired at %s", cert.CertID, cert.ExpiresAt)
	}

	// Verify signature.
	certBytes, err := json.Marshal(struct {
		CertID        string   `json:"cert_id"`
		AgentID       string   `json:"agent_id"`
		PublicKey     string   `json:"public_key"`
		IssuerID      string   `json:"issuer_id"`
		IssuedAt      string   `json:"issued_at"`
		ExpiresAt     string   `json:"expires_at"`
		Capabilities  []string `json:"capabilities"`
		MaxDelegation int      `json:"max_delegation"`
	}{
		CertID:        cert.CertID,
		AgentID:       cert.AgentID,
		PublicKey:     cert.PublicKey,
		IssuerID:      cert.IssuerID,
		IssuedAt:      cert.IssuedAt.Format(time.RFC3339),
		ExpiresAt:     cert.ExpiresAt.Format(time.RFC3339),
		Capabilities:  cert.Capabilities,
		MaxDelegation: cert.MaxDelegation,
	})
	if err != nil {
		return fmt.Errorf("identity: marshal error: %w", err)
	}

	sigBytes, err := hex.DecodeString(cert.Signature)
	if err != nil {
		return fmt.Errorf("identity: invalid signature encoding")
	}

	if !ed25519.Verify(ca.publicKey, certBytes, sigBytes) {
		return fmt.Errorf("identity: signature verification failed")
	}

	return nil
}

// RevokeCertificate revokes an agent certificate.
func (ca *CertificateAuthority) RevokeCertificate(_ context.Context, certID string) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	cert, exists := ca.certs[certID]
	if !exists {
		return fmt.Errorf("identity: certificate %s not found", certID)
	}

	now := time.Now().UTC()
	cert.Revoked = true
	cert.RevokedAt = &now
	ca.crl[certID] = now

	return nil
}

// GetCertificateByAgent returns the active certificate for an agent.
func (ca *CertificateAuthority) GetCertificateByAgent(_ context.Context, agentID string) (*AgentCertificate, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	certID, exists := ca.agentIndex[agentID]
	if !exists {
		return nil, fmt.Errorf("identity: no certificate for agent %s", agentID)
	}
	return ca.certs[certID], nil
}

// CAPublicKey returns the CA's public key in hex.
func (ca *CertificateAuthority) CAPublicKey() string {
	return hex.EncodeToString(ca.publicKey)
}

func generateCertID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	h := sha256.Sum256(b)
	return "cert-" + hex.EncodeToString(h[:])[:16]
}
