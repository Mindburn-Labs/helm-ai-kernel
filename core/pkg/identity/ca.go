// quantum_posture: classical Ed25519 agent certificates, unchanged here; migration
// follows the kernel-wide signing policy.

// Package identity implements agent identity certificates for HELM.
//
// Provides a lightweight Certificate Authority (CA) that issues Ed25519
// identity certificates to agents, enabling verifiable attribution of
// governance receipts to authenticated agents.
package identity

import (
	"crypto/ed25519"
	"sync"
	"time"
)

// AgentCertificate is an Ed25519 identity certificate for an AI agent.
type AgentCertificate struct {
	CertID        string     `json:"cert_id"`
	AgentID       string     `json:"agent_id"`
	AgentName     string     `json:"agent_name"`
	PublicKey     string     `json:"public_key"` // Hex-encoded Ed25519 public key
	IssuerID      string     `json:"issuer_id"`  // CA identifier
	IssuedAt      time.Time  `json:"issued_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	Capabilities  []string   `json:"capabilities"`   // Allowed effect levels: ["E0", "E1", "E2"]
	MaxDelegation int        `json:"max_delegation"` // Max delegation chain depth
	Signature     string     `json:"signature"`      // CA's Ed25519 signature over cert
	Revoked       bool       `json:"revoked"`
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
