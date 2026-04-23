// Package keystore provides the canonical key management interface for HELM.
//
// KeyProvider is the single authority for all signing, sealing, and verification.
// It wraps the existing crypto.Signer/KeyRing with rotation-aware key selection,
// KID tracking, and purpose-separated keys.
//
// All signatures produced through KeyProvider include a KID (Key ID) that can be
// verified against the Trust Registry at any lamport height.
package keystore

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sort"
	"sync"
	"time"

	helmcrypto "github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

// KeyPurpose defines what a key can be used for.
type KeyPurpose string

const (
	PurposeSigning KeyPurpose = "signing"
	PurposeSealing KeyPurpose = "sealing"
	PurposeBoth    KeyPurpose = "both"
)

// KeyMeta describes a key without exposing private material.
type KeyMeta struct {
	KID       string     `json:"kid"`
	Algorithm string     `json:"algorithm"`
	Purpose   KeyPurpose `json:"purpose"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// IsActive returns true if the key has not been revoked or expired.
func (m KeyMeta) IsActive(now time.Time) bool {
	if m.RevokedAt != nil {
		return false
	}
	if m.ExpiresAt != nil && now.After(*m.ExpiresAt) {
		return false
	}
	return true
}

// Signer signs data and provides key identity.
type Signer interface {
	Sign(data []byte) ([]byte, error)
	KID() string
	Algorithm() string
	PublicKey() []byte
}

// Verifier verifies signatures against known keys.
type Verifier interface {
	Verify(kid string, data, signature []byte) (bool, error)
}

// Sealer encrypts and decrypts data at rest.
type Sealer interface {
	Seal(plaintext []byte) (ciphertext []byte, err error)
	Open(ciphertext []byte) (plaintext []byte, err error)
}

// KeyProvider is the canonical interface for key management in HELM.
// All signing, verification, and encryption MUST go through this interface.
type KeyProvider interface {
	// ActiveSigner returns the current active signing key.
	ActiveSigner() (Signer, error)

	// SignerByKID retrieves a specific signer by Key ID.
	// Returns an error if the key is revoked or unknown.
	SignerByKID(kid string) (Signer, error)

	// Verify checks a signature against the key identified by kid.
	Verify(kid string, data, signature []byte) (bool, error)

	// Sealer returns the active sealer for encryption at rest.
	Sealer() (Sealer, error)

	// ListKeys returns metadata for all keys (active, revoked, expired).
	ListKeys() []KeyMeta

	// ActiveKeys returns only currently active key metadata.
	ActiveKeys(now time.Time) []KeyMeta
}

// ── Ed25519 Signer Adapter ───────────────────────────────────

// ed25519Signer adapts the existing crypto.Ed25519Signer to the new Signer interface.
type ed25519Signer struct {
	inner *helmcrypto.Ed25519Signer
	kid   string
}

func (s *ed25519Signer) Sign(data []byte) ([]byte, error) {
	sigHex, err := s.inner.Sign(data)
	if err != nil {
		return nil, err
	}
	// Convert hex signature to bytes
	return []byte(sigHex), nil
}

func (s *ed25519Signer) KID() string       { return s.kid }
func (s *ed25519Signer) Algorithm() string { return "ed25519" }
func (s *ed25519Signer) PublicKey() []byte { return s.inner.PublicKeyBytes() }

// ── In-Memory KeyProvider ────────────────────────────────────

// MemoryKeyProvider is an in-memory KeyProvider for development and testing.
// Production should use a SOPS-backed or HSM-backed provider.
type MemoryKeyProvider struct {
	mu      sync.RWMutex
	signers map[string]Signer
	metas   map[string]KeyMeta
	ordered []string // insertion order for deterministic active key selection
	sealer  Sealer
}

// NewMemoryKeyProvider creates a new in-memory key provider.
func NewMemoryKeyProvider() *MemoryKeyProvider {
	return &MemoryKeyProvider{
		signers: make(map[string]Signer),
		metas:   make(map[string]KeyMeta),
		ordered: make([]string, 0),
	}
}

// GenerateKey creates and registers a new Ed25519 signing key.
func (p *MemoryKeyProvider) GenerateKey(kid string) (Signer, error) {
	inner, err := helmcrypto.NewEd25519Signer(kid)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}
	s := &ed25519Signer{inner: inner, kid: kid}
	meta := KeyMeta{
		KID:       kid,
		Algorithm: "ed25519",
		Purpose:   PurposeSigning,
		CreatedAt: time.Now().UTC(),
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.signers[kid] = s
	p.metas[kid] = meta
	p.ordered = append(p.ordered, kid)

	return s, nil
}

// ImportKey registers an existing Ed25519 private key.
func (p *MemoryKeyProvider) ImportKey(kid string, privateKey ed25519.PrivateKey) Signer {
	inner := helmcrypto.NewEd25519SignerFromKey(privateKey, kid)
	s := &ed25519Signer{inner: inner, kid: kid}
	meta := KeyMeta{
		KID:       kid,
		Algorithm: "ed25519",
		Purpose:   PurposeSigning,
		CreatedAt: time.Now().UTC(),
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.signers[kid] = s
	p.metas[kid] = meta
	p.ordered = append(p.ordered, kid)

	return s
}

// RevokeKey marks a key as revoked. It remains available for historical verification.
func (p *MemoryKeyProvider) RevokeKey(kid string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, ok := p.metas[kid]
	if !ok {
		return fmt.Errorf("unknown key: %s", kid)
	}
	now := time.Now().UTC()
	meta.RevokedAt = &now
	p.metas[kid] = meta
	return nil
}

// SetSealer sets the active sealer.
func (p *MemoryKeyProvider) SetSealer(s Sealer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sealer = s
}

// ── KeyProvider interface implementation ─────────────────────

func (p *MemoryKeyProvider) ActiveSigner() (Signer, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()
	// Walk in reverse insertion order: latest active key wins
	for i := len(p.ordered) - 1; i >= 0; i-- {
		kid := p.ordered[i]
		if meta, ok := p.metas[kid]; ok && meta.IsActive(now) {
			if s, ok := p.signers[kid]; ok {
				return s, nil
			}
		}
	}
	return nil, fmt.Errorf("no active signing key available")
}

func (p *MemoryKeyProvider) SignerByKID(kid string) (Signer, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	meta, ok := p.metas[kid]
	if !ok {
		return nil, fmt.Errorf("unknown key: %s", kid)
	}
	if meta.RevokedAt != nil {
		return nil, fmt.Errorf("key %s has been revoked", kid)
	}
	s, ok := p.signers[kid]
	if !ok {
		return nil, fmt.Errorf("signer not found for key: %s", kid)
	}
	return s, nil
}

func (p *MemoryKeyProvider) Verify(_ context.Context, kid string, data, signature []byte) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// For verification, we allow revoked keys (historical verification)
	s, ok := p.signers[kid]
	if !ok {
		return false, fmt.Errorf("unknown key: %s", kid)
	}
	// Reconstruct the Ed25519 public key for verification
	pubKey := s.PublicKey()
	if len(pubKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size for key %s", kid)
	}
	return ed25519.Verify(pubKey, data, signature), nil
}

// Verify implements the non-context version for KeyProvider interface.
func (p *MemoryKeyProvider) VerifySignature(kid string, data, signature []byte) (bool, error) {
	return p.Verify(context.Background(), kid, data, signature)
}

func (p *MemoryKeyProvider) Sealer() (Sealer, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.sealer == nil {
		return nil, fmt.Errorf("no sealer configured")
	}
	return p.sealer, nil
}

func (p *MemoryKeyProvider) ListKeys() []KeyMeta {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]KeyMeta, 0, len(p.metas))
	for _, kid := range p.ordered {
		if meta, ok := p.metas[kid]; ok {
			result = append(result, meta)
		}
	}
	return result
}

func (p *MemoryKeyProvider) ActiveKeys(now time.Time) []KeyMeta {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]KeyMeta, 0)
	for _, kid := range p.ordered {
		if meta, ok := p.metas[kid]; ok && meta.IsActive(now) {
			result = append(result, meta)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result
}
