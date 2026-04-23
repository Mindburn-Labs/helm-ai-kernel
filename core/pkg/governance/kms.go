//go:build conformance

package governance

import (
	"crypto/ed25519"
	"fmt"
	"sync"
)

// ── KMS Provider Interface ────────────────────────────────────

// KMSProvider extends KeyProvider with tenant key derivation and
// envelope encryption support.
type KMSProvider interface {
	KeyProvider
	// DeriveKey derives a tenant-specific KeyProvider from the master key.
	DeriveKey(tenantID string) (KeyProvider, error)
}

// ── Envelope Encryption ───────────────────────────────────────

// WrappedKey represents an envelope-encrypted data encryption key (DEK).
type WrappedKey struct {
	TenantID   string `json:"tenant_id"`
	DEK        []byte `json:"dek"` // Encrypted DEK
	KeyVersion int    `json:"key_version"`
	WrappedBy  string `json:"wrapped_by"` // KMS key reference
}

// ── Local KMS (In-Memory) ─────────────────────────────────────

// LocalKMS is an in-process KMS implementation suitable for single-node deployments.
// For multi-node or HSM-backed deployments, implement KMSProvider backed by
// AWS KMS, Azure Key Vault, or HashiCorp Vault.
type LocalKMS struct {
	mu      sync.RWMutex
	master  *MemoryKeyProvider
	derived map[string]*MemoryKeyProvider
}

// NewLocalKMS creates a new in-memory KMS backed by a fresh master key.
func NewLocalKMS() (*LocalKMS, error) {
	master, err := NewMemoryKeyProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}
	return &LocalKMS{
		master:  master,
		derived: make(map[string]*MemoryKeyProvider),
	}, nil
}

// Sign signs the given message using the master key.
func (k *LocalKMS) Sign(msg []byte) ([]byte, error) {
	return k.master.Sign(msg)
}

// PublicKey returns the master public key.
func (k *LocalKMS) PublicKey() ed25519.PublicKey {
	return k.master.PublicKey()
}

// DeriveKey derives a tenant-specific KeyProvider using the Keyring's HKDF derivation.
func (k *LocalKMS) DeriveKey(tenantID string) (KeyProvider, error) {
	k.mu.RLock()
	if existing, ok := k.derived[tenantID]; ok {
		k.mu.RUnlock()
		return existing, nil
	}
	k.mu.RUnlock()

	// Derive via Keyring HKDF
	masterKeyring := NewKeyring(k.master)
	tenantKeyring, err := masterKeyring.DeriveForTenant(tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant key derivation failed: %w", err)
	}

	// Cache the derived provider
	derived := tenantKeyring.provider.(*MemoryKeyProvider)
	k.mu.Lock()
	k.derived[tenantID] = derived
	k.mu.Unlock()

	return derived, nil
}

// TenantCount returns the number of derived tenant keys (for testing).
func (k *LocalKMS) TenantCount() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.derived)
}
