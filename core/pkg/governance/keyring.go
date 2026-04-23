package governance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeyProvider defines the interface for cryptographic signing operations.
// This allows swapping the in-memory backend for an HSM, Vault, or Cloud KMS.
type KeyProvider interface {
	Sign(msg []byte) ([]byte, error)
	PublicKey() ed25519.PublicKey
}

// MemoryKeyProvider is an in-memory implementation for development/demo.
type MemoryKeyProvider struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func NewMemoryKeyProvider() (*MemoryKeyProvider, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &MemoryKeyProvider{pub: pub, priv: priv}, nil
}

func (m *MemoryKeyProvider) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(m.priv, msg), nil
}

func (m *MemoryKeyProvider) PublicKey() ed25519.PublicKey {
	return m.pub
}

// Keyring manages the Governance Keys using a Provider.
type Keyring struct {
	provider KeyProvider
}

func NewKeyring(p KeyProvider) *Keyring {
	if p == nil {
		// Fallback for seamless init? Or Enforce?
		// For safety, let's create a memory one if nil, but warn.
		p, _ = NewMemoryKeyProvider()
	}
	return &Keyring{provider: p}
}

func (k *Keyring) Sign(data interface{}) ([]byte, error) {
	msg, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return k.provider.Sign(msg)
}

func (k *Keyring) PublicKey() ed25519.PublicKey {
	return k.provider.PublicKey()
}

// DeriveForTenant derives a tenant-specific Keyring using HKDF-SHA256.
// The master key's private seed (first 32 bytes of Ed25519 private key)
// is used as IKM, and the tenantID is used as info.
// This ensures each tenant gets a unique, deterministic Ed25519 keypair.
func (k *Keyring) DeriveForTenant(tenantID string) (*Keyring, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenantID must not be empty")
	}

	// Extract seed from master key (first 32 bytes of Ed25519 private key)
	masterKey := k.provider.(*MemoryKeyProvider)
	if masterKey == nil {
		return nil, fmt.Errorf("tenant key derivation requires MemoryKeyProvider")
	}
	seed := masterKey.priv.Seed()

	// HKDF-SHA256: derive 32 bytes of tenant-specific key material
	hkdfReader := hkdf.New(sha256.New, seed, []byte("helm-tenant-kdf"), []byte(tenantID))
	tenantSeed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(hkdfReader, tenantSeed); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}

	// Derive Ed25519 keypair from seed
	priv := ed25519.NewKeyFromSeed(tenantSeed)
	pub := priv.Public().(ed25519.PublicKey)

	derived := &MemoryKeyProvider{pub: pub, priv: priv}
	return NewKeyring(derived), nil
}
