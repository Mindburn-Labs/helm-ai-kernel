// quantum_posture: classical Ed25519/SHA-256 only; adds no post-quantum assurance.

package governance

import (
	"crypto/ed25519"
)

// KeyProvider defines the interface for cryptographic signing operations.
// This allows swapping the in-memory backend for an HSM, Vault, or Cloud KMS.
type KeyProvider interface {
	Sign(msg []byte) ([]byte, error)
	PublicKey() ed25519.PublicKey
}

// MemoryKeyProvider is an in-memory implementation of KeyProvider.
type MemoryKeyProvider struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// Keyring manages the Governance Keys using a Provider.
type Keyring struct {
	provider KeyProvider
}
