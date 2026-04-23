package pack

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PackBuilder assembles packs from components.
type PackBuilder struct {
	manifest PackManifest
	privKey  ed25519.PrivateKey
}

// NewPackBuilder creates a new builder.
func NewPackBuilder(manifest PackManifest) *PackBuilder {
	return &PackBuilder{
		manifest: manifest,
	}
}

// WithSigningKey sets the private key for signing the pack.
func (b *PackBuilder) WithSigningKey(privKey ed25519.PrivateKey) *PackBuilder {
	b.privKey = privKey
	return b
}

// Build assembles the pack and signs it.
func (b *PackBuilder) Build() (*Pack, error) {
	if b.manifest.Name == "" || b.manifest.Version == "" {
		return nil, fmt.Errorf("manifest missing name or version")
	}

	pack := &Pack{
		PackID:    uuid.New().String(),
		Manifest:  b.manifest,
		CreatedAt: time.Now().UTC(),
	}

	// Compute Content Hash
	pack.ContentHash = ComputePackHash(pack)

	// Sign if key available
	if b.privKey != nil {
		sig := ed25519.Sign(b.privKey, []byte(pack.ContentHash))
		pack.Signature = hex.EncodeToString(sig)
	}

	return pack, nil
}

// ValidateManifest checks if the manifest itself is valid (e.g. valid capabilities).
func ValidateManifest(m PackManifest) error {
	for _, cap := range m.Capabilities {
		if cap == "" {
			return fmt.Errorf("capability cannot be empty")
		}
	}
	return nil
}
