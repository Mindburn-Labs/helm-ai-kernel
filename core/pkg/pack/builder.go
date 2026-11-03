package pack

import (
	"crypto/ed25519"
)

// PackBuilder assembles packs from components.
type PackBuilder struct {
	manifest PackManifest
	privKey  ed25519.PrivateKey
}
