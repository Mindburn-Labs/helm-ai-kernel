// quantum_posture: classical Ed25519/SHA-256 only; adds no post-quantum assurance.
package pack

import (
	"crypto/ed25519"
)

// PackBuilder assembles packs from components.
type PackBuilder struct {
	manifest PackManifest
	privKey  ed25519.PrivateKey
}
