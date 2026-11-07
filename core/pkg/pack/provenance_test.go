// quantum_posture: classical Ed25519/SHA-256 only; adds no post-quantum assurance.
package pack_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pack"
)

func makeProvenanceFixture() (ed25519.PublicKey, ed25519.PrivateKey, []byte, *pack.ProvenanceRecord) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	content := []byte(`{"name":"test-pack","version":"1.0.0"}`)

	h := sha256.Sum256(content)
	contentHash := "sha256:" + hex.EncodeToString(h[:])
	sig := ed25519.Sign(priv, []byte(contentHash))

	record := &pack.ProvenanceRecord{
		PackID:         "pack-prov-1",
		ContentHash:    contentHash,
		PublisherKeyID: "publisher-1",
		PublisherSig:   hex.EncodeToString(sig),
		Timestamp:      time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC),
		Version:        "1.0.0",
	}

	return pub, priv, content, record
}
