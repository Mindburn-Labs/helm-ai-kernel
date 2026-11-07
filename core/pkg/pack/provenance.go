// quantum_posture: classical Ed25519/SHA-256 only; adds no post-quantum assurance.
// provenance.go implements cryptographic provenance verification for HELM packs.
// Per arXiv 2604.08407, the LiteLLM supply chain attack (March 2026) exploited
// dependency confusion to inject malicious code into every deployment.
//
// HELM packs are signed by their publisher. Before loading any pack, the
// provenance verifier checks:
//  1. Publisher signature is valid (Ed25519)
//  2. Content hash matches declared hash
//  3. Publisher is in the trusted publisher set
//
// Design invariants:
//   - Fail-closed: invalid provenance = pack rejected
//   - No network calls (verification is offline)
//   - Supports key rotation via publisher key list
package pack

import (
	"sync"
	"time"
)

// ProvenanceRecord binds pack content to a publisher identity via Ed25519 signature.
type ProvenanceRecord struct {
	PackID         string    `json:"pack_id"`
	ContentHash    string    `json:"content_hash"` // SHA-256 of pack content
	PublisherKeyID string    `json:"publisher_key_id"`
	PublisherSig   string    `json:"publisher_sig"` // Ed25519 signature (hex-encoded)
	Timestamp      time.Time `json:"timestamp"`
	Version        string    `json:"version"`
}

// ProvenanceVerifier maintains a set of trusted publisher keys and verifies
// pack provenance records against them. All operations are offline.
type ProvenanceVerifier struct {
	mu          sync.RWMutex
	trustedKeys map[string][]byte // keyID -> Ed25519 public key bytes
}

// ProvenanceResult is the outcome of a provenance verification.
type ProvenanceResult struct {
	Valid          bool   `json:"valid"`
	PackID         string `json:"pack_id"`
	PublisherKeyID string `json:"publisher_key_id"`
	Reason         string `json:"reason,omitempty"` // Failure reason
}
