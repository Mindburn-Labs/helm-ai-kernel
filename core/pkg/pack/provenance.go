// quantum_posture: pack provenance records carry classical Ed25519 signatures and SHA-256 digests.
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

// ProvenanceVerifier retains the trusted publisher keys of the former pack verifier.
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
