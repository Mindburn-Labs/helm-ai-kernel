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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ProvenanceRecord binds pack content to a publisher identity via Ed25519 signature.
type ProvenanceRecord struct {
	PackID         string    `json:"pack_id"`
	ContentHash    string    `json:"content_hash"`    // SHA-256 of pack content
	PublisherKeyID string    `json:"publisher_key_id"`
	PublisherSig   string    `json:"publisher_sig"`   // Ed25519 signature (hex-encoded)
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

// NewProvenanceVerifier creates a verifier with an empty trusted key set.
func NewProvenanceVerifier() *ProvenanceVerifier {
	return &ProvenanceVerifier{
		trustedKeys: make(map[string][]byte),
	}
}

// AddTrustedKey registers a publisher's Ed25519 public key as trusted.
func (v *ProvenanceVerifier) AddTrustedKey(keyID string, pubKey []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.trustedKeys[keyID] = pubKey
}

// RemoveTrustedKey removes a publisher's key from the trusted set (key rotation).
func (v *ProvenanceVerifier) RemoveTrustedKey(keyID string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.trustedKeys, keyID)
}

// IsTrusted reports whether the given key ID is in the trusted set.
func (v *ProvenanceVerifier) IsTrusted(keyID string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.trustedKeys[keyID]
	return ok
}

// Verify checks the provenance of a pack. Verification algorithm:
//  1. Check publisher_key_id is in trusted set
//  2. Compute SHA-256 of content and compare with record.ContentHash
//  3. Verify Ed25519 signature of ContentHash using publisher's public key
//
// Fail-closed: any check failure returns a result with Valid=false.
func (v *ProvenanceVerifier) Verify(record *ProvenanceRecord, content []byte) *ProvenanceResult {
	if record == nil {
		return &ProvenanceResult{
			Valid:  false,
			Reason: "provenance record is nil",
		}
	}

	result := &ProvenanceResult{
		PackID:         record.PackID,
		PublisherKeyID: record.PublisherKeyID,
	}

	// Step 1: Check publisher is trusted.
	v.mu.RLock()
	pubKey, trusted := v.trustedKeys[record.PublisherKeyID]
	v.mu.RUnlock()

	if !trusted {
		result.Valid = false
		result.Reason = fmt.Sprintf("publisher key %q is not in trusted set", record.PublisherKeyID)
		return result
	}

	// Step 2: Verify content hash.
	h := sha256.Sum256(content)
	computedHash := "sha256:" + hex.EncodeToString(h[:])

	if computedHash != record.ContentHash {
		result.Valid = false
		result.Reason = fmt.Sprintf("content hash mismatch: expected %s, computed %s", record.ContentHash, computedHash)
		return result
	}

	// Step 3: Verify Ed25519 signature of the content hash.
	sigBytes, err := hex.DecodeString(record.PublisherSig)
	if err != nil {
		result.Valid = false
		result.Reason = fmt.Sprintf("invalid signature encoding: %v", err)
		return result
	}

	if len(pubKey) != ed25519.PublicKeySize {
		result.Valid = false
		result.Reason = fmt.Sprintf("invalid public key size: got %d, want %d", len(pubKey), ed25519.PublicKeySize)
		return result
	}

	if !ed25519.Verify(pubKey, []byte(record.ContentHash), sigBytes) {
		result.Valid = false
		result.Reason = "Ed25519 signature verification failed"
		return result
	}

	result.Valid = true
	return result
}
