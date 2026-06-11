package translog

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// SignedTreeHead is an exportable checkpoint of the transparency log at
// a given size, signed by the kernel keyring. The signature covers the
// JCS (RFC 8785) canonical serialization of {log_id, root_hash,
// timestamp, tree_size} so that any party reproduces identical signed
// bytes. Suitable for cross-publication (EvidencePacks, Console).
type SignedTreeHead struct {
	TreeSize  uint64 `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	Timestamp string `json:"timestamp"` // RFC 3339 UTC
	LogID     string `json:"log_id"`
	PublicKey string `json:"public_key,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// sthSigningPayload is the signed subset of the tree head. Field order
// is irrelevant: JCS sorts keys lexicographically.
type sthSigningPayload struct {
	LogID     string `json:"log_id"`
	RootHash  string `json:"root_hash"`
	Timestamp string `json:"timestamp"`
	TreeSize  uint64 `json:"tree_size"`
}

// SigningBytes returns the JCS canonical bytes covered by the signature.
func (s *SignedTreeHead) SigningBytes() ([]byte, error) {
	return crypto.CanonicalMarshal(sthSigningPayload{
		LogID:     s.LogID,
		RootHash:  s.RootHash,
		Timestamp: s.Timestamp,
		TreeSize:  s.TreeSize,
	})
}

// SignTreeHead produces a signed tree head for the given size and root
// using the kernel signer. now is the checkpoint time (UTC enforced).
func SignTreeHead(signer crypto.Signer, logID string, treeSize uint64, root [HashSize]byte, now time.Time) (*SignedTreeHead, error) {
	sth := &SignedTreeHead{
		TreeSize:  treeSize,
		RootHash:  hex.EncodeToString(root[:]),
		Timestamp: now.UTC().Format(time.RFC3339),
		LogID:     logID,
	}
	payload, err := sth.SigningBytes()
	if err != nil {
		return nil, fmt.Errorf("translog: canonicalize STH: %w", err)
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("translog: sign STH: %w", err)
	}
	sth.Signature = sig
	sth.PublicKey = signer.PublicKey()
	return sth, nil
}

// VerifyTreeHead verifies the STH signature against the given hex
// public key. Returns nil if the signature is valid.
func VerifyTreeHead(sth *SignedTreeHead, pubKeyHex string) error {
	if sth == nil {
		return fmt.Errorf("translog: nil STH")
	}
	if sth.Signature == "" {
		return fmt.Errorf("translog: STH is unsigned")
	}
	payload, err := sth.SigningBytes()
	if err != nil {
		return fmt.Errorf("translog: canonicalize STH: %w", err)
	}
	ok, err := crypto.Verify(pubKeyHex, sth.Signature, payload)
	if err != nil {
		return fmt.Errorf("translog: verify STH: %w", err)
	}
	if !ok {
		return fmt.Errorf("translog: STH signature invalid")
	}
	return nil
}

// LogIDFromPublicKey derives the log identifier as the hex SHA-256 of
// the raw public key bytes, mirroring the RFC 6962 log ID construction.
func LogIDFromPublicKey(pubKey []byte) string {
	sum := sha256.Sum256(pubKey)
	return hex.EncodeToString(sum[:])
}

// DetectEquivocation reports whether two signed tree heads constitute a
// split view: same log, same tree size, different roots. Signature
// validity must be checked separately via VerifyTreeHead.
func DetectEquivocation(a, b *SignedTreeHead) bool {
	if a == nil || b == nil {
		return false
	}
	return a.LogID == b.LogID && a.TreeSize == b.TreeSize && a.RootHash != b.RootHash
}
