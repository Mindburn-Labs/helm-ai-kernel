package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Hasher provides deterministic hashing for HELM artifacts.
type Hasher interface {
	Hash(v interface{}) (string, error)
}

// CanonicalHasher implements RFC 8785 (JCS) inspired canonicalization.
// For MVP, we use standard library json.Marshal which sorts map keys by default.
type CanonicalHasher struct{}

func NewCanonicalHasher() *CanonicalHasher {
	return &CanonicalHasher{}
}

func (h *CanonicalHasher) Hash(v interface{}) (string, error) {
	// json.Marshal produces canonical JSON (keys sorted) for maps.
	// This is sufficient for MVP determinism if structs are stable.
	// Use CanonicalMarshal for JCS compliance (no HTML escaping, sorted keys)
	bytes, err := CanonicalMarshal(v)
	if err != nil {
		return "", fmt.Errorf("canonical serialization failed: %w", err)
	}

	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:]), nil
}
