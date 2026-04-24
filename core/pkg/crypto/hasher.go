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

// CanonicalHasher implements deterministic artifact hashing.
type CanonicalHasher struct{}

func NewCanonicalHasher() *CanonicalHasher {
	return &CanonicalHasher{}
}

func (h *CanonicalHasher) Hash(v interface{}) (string, error) {
	bytes, err := CanonicalMarshal(v)
	if err != nil {
		return "", fmt.Errorf("canonical serialization failed: %w", err)
	}

	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:]), nil
}
