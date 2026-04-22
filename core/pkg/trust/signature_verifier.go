// Package trust implements the Pack Trust Fabric per Addendum 14.X.
// This file contains cryptographic signature verification for TUF.
package trust

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// SignatureVerifier verifies cryptographic signatures on TUF metadata.
type SignatureVerifier struct {
	// trustedKeys maps key IDs to public keys
	trustedKeys map[string]crypto.PublicKey
}

// NewSignatureVerifier creates a verifier with the given trusted keys.
func NewSignatureVerifier(keys map[string]crypto.PublicKey) *SignatureVerifier {
	return &SignatureVerifier{
		trustedKeys: keys,
	}
}

// VerifySignatures verifies that a signed role has valid signatures.
// Per Section 14.X.1: Threshold signature verification.
func (v *SignatureVerifier) VerifySignatures(role *SignedRole, threshold int) error {
	if role == nil {
		return fmt.Errorf("nil signed role")
	}

	if len(role.Signatures) == 0 {
		return fmt.Errorf("no signatures present")
	}

	if threshold <= 0 {
		threshold = 1
	}

	// Compute the canonical hash of the signed content
	signedBytes := role.Signed
	hash := sha256.Sum256(signedBytes)

	validSignatures := 0
	usedKeys := make(map[string]bool)

	for _, sig := range role.Signatures {
		// Skip duplicate key IDs
		if usedKeys[sig.KeyID] {
			continue
		}

		// Find the trusted key
		pubKey, exists := v.trustedKeys[sig.KeyID]
		if !exists {
			continue // Unknown key, skip
		}

		// Verify the signature
		sigBytes, err := decodeSignature(sig.Signature)
		if err != nil {
			continue // Invalid signature encoding
		}

		if err := verifySignature(pubKey, hash[:], sigBytes); err != nil {
			continue // Invalid signature
		}

		validSignatures++
		usedKeys[sig.KeyID] = true

		if validSignatures >= threshold {
			return nil // Threshold met
		}
	}

	return fmt.Errorf("insufficient valid signatures: got %d, need %d", validSignatures, threshold)
}

// VerifyRootSignatures verifies root metadata with self-signed keys.

// TUFKey represents a key in TUF metadata.
type TUFKey struct {
	KeyType string            `json:"keytype"`
	Scheme  string            `json:"scheme"`
	KeyVal  map[string]string `json:"keyval"`
}

// parseTUFKey converts a TUF key to a crypto.PublicKey.

// verifySignature verifies a signature with the given public key.
func verifySignature(pubKey crypto.PublicKey, hash, sig []byte) error {
	switch pk := pubKey.(type) {
	case ed25519.PublicKey:
		// Ed25519 signs the message directly, not the hash
		// For TUF, we verify against the hash
		if !ed25519.Verify(pk, hash, sig) {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
		return nil

	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, hash, sig); err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
		return nil

	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pk, hash, sig) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported key type: %T", pubKey)
	}
}

// decodeSignature decodes a base64 or hex encoded signature.
func decodeSignature(sig string) ([]byte, error) {
	// Try base64 first
	if data, err := base64.StdEncoding.DecodeString(sig); err == nil {
		return data, nil
	}

	// Fall back to hex
	if data, err := hex.DecodeString(sig); err == nil {
		return data, nil
	}

	return nil, fmt.Errorf("failed to decode signature")
}

// ComputeKeyID computes the TUF key ID from a public key.
