// Package did implements W3C Decentralized Identifier (DID) support for HELM agents.
// Per arXiv 2511.02841, DIDs + Verifiable Credentials are the emerging standard
// for agent identity. HELM uses the did:key method for self-contained identifiers.
//
// DID format: did:key:<multibase-encoded-public-key>
// For Ed25519: did:key:z6Mk... (multicodec 0xed01 + raw public key, base58btc)
//
// Design invariants:
//   - DIDs are deterministically derived from public keys
//   - No registry needed (self-certifying)
//   - Thread-safe
//   - Compatible with existing HELM principal IDs
package did

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// didKeyPrefix is the method-specific prefix for all did:key identifiers.
	didKeyPrefix = "did:key:"

	// multicodecEd25519 is the two-byte multicodec prefix for Ed25519 public keys.
	// See https://github.com/multiformats/multicodec/blob/master/table.csv
	multicodecEd25519Byte0 = 0xed
	multicodecEd25519Byte1 = 0x01

	// ed25519PubKeyLen is the expected length of a raw Ed25519 public key.
	ed25519PubKeyLen = 32

	// w3cDIDContext is the standard W3C DID context URL.
	w3cDIDContext = "https://www.w3.org/ns/did/v1"

	// ed25519VerificationKey2020 is the verification method type for Ed25519.
	ed25519VerificationKey2020 = "Ed25519VerificationKey2020"
)

// DID is a W3C Decentralized Identifier string.
type DID string

// DIDDocument represents a minimal W3C DID Document.
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
}

// VerificationMethod is a public key entry within a DID Document.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// FromEd25519PublicKey creates a did:key from a raw Ed25519 public key.
// Format: did:key:z<base58btc(0xed01 + pubkey)>
func FromEd25519PublicKey(pubKey []byte) (DID, error) {
	if len(pubKey) != ed25519PubKeyLen {
		return "", fmt.Errorf("did: ed25519 public key must be %d bytes, got %d", ed25519PubKeyLen, len(pubKey))
	}

	// Prepend multicodec prefix (0xed, 0x01) to the raw public key.
	multicodecKey := make([]byte, 2+ed25519PubKeyLen)
	multicodecKey[0] = multicodecEd25519Byte0
	multicodecKey[1] = multicodecEd25519Byte1
	copy(multicodecKey[2:], pubKey)

	// Encode as base58btc with 'z' multibase prefix.
	encoded := "z" + encodeBase58(multicodecKey)
	return DID(didKeyPrefix + encoded), nil
}

// FromHexPublicKey creates a did:key from a hex-encoded Ed25519 public key.
func FromHexPublicKey(hexPubKey string) (DID, error) {
	pubKey, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return "", fmt.Errorf("did: invalid hex public key: %w", err)
	}
	return FromEd25519PublicKey(pubKey)
}

// Method returns "key" for did:key identifiers.
func (d DID) Method() string {
	s := string(d)
	if !strings.HasPrefix(s, "did:") {
		return ""
	}
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[1]
}

// PublicKeyBytes extracts the raw Ed25519 public key bytes from a did:key.
func (d DID) PublicKeyBytes() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}

	s := string(d)
	multibaseEncoded := s[len(didKeyPrefix):]

	// Must start with 'z' (base58btc multibase prefix).
	if multibaseEncoded[0] != 'z' {
		return nil, errors.New("did: unsupported multibase encoding (expected 'z' for base58btc)")
	}

	decoded, err := decodeBase58(multibaseEncoded[1:])
	if err != nil {
		return nil, fmt.Errorf("did: base58 decode failed: %w", err)
	}

	if len(decoded) < 2 {
		return nil, errors.New("did: decoded key too short for multicodec prefix")
	}

	if decoded[0] != multicodecEd25519Byte0 || decoded[1] != multicodecEd25519Byte1 {
		return nil, fmt.Errorf("did: unsupported multicodec prefix: 0x%02x%02x (expected 0xed01 for Ed25519)", decoded[0], decoded[1])
	}

	pubKey := decoded[2:]
	if len(pubKey) != ed25519PubKeyLen {
		return nil, fmt.Errorf("did: extracted key is %d bytes, expected %d", len(pubKey), ed25519PubKeyLen)
	}

	return pubKey, nil
}

// String returns the DID as a string.
func (d DID) String() string {
	return string(d)
}

// Validate checks that the DID is well-formed.
func (d DID) Validate() error {
	s := string(d)
	if s == "" {
		return errors.New("did: empty DID")
	}

	if !strings.HasPrefix(s, didKeyPrefix) {
		return fmt.Errorf("did: expected prefix %q, got %q", didKeyPrefix, s)
	}

	multibaseEncoded := s[len(didKeyPrefix):]
	if len(multibaseEncoded) == 0 {
		return errors.New("did: missing multibase-encoded key")
	}

	if multibaseEncoded[0] != 'z' {
		return fmt.Errorf("did: unsupported multibase prefix %q (expected 'z')", string(multibaseEncoded[0]))
	}

	if len(multibaseEncoded) < 2 {
		return errors.New("did: multibase-encoded key too short")
	}

	return nil
}

// Document generates a W3C DID Document for this DID.
func (d DID) Document() (*DIDDocument, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}

	s := string(d)
	multibaseEncoded := s[len(didKeyPrefix):]
	vmID := s + "#" + multibaseEncoded

	return &DIDDocument{
		Context: []string{w3cDIDContext},
		ID:      s,
		VerificationMethod: []VerificationMethod{
			{
				ID:                 vmID,
				Type:               ed25519VerificationKey2020,
				Controller:         s,
				PublicKeyMultibase: multibaseEncoded,
			},
		},
		Authentication:  []string{vmID},
		AssertionMethod: []string{vmID},
	}, nil
}

// ────────────────────────────────────────────────────────────────
// Base58btc codec (minimal, no external dependency)
// ────────────────────────────────────────────────────────────────

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// encodeBase58 encodes a byte slice to a base58btc string.
func encodeBase58(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Count leading zeros.
	leadingZeros := 0
	for _, b := range data {
		if b != 0 {
			break
		}
		leadingZeros++
	}

	// Allocate enough space in big-endian base58 representation.
	// log(256) / log(58) ≈ 1.366, so we need at most len(data)*138/100+1 digits.
	size := len(data)*138/100 + 1
	digits := make([]byte, size)

	// Process each byte.
	for _, b := range data {
		carry := int(b)
		for i := size - 1; i >= 0; i-- {
			carry += 256 * int(digits[i])
			digits[i] = byte(carry % 58)
			carry /= 58
		}
	}

	// Skip leading zeros in digits array.
	start := 0
	for start < size && digits[start] == 0 {
		start++
	}

	// Build result: leading '1's for zero bytes + encoded digits.
	result := make([]byte, leadingZeros+size-start)
	for i := 0; i < leadingZeros; i++ {
		result[i] = '1'
	}
	for i := start; i < size; i++ {
		result[leadingZeros+i-start] = base58Alphabet[digits[i]]
	}

	return string(result)
}

// decodeBase58 decodes a base58btc string to a byte slice.
func decodeBase58(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}

	// Build reverse lookup.
	alphabetMap := [256]int{}
	for i := range alphabetMap {
		alphabetMap[i] = -1
	}
	for i, c := range base58Alphabet {
		alphabetMap[c] = i
	}

	// Count leading '1's (which represent zero bytes).
	leadingOnes := 0
	for _, c := range s {
		if c != '1' {
			break
		}
		leadingOnes++
	}

	// Allocate enough space for the decoded bytes.
	// log(58) / log(256) ≈ 0.733, so we need at most len(s)*733/1000+1 bytes.
	size := len(s)*733/1000 + 1
	output := make([]byte, size)

	for _, c := range s {
		val := alphabetMap[c]
		if val == -1 {
			return nil, fmt.Errorf("did: invalid base58 character: %q", string(c))
		}

		carry := val
		for i := size - 1; i >= 0; i-- {
			carry += 58 * int(output[i])
			output[i] = byte(carry % 256)
			carry /= 256
		}
	}

	// Skip leading zeros in output array.
	start := 0
	for start < size && output[start] == 0 {
		start++
	}

	// Build result: leading zero bytes + decoded data.
	result := make([]byte, leadingOnes+size-start)
	// leadingOnes zero bytes are already zero-valued.
	copy(result[leadingOnes:], output[start:])

	return result, nil
}
