// Package sdjwt implements SD-JWT (Selective Disclosure JWT) per RFC 9901.
//
// SD-JWT enables privacy-preserving attestations: an issuer creates a JWT
// with selectively disclosable claims. A holder can then present a subset
// of claims to a verifier without revealing the full payload.
//
// Per STANDARDS_AND_ARCHITECTURE §2 and EVIDENCE_MERKLE selective-disclosure:
// SD-JWT is the core primitive for privacy-preserving selective disclosure — "prove
// compliance facts without revealing sensitive internals."
package sdjwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Disclosure represents a single selectively disclosable claim.
// Format: base64url(json([salt, claim_name, claim_value]))
type Disclosure struct {
	Salt      string `json:"salt"`
	ClaimName string `json:"claim_name"`
	Value     any    `json:"value"`
	Encoded   string `json:"-"` // base64url-encoded disclosure string
}

// NewDisclosure creates a disclosure with a random salt.
func NewDisclosure(claimName string, value any) (*Disclosure, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("salt generation failed: %w", err)
	}
	d := &Disclosure{
		Salt:      base64.RawURLEncoding.EncodeToString(salt),
		ClaimName: claimName,
		Value:     value,
	}
	d.Encoded = d.encode()
	return d, nil
}

// NewDisclosureWithSalt creates a disclosure with a specified salt (for deterministic testing).
func NewDisclosureWithSalt(salt, claimName string, value any) *Disclosure {
	d := &Disclosure{
		Salt:      salt,
		ClaimName: claimName,
		Value:     value,
	}
	d.Encoded = d.encode()
	return d
}

// Hash returns the SHA-256 hash of the encoded disclosure (used as _sd value).
func (d *Disclosure) Hash() string {
	h := sha256.Sum256([]byte(d.Encoded))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// encode serializes the disclosure as base64url([salt, claim_name, value]).
func (d *Disclosure) encode() string {
	arr := []any{d.Salt, d.ClaimName, d.Value}
	data, _ := json.Marshal(arr)
	return base64.RawURLEncoding.EncodeToString(data)
}

// Issuer creates SD-JWTs with selectively disclosable claims.
type Issuer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	issuerID   string
}

// NewIssuer creates an Issuer with an Ed25519 key pair.
func NewIssuer(privateKey ed25519.PrivateKey, issuerID string) *Issuer {
	return &Issuer{
		privateKey: privateKey,
		publicKey:  privateKey.Public().(ed25519.PublicKey),
		issuerID:   issuerID,
	}
}

// SDJWTHeader is the JWT header for SD-JWT.
type SDJWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Issue creates an SD-JWT from claims with specified disclosable claim names.
// Non-disclosable claims appear directly in the JWT payload.
// Disclosable claims are replaced by their hashes in the _sd array.
//
// Returns: issuerJWT~disclosure1~disclosure2~...~
func (iss *Issuer) Issue(claims map[string]any, disclosableNames []string) (string, []*Disclosure, error) {
	disclosableSet := make(map[string]bool, len(disclosableNames))
	for _, n := range disclosableNames {
		disclosableSet[n] = true
	}

	// Build disclosures for disclosable claims.
	disclosures := make([]*Disclosure, 0, len(disclosableNames))
	sdHashes := make([]string, 0, len(disclosableNames))
	payload := make(map[string]any)

	for name, value := range claims {
		if disclosableSet[name] {
			d, err := NewDisclosure(name, value)
			if err != nil {
				return "", nil, fmt.Errorf("disclosure creation failed for %s: %w", name, err)
			}
			disclosures = append(disclosures, d)
			sdHashes = append(sdHashes, d.Hash())
		} else {
			payload[name] = value
		}
	}

	// Add _sd array and _sd_alg to payload.
	if len(sdHashes) > 0 {
		payload["_sd"] = sdHashes
		payload["_sd_alg"] = "sha-256"
	}
	payload["iss"] = iss.issuerID

	// Encode header.
	header := SDJWTHeader{Alg: "EdDSA", Typ: "sd+jwt"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", nil, fmt.Errorf("header encoding failed: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encode payload.
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", nil, fmt.Errorf("payload encoding failed: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Sign.
	signingInput := headerB64 + "." + payloadB64
	sig := ed25519.Sign(iss.privateKey, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	jwt := headerB64 + "." + payloadB64 + "." + sigB64

	// Build SD-JWT: jwt~disclosure1~disclosure2~...~
	var sb strings.Builder
	sb.WriteString(jwt)
	for _, d := range disclosures {
		sb.WriteString("~")
		sb.WriteString(d.Encoded)
	}
	sb.WriteString("~")

	return sb.String(), disclosures, nil
}

// Presentation creates a presentation from an SD-JWT with selected disclosures.
// The holder selects which claims to disclose to the verifier.
func Presentation(sdJWT string, selectedDisclosures []*Disclosure) string {
	// Extract the issuer JWT (everything before the first ~).
	parts := strings.SplitN(sdJWT, "~", 2)
	jwt := parts[0]

	var sb strings.Builder
	sb.WriteString(jwt)
	for _, d := range selectedDisclosures {
		sb.WriteString("~")
		sb.WriteString(d.Encoded)
	}
	sb.WriteString("~")
	return sb.String()
}

// Verifier validates SD-JWT presentations.
type Verifier struct {
	publicKey ed25519.PublicKey
}

// NewVerifier creates a Verifier with the issuer's public key.
func NewVerifier(publicKey ed25519.PublicKey) *Verifier {
	return &Verifier{publicKey: publicKey}
}

// VerifiedClaims holds the result of verification.
type VerifiedClaims struct {
	Claims    map[string]any // All verified claims (both direct and disclosed)
	Disclosed []string       // Names of claims that were selectively disclosed
	IssuerID  string         // Issuer identifier from the JWT
}

// Verify validates an SD-JWT presentation and returns the verified claims.
// It checks the JWT signature and matches disclosures against _sd hashes.
func (v *Verifier) Verify(presentation string) (*VerifiedClaims, error) {
	// Split on ~: first part is the JWT, rest are disclosures.
	parts := strings.Split(presentation, "~")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid SD-JWT format: missing ~ separator")
	}
	jwt := parts[0]

	// Parse JWT.
	jwtParts := strings.SplitN(jwt, ".", 3)
	if len(jwtParts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(jwtParts))
	}
	headerB64, payloadB64, sigB64 := jwtParts[0], jwtParts[1], jwtParts[2]

	// Verify signature.
	signingInput := headerB64 + "." + payloadB64
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("signature decode failed: %w", err)
	}
	if !ed25519.Verify(v.publicKey, []byte(signingInput), sig) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Decode payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("payload decode failed: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("payload parse failed: %w", err)
	}

	// Extract _sd hashes.
	sdHashesRaw, _ := payload["_sd"].([]any)
	sdHashes := make(map[string]bool, len(sdHashesRaw))
	for _, h := range sdHashesRaw {
		if s, ok := h.(string); ok {
			sdHashes[s] = true
		}
	}

	// Process disclosures.
	disclosed := make([]string, 0)
	for i := 1; i < len(parts); i++ {
		disclosureStr := parts[i]
		if disclosureStr == "" {
			continue // trailing ~
		}

		// Verify disclosure hash matches _sd.
		discHash := hashDisclosure(disclosureStr)
		if !sdHashes[discHash] {
			return nil, fmt.Errorf("disclosure hash mismatch: disclosure not found in _sd array")
		}

		// Decode disclosure: base64url → json → [salt, name, value].
		discJSON, err := base64.RawURLEncoding.DecodeString(disclosureStr)
		if err != nil {
			return nil, fmt.Errorf("disclosure decode failed: %w", err)
		}
		var arr []any
		if err := json.Unmarshal(discJSON, &arr); err != nil {
			return nil, fmt.Errorf("disclosure parse failed: %w", err)
		}
		if len(arr) != 3 {
			return nil, fmt.Errorf("disclosure must have 3 elements [salt, name, value], got %d", len(arr))
		}
		claimName, ok := arr[1].(string)
		if !ok {
			return nil, fmt.Errorf("disclosure claim name must be a string")
		}

		// Add disclosed claim to payload.
		payload[claimName] = arr[2]
		disclosed = append(disclosed, claimName)
	}

	// Remove SD-JWT internal fields.
	issuer, _ := payload["iss"].(string)
	delete(payload, "_sd")
	delete(payload, "_sd_alg")
	delete(payload, "iss")

	return &VerifiedClaims{
		Claims:    payload,
		Disclosed: disclosed,
		IssuerID:  issuer,
	}, nil
}

// hashDisclosure computes SHA-256 of a disclosure string for _sd matching.
func hashDisclosure(encoded string) string {
	h := sha256.Sum256([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// PublicKey returns the public key for the signer (implements subset of crypto.Signer).
func (iss *Issuer) PublicKey() crypto.PublicKey {
	return iss.publicKey
}
