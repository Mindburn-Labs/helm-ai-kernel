// document.go — shared DID Document types used across all DID methods.
//
// The original did.go ships a minimal DIDDocument tailored to did:key. This
// file extends the shape with the Tier-2 axis fields the multi-method
// resolver needs: service endpoints, controller, alsoKnownAs, and
// keyAgreement. The structures stay W3C-compliant per the v1.0
// recommendation (https://www.w3.org/TR/did-core/).
//
// No method-specific logic lives here; method drivers under did/method/ are
// expected to populate these fields when they resolve a document.

package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ServiceEndpoint represents a service entry in a DID Document.
type ServiceEndpoint struct {
	ID              string   `json:"id"`
	Type            string   `json:"type"`
	ServiceEndpoint string   `json:"serviceEndpoint"`
	Accept          []string `json:"accept,omitempty"`
}

// ResolvedDocument is the full W3C DID Document plus resolution metadata.
// Resolvers populate this; verifiers consume it.
type ResolvedDocument struct {
	Context              []string             `json:"@context"`
	ID                   string               `json:"id"`
	AlsoKnownAs          []string             `json:"alsoKnownAs,omitempty"`
	Controller           []string             `json:"controller,omitempty"`
	VerificationMethod   []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication       []string             `json:"authentication,omitempty"`
	AssertionMethod      []string             `json:"assertionMethod,omitempty"`
	KeyAgreement         []string             `json:"keyAgreement,omitempty"`
	CapabilityInvocation []string             `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation []string             `json:"capabilityDelegation,omitempty"`
	Service              []ServiceEndpoint    `json:"service,omitempty"`
}

// PrimaryAssertionKey returns the verification method bytes that the
// resolver believes should be used for assertion-purpose proofs (e.g.
// W3C VC issuance). It picks the first VerificationMethod referenced
// from AssertionMethod, falling back to Authentication, then to the
// first VerificationMethod entry.
//
// Returns the raw Ed25519 public key bytes when the method type is
// Ed25519VerificationKey2020 (or Ed25519VerificationKey2018, accepted as a
// historical alias). For other types callers must call VerificationMethod
// directly and parse the multibase value themselves.
func (d *ResolvedDocument) PrimaryAssertionKey() ([]byte, error) {
	if d == nil {
		return nil, errors.New("did: nil document")
	}

	// Resolve the first key reference from AssertionMethod, then Authentication.
	var ref string
	switch {
	case len(d.AssertionMethod) > 0:
		ref = d.AssertionMethod[0]
	case len(d.Authentication) > 0:
		ref = d.Authentication[0]
	case len(d.VerificationMethod) > 0:
		ref = d.VerificationMethod[0].ID
	default:
		return nil, errors.New("did: document has no verification method")
	}

	for _, vm := range d.VerificationMethod {
		if vm.ID != ref {
			continue
		}
		switch vm.Type {
		case ed25519VerificationKey2020, "Ed25519VerificationKey2018":
			return decodeEd25519Multibase(vm.PublicKeyMultibase)
		default:
			return nil, fmt.Errorf("did: verification method type %q not yet supported", vm.Type)
		}
	}
	return nil, fmt.Errorf("did: verification method %q not found in document", ref)
}

// decodeEd25519Multibase decodes a multibase-encoded Ed25519 public key
// (multicodec 0xed01 + 32 bytes). The encoded value must start with 'z'
// (base58btc per W3C did:key recommendation).
func decodeEd25519Multibase(multibase string) ([]byte, error) {
	if multibase == "" {
		return nil, errors.New("did: empty publicKeyMultibase")
	}
	if multibase[0] != 'z' {
		return nil, fmt.Errorf("did: unsupported multibase prefix %q (expected 'z')", string(multibase[0]))
	}
	decoded, err := decodeBase58(multibase[1:])
	if err != nil {
		return nil, fmt.Errorf("did: base58 decode failed: %w", err)
	}
	if len(decoded) != 2+ed25519PubKeyLen {
		return nil, fmt.Errorf("did: decoded key length %d != %d", len(decoded), 2+ed25519PubKeyLen)
	}
	if decoded[0] != multicodecEd25519Byte0 || decoded[1] != multicodecEd25519Byte1 {
		return nil, fmt.Errorf("did: unsupported multicodec prefix 0x%02x%02x", decoded[0], decoded[1])
	}
	return decoded[2:], nil
}

// EncodeEd25519Multibase encodes a 32-byte Ed25519 public key as a
// multibase-prefixed base58btc string suitable for publicKeyMultibase.
func EncodeEd25519Multibase(pub []byte) (string, error) {
	if len(pub) != ed25519PubKeyLen {
		return "", fmt.Errorf("did: ed25519 public key must be %d bytes, got %d", ed25519PubKeyLen, len(pub))
	}
	out := make([]byte, 2+ed25519PubKeyLen)
	out[0] = multicodecEd25519Byte0
	out[1] = multicodecEd25519Byte1
	copy(out[2:], pub)
	return "z" + encodeBase58(out), nil
}

// MarshalJSON ensures the @context is always emitted as a JSON array per
// the W3C DID Core spec.
func (d *ResolvedDocument) MarshalJSON() ([]byte, error) {
	type alias ResolvedDocument
	if len(d.Context) == 0 {
		d.Context = []string{w3cDIDContext}
	}
	return json.Marshal((*alias)(d))
}

// ParseDID extracts the method and method-specific identifier from a DID URI.
// Example: did:web:example.com -> ("web", "example.com").
func ParseDID(s string) (method, identifier string, err error) {
	if !strings.HasPrefix(s, "did:") {
		return "", "", fmt.Errorf("did: missing did: prefix in %q", s)
	}
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 3 || parts[1] == "" || parts[2] == "" {
		return "", "", fmt.Errorf("did: malformed DID %q", s)
	}
	return parts[1], parts[2], nil
}
