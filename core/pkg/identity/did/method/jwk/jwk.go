// Package jwk implements the did:jwk DID method driver.
//
// did:jwk encodes a JSON Web Key directly in the DID identifier:
//   did:jwk:<base64url(JWK)>
//
// Resolution is offline: the driver decodes the base64url payload and
// constructs the DID Document from the JWK. Only Ed25519 keys (kty=OKP,
// crv=Ed25519) are supported in this initial implementation; additional
// curves can be added without breaking the public surface.
//
// Reference: https://github.com/quartzjer/did-jwk/blob/main/spec.md
package jwk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/did"
)

// Driver implements did.Method for the did:jwk method.
type Driver struct{}

// New returns a stateless did:jwk driver.
func New() *Driver { return &Driver{} }

// Name returns the method-specific name.
func (Driver) Name() string { return "jwk" }

// jwkPayload is the minimal JWK representation we accept.
type jwkPayload struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x"` // base64url, no padding
}

// Resolve decodes the JWK from the DID identifier and constructs a DID
// Document. No network access.
func (Driver) Resolve(_ context.Context, didURI string) (*did.ResolvedDocument, error) {
	method, identifier, err := did.ParseDID(didURI)
	if err != nil {
		return nil, err
	}
	if method != "jwk" {
		return nil, fmt.Errorf("did:jwk: wrong method %q", method)
	}

	jwkBytes, err := base64.RawURLEncoding.DecodeString(identifier)
	if err != nil {
		return nil, fmt.Errorf("did:jwk: decoding identifier: %w", err)
	}

	var jwk jwkPayload
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return nil, fmt.Errorf("did:jwk: parsing JWK: %w", err)
	}

	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("did:jwk: only OKP/Ed25519 supported (got kty=%q crv=%q)", jwk.Kty, jwk.Crv)
	}

	pub, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("did:jwk: decoding key bytes: %w", err)
	}

	mb, err := did.EncodeEd25519Multibase(pub)
	if err != nil {
		return nil, err
	}

	vmID := didURI + "#0"
	return &did.ResolvedDocument{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      didURI,
		VerificationMethod: []did.VerificationMethod{{
			ID:                 vmID,
			Type:               "Ed25519VerificationKey2020",
			Controller:         didURI,
			PublicKeyMultibase: mb,
		}},
		Authentication:  []string{vmID},
		AssertionMethod: []string{vmID},
	}, nil
}

// FromEd25519 builds a did:jwk identifier from a raw Ed25519 public key.
// Useful for tests and for users who want to mint a fresh JWK DID.
func FromEd25519(pub []byte) (string, error) {
	if len(pub) != 32 {
		return "", fmt.Errorf("did:jwk: ed25519 key must be 32 bytes, got %d", len(pub))
	}
	jwk := jwkPayload{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
	body, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	return "did:jwk:" + base64.RawURLEncoding.EncodeToString(body), nil
}
