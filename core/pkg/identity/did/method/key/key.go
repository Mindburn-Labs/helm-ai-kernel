// Package key implements the did:key DID method driver.
//
// did:key DIDs are self-certifying: the public key bytes are encoded in the
// identifier itself, so resolution is deterministic and offline. This
// driver wraps the static encoder/decoder in core/pkg/identity/did/did.go
// and exposes it via the Method interface so the multi-method Resolver
// can dispatch to it uniformly.
//
// Reference: https://w3c-ccg.github.io/did-method-key/
package key

import (
	"context"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/did"
)

// Driver implements did.Method for the did:key method.
type Driver struct{}

// New returns a stateless did:key driver.
func New() *Driver { return &Driver{} }

// Name returns the method-specific name.
func (Driver) Name() string { return "key" }

// Resolve constructs the DID Document directly from the multibase-encoded
// public key embedded in the DID. No network access.
func (Driver) Resolve(_ context.Context, didURI string) (*did.ResolvedDocument, error) {
	d := did.DID(didURI)
	if err := d.Validate(); err != nil {
		return nil, fmt.Errorf("did:key: %w", err)
	}
	doc, err := d.Document()
	if err != nil {
		return nil, fmt.Errorf("did:key: building document: %w", err)
	}
	// Promote the minimal DIDDocument to a ResolvedDocument so the resolver
	// caches a single shape across all methods.
	return &did.ResolvedDocument{
		Context:            doc.Context,
		ID:                 doc.ID,
		VerificationMethod: doc.VerificationMethod,
		Authentication:     doc.Authentication,
		AssertionMethod:    doc.AssertionMethod,
	}, nil
}
