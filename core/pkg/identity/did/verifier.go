// verifier.go — DID-aware Verifiable Credential verifier.
//
// The base vcredentials.Verifier expects callers to supply the issuer's
// public-key bytes out of band. With a multi-method DID resolver the
// kernel can lift that constraint: given an issuer DID, the verifier
// resolves the DID Document, extracts the assertionMethod public key,
// and hands it to the underlying VC verifier.
//
// This file defines the Verifier (and a no-trust-list mode for offline
// flows where the caller has already pinned the issuer DID).

package did

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/vcredentials"
)

// Verifier is a DID-aware Verifiable Credential verifier. It composes a
// resolver with the existing vcredentials.Verifier so VCs issued by any
// resolvable DID can be verified offline once the document is cached.
type Verifier struct {
	resolver *Resolver
	clock    func() time.Time
	trusted  map[string]bool
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithTrustedIssuers restricts verification to a fixed allowlist of issuer
// DIDs. When the allowlist is empty the verifier accepts any resolvable
// issuer (offline-trust mode).
func WithTrustedIssuers(issuers []string) VerifierOption {
	return func(v *Verifier) {
		v.trusted = make(map[string]bool, len(issuers))
		for _, did := range issuers {
			v.trusted[did] = true
		}
	}
}

// WithVerifierClock injects a deterministic clock for testing.
func WithVerifierClock(clock func() time.Time) VerifierOption {
	return func(v *Verifier) { v.clock = clock }
}

// NewVerifier wraps a resolver with VC verification.
func NewVerifier(resolver *Resolver, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		resolver: resolver,
		clock:    time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// VerifyVC resolves the issuer's DID, extracts the assertion-method key,
// and validates the credential's signature, temporal window, and required
// contexts.
func (v *Verifier) VerifyVC(ctx context.Context, vc *vcredentials.VerifiableCredential) error {
	if vc == nil {
		return errors.New("did: nil credential")
	}
	if v.resolver == nil {
		return errors.New("did: verifier has no resolver")
	}

	issuerDID := vc.Issuer.ID
	if issuerDID == "" {
		return errors.New("did: credential issuer ID is empty")
	}

	if len(v.trusted) > 0 && !v.trusted[issuerDID] {
		return fmt.Errorf("did: untrusted issuer %q", issuerDID)
	}

	doc, err := v.resolver.Resolve(ctx, issuerDID)
	if err != nil {
		return fmt.Errorf("did: resolving issuer %s: %w", issuerDID, err)
	}

	pub, err := doc.PrimaryAssertionKey()
	if err != nil {
		return fmt.Errorf("did: extracting assertion key for %s: %w", issuerDID, err)
	}

	// We trust the issuer transitively via the DID Document, so the inner
	// vcredentials.Verifier is configured to accept that issuer DID.
	inner := vcredentials.NewVerifierWithClock([]string{issuerDID}, v.clock)
	if err := inner.Verify(vc, pub); err != nil {
		return fmt.Errorf("did: %w", err)
	}
	return nil
}
