package vcredentials

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// Verifier checks W3C Verifiable Credentials for signature validity,
// issuer trust, temporal validity, and capability presence.
type Verifier struct {
	trustedIssuers map[string]bool
	clock          func() time.Time
}

// NewVerifier creates a credential verifier that trusts the given issuer DIDs.
func NewVerifier(trustedIssuers []string) *Verifier {
	m := make(map[string]bool, len(trustedIssuers))
	for _, did := range trustedIssuers {
		m[did] = true
	}
	return &Verifier{
		trustedIssuers: m,
		clock:          time.Now,
	}
}

// NewVerifierWithClock creates a credential verifier with a custom clock.
// This is primarily useful for deterministic testing.
func NewVerifierWithClock(trustedIssuers []string, clock func() time.Time) *Verifier {
	v := NewVerifier(trustedIssuers)
	v.clock = clock
	return v
}

// Verify checks the credential's issuer trust, temporal validity, required
// contexts, and cryptographic signature.
//
// Checks performed (in order):
//  1. Proof is present
//  2. Issuer is in the trusted set
//  3. ValidFrom <= now
//  4. now <= ValidUntil (if ValidUntil is set)
//  5. Required @context values are present
//  6. Signature is valid over JCS-canonical credential bytes
func (v *Verifier) Verify(vc *VerifiableCredential, publicKey []byte) error {
	if vc.Proof == nil {
		return fmt.Errorf("credential has no proof")
	}

	// 1. Issuer trust
	if !v.trustedIssuers[vc.Issuer.ID] {
		return fmt.Errorf("untrusted issuer: %s", vc.Issuer.ID)
	}

	// 2. Temporal validity
	now := v.clock()
	if now.Before(vc.ValidFrom) {
		return fmt.Errorf("credential is not yet valid: validFrom %s is in the future", vc.ValidFrom.Format(time.RFC3339))
	}
	if !vc.ValidUntil.IsZero() && now.After(vc.ValidUntil) {
		return fmt.Errorf("credential has expired: validUntil %s", vc.ValidUntil.Format(time.RFC3339))
	}

	// 3. Required contexts
	if !hasContext(vc, ContextW3CCredentials) {
		return fmt.Errorf("missing required context: %s", ContextW3CCredentials)
	}
	if !hasContext(vc, ContextHELMAgent) {
		return fmt.Errorf("missing required context: %s", ContextHELMAgent)
	}

	// 4. Signature verification
	if err := v.verifySignature(vc, publicKey); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// CheckCapability checks whether the credential grants a specific action,
// optionally scoped to a resource. An empty resource matches any resource scope.
func (v *Verifier) CheckCapability(vc *VerifiableCredential, action, resource string) bool {
	for _, cap := range vc.CredentialSubject.Capabilities {
		if cap.Action != action {
			continue
		}
		if !cap.Verified {
			continue
		}
		// Empty resource in the claim means unrestricted; empty resource in the
		// query means "any resource is fine".
		if resource == "" || cap.Resource == "" || cap.Resource == resource {
			return true
		}
	}
	return false
}

// verifySignature reconstructs the canonical credential bytes (without proof)
// and verifies the signature against the provided public key.
func (v *Verifier) verifySignature(vc *VerifiableCredential, publicKey []byte) error {
	// Reconstruct the credential without proof for verification.
	signable := &VerifiableCredential{
		Context:           vc.Context,
		ID:                vc.ID,
		Type:              vc.Type,
		Issuer:            vc.Issuer,
		ValidFrom:         vc.ValidFrom,
		ValidUntil:        vc.ValidUntil,
		CredentialSubject: vc.CredentialSubject,
		// Proof is intentionally nil — matches the signing input.
	}

	canonical, err := canonicalize.JCS(signable)
	if err != nil {
		return fmt.Errorf("JCS canonicalization failed: %w", err)
	}

	pubKeyHex := fmt.Sprintf("%x", publicKey)
	valid, err := crypto.Verify(pubKeyHex, vc.Proof.ProofValue, canonical)
	if err != nil {
		return fmt.Errorf("verification error: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// hasContext checks whether the credential's @context array contains the given URI.
func hasContext(vc *VerifiableCredential, ctx string) bool {
	for _, c := range vc.Context {
		if c == ctx {
			return true
		}
	}
	return false
}
