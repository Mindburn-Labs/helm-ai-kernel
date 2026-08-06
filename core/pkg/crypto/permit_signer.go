package crypto

import (
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

// Permit verification failures. Callers deny on any of them; they are
// distinguished so a receipt can record why authority was refused, not so a
// caller can decide that some of them are survivable.
var (
	// ErrPermitUnsigned is returned for a permit carrying no signature or no
	// signature version. Before permit.v1 every permit was in this state, which
	// is exactly why an unsigned permit must never execute.
	ErrPermitUnsigned = errors.New("permit is unsigned")
	// ErrPermitSignatureInvalid is returned when the signature does not verify
	// over the permit's own declared preimage — the tampering case.
	ErrPermitSignatureInvalid = errors.New("permit signature does not verify")
	// ErrPermitExpired is returned for a permit past ExpiresAt.
	ErrPermitExpired = errors.New("permit has expired")
	// ErrPermitReplayed is returned when a single-use permit's nonce was
	// already consumed.
	ErrPermitReplayed = errors.New("permit nonce was already consumed")
	// ErrPermitOutOfScope is returned when the requested action, parameters or
	// connector fall outside what the permit authorizes.
	ErrPermitOutOfScope = errors.New("action is outside the permit scope")
)

// SignPermit signs a permit in place with the active preimage revision.
//
// It is deliberately a function over the Signer interface rather than a new
// interface method: every existing Signer implementation (Ed25519, hybrid,
// ML-DSA, and test doubles) gains permit signing without a coordinated
// interface change, and the preimage stays selected in one place.
func SignPermit(signer Signer, p *effects.EffectPermit) error {
	if signer == nil {
		return fmt.Errorf("permit signer is nil")
	}
	payload, err := PermitSigningPayload(p)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return fmt.Errorf("sign permit: %w", err)
	}
	p.Signature = sig
	return nil
}

// VerifyPermitSignature checks a permit's signature against a public key.
//
// Every failure path returns an error; there is no boolean "unverified but
// acceptable" result, because the only safe reading of an unverifiable permit
// is denial.
func VerifyPermitSignature(publicKeyHex string, p *effects.EffectPermit) error {
	if p == nil {
		return fmt.Errorf("permit is nil")
	}
	if p.Signature == "" || p.SignatureVersion == "" {
		return ErrPermitUnsigned
	}
	payload, err := PermitVerifyPayload(p)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPermitSignatureInvalid, err)
	}
	ok, err := Verify(publicKeyHex, p.Signature, payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPermitSignatureInvalid, err)
	}
	if !ok {
		return ErrPermitSignatureInvalid
	}
	return nil
}

// PermitVerificationOptions carries the checks a consumer runs beyond the
// signature. A zero Now means "use the wall clock"; NonceStore may be nil only
// when the caller has already consumed the nonce itself.
type PermitVerificationOptions struct {
	PublicKeyHex string
	Now          time.Time
	NonceStore   effects.NonceStore
	ConnectorID  string
	Action       string
	Params       map[string]any
}

// VerifyPermitForUse is the fail-closed gate a connector runs before executing
// anything. It verifies the signature, then the permit's own constraints:
// expiry, single-use replay, connector binding, and action scope. Any failure —
// including an error reaching the nonce store — denies.
//
// It does not consume the nonce. Consumption is the caller's decision because
// only the caller knows whether it is about to execute; recording the nonce
// here would burn a permit on a verification-only probe.
func VerifyPermitForUse(p *effects.EffectPermit, opts PermitVerificationOptions) error {
	if p == nil {
		return fmt.Errorf("permit is nil")
	}
	if err := VerifyPermitSignature(opts.PublicKeyHex, p); err != nil {
		return err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if !p.ExpiresAt.IsZero() && !now.Before(p.ExpiresAt) {
		return fmt.Errorf("%w at %s", ErrPermitExpired, p.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if p.SingleUse && opts.NonceStore != nil && opts.NonceStore.HasNonce(p.Nonce) {
		return ErrPermitReplayed
	}
	if opts.ConnectorID != "" && p.ConnectorID != "" && opts.ConnectorID != p.ConnectorID {
		return fmt.Errorf("%w: permit binds connector %q, request targets %q", ErrPermitOutOfScope, p.ConnectorID, opts.ConnectorID)
	}
	if opts.Action != "" && p.Scope.AllowedAction != "" && opts.Action != p.Scope.AllowedAction {
		return fmt.Errorf("%w: permit allows %q, request is %q", ErrPermitOutOfScope, p.Scope.AllowedAction, opts.Action)
	}
	if len(opts.Params) > 0 && len(p.Scope.AllowedParams) > 0 {
		allowed := make(map[string]struct{}, len(p.Scope.AllowedParams))
		for _, name := range p.Scope.AllowedParams {
			allowed[name] = struct{}{}
		}
		for name := range opts.Params {
			if _, ok := allowed[name]; !ok {
				return fmt.Errorf("%w: parameter %q is not in the permitted set", ErrPermitOutOfScope, name)
			}
		}
	}
	return nil
}
