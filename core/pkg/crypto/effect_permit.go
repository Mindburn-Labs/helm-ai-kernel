// quantum_posture: the permit preimage is algorithm-neutral; SignPermit
// inherits whatever posture the injected signer has (Ed25519 today).
package crypto

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

// EffectPermitSignatureV1 identifies the permit signing preimage below. It is
// carried inside the signed envelope rather than on effects.EffectPermit: the
// permit wire type has no version field, and a constant in the preimage still
// gives the domain separation a version tag exists for — a v1 payload can never
// be replayed as a future v2 payload.
const EffectPermitSignatureV1 = "effect_permit.v1"

// effectPermitV1SigningEnvelope is the complete signed view of an EffectPermit.
//
// COVERED FIELDS — every field of effects.EffectPermit except Signature itself,
// which cannot be an input to the value it authenticates:
//
//	permit_id, intent_hash, verdict_hash, plan_hash, policy_hash, effect_type,
//	connector_id, scope (allowed_action, allowed_params, deny_patterns),
//	resource_ref, expires_at, single_use, nonce, issued_at, issuer_id,
//	evidence_bindings
//
// NOT COVERED: signature. Nothing else is excluded. If a field is added to
// EffectPermit it must be added here in the same change, under a new version
// constant — a partially covering signature is the defect this envelope exists
// to prevent (see the F-05 note in ReceiptPreimageV5 for what that costs).
//
// No field uses omitempty. An explicitly empty plan_hash is part of the signed
// schema and must not be confusable with a field a transport dropped.
//
// TRANSPORT SCOPE — v1 signatures are in-process only. evidence_bindings is a
// covered field of the Go type but has no counterpart in
// protocols/proto/helm/effects/v1/effects.proto, so any proto or
// schema-validated JSON hop drops it and verification fails on the far side.
// Before a permit is signed on one process and verified on another, either add
// evidence_bindings to the wire contract (a backward-compatible field add) or
// cut a v2 preimage that excludes it. There is no Go↔proto permit conversion in
// the kernel today, so nothing is broken by this — it is a precondition, not a
// defect.
type effectPermitV1SigningEnvelope struct {
	SignatureVersion string              `json:"signature_version"`
	PermitID         string              `json:"permit_id"`
	IntentHash       string              `json:"intent_hash"`
	VerdictHash      string              `json:"verdict_hash"`
	PlanHash         string              `json:"plan_hash"`
	PolicyHash       string              `json:"policy_hash"`
	EffectType       string              `json:"effect_type"`
	ConnectorID      string              `json:"connector_id"`
	Scope            effectPermitScopeV1 `json:"scope"`
	ResourceRef      string              `json:"resource_ref"`
	ExpiresAt        time.Time           `json:"expires_at"`
	SingleUse        bool                `json:"single_use"`
	Nonce            string              `json:"nonce"`
	IssuedAt         time.Time           `json:"issued_at"`
	IssuerID         string              `json:"issuer_id"`
	EvidenceBindings map[string]string   `json:"evidence_bindings"`
}

// effectPermitScopeV1 mirrors effects.EffectScope without omitempty, so a nil
// list and an empty list canonicalize identically instead of producing `null`
// against `[]`.
type effectPermitScopeV1 struct {
	AllowedAction string   `json:"allowed_action"`
	AllowedParams []string `json:"allowed_params"`
	DenyPatterns  []string `json:"deny_patterns"`
}

// PermitSigner is the minimal signing capability EffectPermit signing needs.
// It is deliberately narrower than Signer: adding SignPermit to Signer would
// break every existing implementation (external, hybrid, ML-DSA, test doubles)
// for no gain, since none of them need permit-specific behaviour.
type PermitSigner interface {
	Sign(data []byte) (string, error)
}

// EffectPermitSigningPayload returns the canonical v1 preimage for a permit.
//
// Timestamps are normalized to UTC so an instant that survives a JSON round
// trip carrying a numeric offset still produces the preimage it was signed
// over. Slice order inside the scope is significant: a reordered allowed_params
// list is a different preimage and will not verify.
func EffectPermitSigningPayload(p *effects.EffectPermit) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("effect permit is nil")
	}
	return canonicalize.JCS(effectPermitV1SigningEnvelope{
		SignatureVersion: EffectPermitSignatureV1,
		PermitID:         p.PermitID,
		IntentHash:       p.IntentHash,
		VerdictHash:      p.VerdictHash,
		PlanHash:         p.PlanHash,
		PolicyHash:       p.PolicyHash,
		EffectType:       string(p.EffectType),
		ConnectorID:      p.ConnectorID,
		Scope: effectPermitScopeV1{
			AllowedAction: p.Scope.AllowedAction,
			AllowedParams: normalizeStrings(p.Scope.AllowedParams),
			DenyPatterns:  normalizeStrings(p.Scope.DenyPatterns),
		},
		ResourceRef:      p.ResourceRef,
		ExpiresAt:        p.ExpiresAt.UTC(),
		SingleUse:        p.SingleUse,
		Nonce:            p.Nonce,
		IssuedAt:         p.IssuedAt.UTC(),
		IssuerID:         p.IssuerID,
		EvidenceBindings: normalizeStringMap(p.EvidenceBindings),
	})
}

// SignPermit signs p over the v1 preimage and writes the hex signature into
// p.Signature. It is the only supported way to populate that field.
func SignPermit(signer PermitSigner, p *effects.EffectPermit) error {
	if signer == nil {
		return fmt.Errorf("permit signer is nil")
	}
	if p == nil {
		return fmt.Errorf("effect permit is nil")
	}
	payload, err := EffectPermitSigningPayload(p)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return fmt.Errorf("sign effect permit: %w", err)
	}
	p.Signature = sig
	return nil
}

// VerifyPermit checks p.Signature against pubKeyHex over the v1 preimage.
//
// An absent signature is an error, not a false: a caller that cannot tell
// "unsigned" from "forged" cannot fail closed on the right one.
func VerifyPermit(pubKeyHex string, p *effects.EffectPermit) (bool, error) {
	if p == nil {
		return false, fmt.Errorf("effect permit is nil")
	}
	if p.Signature == "" {
		return false, fmt.Errorf("effect permit is unsigned")
	}
	payload, err := EffectPermitSigningPayload(p)
	if err != nil {
		return false, err
	}
	return Verify(pubKeyHex, p.Signature, payload)
}

// normalizeStrings returns a non-nil slice so nil and empty canonicalize alike.
func normalizeStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// normalizeStringMap returns a non-nil map so nil and empty canonicalize alike.
func normalizeStringMap(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	return in
}
