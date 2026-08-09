// quantum_posture: permit verification here checks classical Ed25519
// signatures only; it provides and claims no hybrid or post-quantum
// protection.

package receiptverify

import (
	"errors"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// effectPermitSignatureV1 duplicates crypto.EffectPermitSignatureV1. Duplicated
// rather than imported for the same reason the receipt preimages are:
// core/pkg/crypto's import graph reaches the network and this package's entire
// claim is that it cannot. TestPermitCanonicalizationAgreesWithCrypto pins the
// two constants and the two envelopes together, so drift fails a build instead
// of surfacing as a counterparty reporting that a genuine permit does not
// verify.
const effectPermitSignatureV1 = "effect_permit.v1"

// PermitRecord mirrors the JSON wire shape of effects.EffectPermit.
//
// It is a local mirror, not an import: effects transitively reaches net,
// net/http and crypto/tls (208 packages), and one import would forfeit the
// offline property TestNoTransportPackageIsReachable proves. The mirror is
// pinned against the real struct in tests, which are allowed to import
// anything because test binaries ship to nobody.
type PermitRecord struct {
	PermitID    string      `json:"permit_id"`
	IntentHash  string      `json:"intent_hash"`
	VerdictHash string      `json:"verdict_hash"`
	PlanHash    string      `json:"plan_hash,omitempty"`
	PolicyHash  string      `json:"policy_hash,omitempty"`
	EffectType  string      `json:"effect_type"`
	ConnectorID string      `json:"connector_id"`
	Scope       PermitScope `json:"scope"`
	ResourceRef string      `json:"resource_ref"`
	ExpiresAt   time.Time   `json:"expires_at"`
	SingleUse   bool        `json:"single_use"`
	Nonce       string      `json:"nonce"`
	IssuedAt    time.Time   `json:"issued_at"`
	IssuerID    string      `json:"issuer_id"`
	// EvidenceBindings is the permit's evidence obligations: hashes of the
	// evidence connector policy requires before the effect may run. Since
	// kernel PR #803 the field has a wire home (field 16), and since #798 it is
	// inside the signed envelope — which is what makes it checkable here:
	// rewriting an obligation breaks the permit signature, and this verifier
	// catches that with no HELM service in the trust path.
	EvidenceBindings map[string]string `json:"evidence_bindings,omitempty"`
	Signature        string            `json:"signature,omitempty"`
}

// PermitScope mirrors effects.EffectScope.
type PermitScope struct {
	AllowedAction string   `json:"allowed_action"`
	AllowedParams []string `json:"allowed_params,omitempty"`
	DenyPatterns  []string `json:"deny_patterns,omitempty"`
}

// permitV1SigningEnvelope mirrors crypto.effectPermitV1SigningEnvelope field
// for field. No omitempty anywhere: an explicitly empty plan_hash is part of
// the signed schema and must not be confusable with a field a transport
// dropped.
type permitV1SigningEnvelope struct {
	SignatureVersion string                `json:"signature_version"`
	PermitID         string                `json:"permit_id"`
	IntentHash       string                `json:"intent_hash"`
	VerdictHash      string                `json:"verdict_hash"`
	PlanHash         string                `json:"plan_hash"`
	PolicyHash       string                `json:"policy_hash"`
	EffectType       string                `json:"effect_type"`
	ConnectorID      string                `json:"connector_id"`
	Scope            permitV1EnvelopeScope `json:"scope"`
	ResourceRef      string                `json:"resource_ref"`
	ExpiresAt        time.Time             `json:"expires_at"`
	SingleUse        bool                  `json:"single_use"`
	Nonce            string                `json:"nonce"`
	IssuedAt         time.Time             `json:"issued_at"`
	IssuerID         string                `json:"issuer_id"`
	EvidenceBindings map[string]string     `json:"evidence_bindings"`
}

type permitV1EnvelopeScope struct {
	AllowedAction string   `json:"allowed_action"`
	AllowedParams []string `json:"allowed_params"`
	DenyPatterns  []string `json:"deny_patterns"`
}

// canonicalizePermitV1 reproduces crypto.EffectPermitSigningPayload.
//
// Timestamps normalize to UTC so an instant that crossed a JSON hop carrying a
// numeric offset still produces the preimage it was signed over. Nil slices
// and maps normalize to empty so nil and empty canonicalize identically.
func canonicalizePermitV1(p *PermitRecord) ([]byte, error) {
	if p == nil {
		return nil, errors.New("permit is nil")
	}
	return canonicalize.JCS(permitV1SigningEnvelope{
		SignatureVersion: effectPermitSignatureV1,
		PermitID:         p.PermitID,
		IntentHash:       p.IntentHash,
		VerdictHash:      p.VerdictHash,
		PlanHash:         p.PlanHash,
		PolicyHash:       p.PolicyHash,
		EffectType:       p.EffectType,
		ConnectorID:      p.ConnectorID,
		Scope: permitV1EnvelopeScope{
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

// normalizeStrings returns a non-nil slice so nil and empty canonicalize alike.
// Mirrors crypto.normalizeStrings; pinned by the same agreement test.
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
