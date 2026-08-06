package crypto

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

// PermitSignatureV1 is the current EffectPermit signing preimage revision.
//
// Permits were carried unsigned until this revision: effects.EffectPermit had
// a Signature field that no issuance path ever populated, so any process able
// to hand a connector a permit could mint its own authorization. The whole
// point of a pre-action permit is that its scope and expiry cannot be rewritten
// by the party it authorizes, which requires a signature over exactly those
// fields.
const PermitSignatureV1 = "permit.v1"

// permitV1SigningEnvelope is the durable narrow signed view of a permit.
//
// Every field that decides what the permit authorizes is bound: the identity
// of the permit, what it was derived from (intent, verdict, policy), what it
// permits (effect type, connector, full scope, resource), when it stops being
// valid, how often it may be used, and who issued it. Scope is embedded whole
// rather than summarized — an unbound AllowedParams or DenyPatterns would let a
// holder widen the very boundary the permit exists to draw.
//
// Deliberate carve-outs, each with a reason:
//
//   - Signature: a signature cannot be an input to the value it authenticates.
//   - PlanHash: optional planning provenance that no enforcement path reads.
//     It is advisory metadata, and binding it would make permits from equivalent
//     decisions differ by an unenforced field. If any connector ever gates on
//     it, it moves into permit.v2 rather than being trusted unsigned.
//
// Nothing else is excluded. Unlike receipts, a permit is complete at issuance:
// there is no post-signing anchoring step, so no field legitimately changes
// after the signature exists.
//
// This envelope is a JCS object, not a delimiter-joined string. The receipt v4
// preimage joined fields with a bare ":" and escaped nothing, so a value
// containing a colon shifted field boundaries and two distinct receipts shared
// one signature (F-06). Every field here is separately keyed and every string
// is escaped, so no value can impersonate a boundary. Binding the full decision
// surface rather than a subset is the same lesson as F-05, where verdict,
// policy hash and key id stayed rewritable under a valid receipt signature.
type permitV1SigningEnvelope struct {
	SignatureVersion string            `json:"signature_version"`
	PermitID         string            `json:"permit_id"`
	IntentHash       string            `json:"intent_hash"`
	VerdictHash      string            `json:"verdict_hash"`
	PolicyHash       string            `json:"policy_hash"`
	EffectType       string            `json:"effect_type"`
	ConnectorID      string            `json:"connector_id"`
	Scope            permitV1ScopeView `json:"scope"`
	ResourceRef      string            `json:"resource_ref"`
	ExpiresAt        string            `json:"expires_at"`
	SingleUse        bool              `json:"single_use"`
	Nonce            string            `json:"nonce"`
	IssuedAt         string            `json:"issued_at"`
	IssuerID         string            `json:"issuer_id"`
	EvidenceBindings map[string]string `json:"evidence_bindings"`
}

// permitV1ScopeView mirrors effects.EffectScope with every field required, so
// an empty AllowedParams list and an absent one canonicalize identically and a
// permit cannot silently drop a deny pattern between signing and verification.
type permitV1ScopeView struct {
	AllowedAction string   `json:"allowed_action"`
	AllowedParams []string `json:"allowed_params"`
	DenyPatterns  []string `json:"deny_patterns"`
}

// CanonicalizePermitV1 returns the permit.v1 signing preimage.
//
// Timestamps are rendered RFC 3339 in UTC with nanosecond precision so a
// verifier reconstructs the same bytes regardless of the location attached to
// the time value it decoded.
func CanonicalizePermitV1(p *effects.EffectPermit) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("permit is nil")
	}
	scope := permitV1ScopeView{
		AllowedAction: p.Scope.AllowedAction,
		AllowedParams: nonNilStrings(p.Scope.AllowedParams),
		DenyPatterns:  nonNilStrings(p.Scope.DenyPatterns),
	}
	bindings := p.EvidenceBindings
	if bindings == nil {
		bindings = map[string]string{}
	}
	return canonicalize.JCS(permitV1SigningEnvelope{
		SignatureVersion: PermitSignatureV1,
		PermitID:         p.PermitID,
		IntentHash:       p.IntentHash,
		VerdictHash:      p.VerdictHash,
		PolicyHash:       p.PolicyHash,
		EffectType:       string(p.EffectType),
		ConnectorID:      p.ConnectorID,
		Scope:            scope,
		ResourceRef:      p.ResourceRef,
		ExpiresAt:        canonicalPermitTime(p.ExpiresAt),
		SingleUse:        p.SingleUse,
		Nonce:            p.Nonce,
		IssuedAt:         canonicalPermitTime(p.IssuedAt),
		IssuerID:         p.IssuerID,
		EvidenceBindings: bindings,
	})
}

// PermitSigningPayload stamps the permit with the current preimage version and
// returns the payload to sign. All signers must use this instead of calling a
// Canonicalize* function directly, so a new preimage revision is a one-line
// change here rather than a hunt across every issuance path.
func PermitSigningPayload(p *effects.EffectPermit) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("permit is nil")
	}
	p.SignatureVersion = PermitSignatureV1
	return CanonicalizePermitV1(p)
}

// PermitVerifyPayload reconstructs the signed payload according to the permit's
// declared preimage version. An empty version is rejected rather than assumed:
// no permit was ever issued signed before permit.v1, so an unversioned permit
// is either unsigned or forged, and both must fail closed. Unknown versions are
// rejected rather than guessed.
func PermitVerifyPayload(p *effects.EffectPermit) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("permit is nil")
	}
	switch p.SignatureVersion {
	case PermitSignatureV1:
		return CanonicalizePermitV1(p)
	case "":
		return nil, fmt.Errorf("permit declares no signature version")
	default:
		return nil, fmt.Errorf("unsupported permit signature version %q", p.SignatureVersion)
	}
}

// canonicalPermitTime renders a timestamp so signer and verifier agree on the
// bytes. A time carrying a +03:00 location and the same instant in UTC must not
// produce two different preimages, and a zero time must render deterministically
// rather than as whatever the local zone makes of it.
func canonicalPermitTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
