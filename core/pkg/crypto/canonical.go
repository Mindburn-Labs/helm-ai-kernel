// quantum_posture: canonical signing preimages are algorithm-neutral; they do
// not upgrade the posture of the configured signer or external trust edges.
package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// CanonicalMarshal marshals v into canonical JSON format (RFC 8785).
// Key features:
// 1. Map keys sorted lexicographically (Go default)
// 2. No HTML escaping (SetEscapeHTML(false))
// 3. Compact representation (no whitespace)
// 4. Trailing newline is NOT added
func CanonicalMarshal(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "") // Compact

	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("canonical encoding failed: %w", err)
	}

	// json.Encoder.Encode adds a trailing newline, which we must remove for strict JCS compliance
	// if we want pure content addressing of the value data.
	ret := buf.Bytes()
	if len(ret) > 0 && ret[len(ret)-1] == '\n' {
		ret = ret[:len(ret)-1]
	}

	return ret, nil
}

// Signature components separators and prefixes
const (
	SigSeparator     = ":"
	SigPrefixEd25519 = "ed25519"
	SigPrefixMLDSA65 = "ml-dsa-65"
)

// CanonicalizeDecision creates a canonical string representation of a decision record for signing.
// V2: binds all security-relevant fields including PhenotypeHash, PolicyContentHash, EffectDigest (DRIFT-7 fix).
// Empty security-relevant hashes are permitted for backward compatibility but logged as a warning.
func CanonicalizeDecision(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s", id, SigSeparator, verdict, SigSeparator, reason, SigSeparator, phenotypeHash, SigSeparator, policyContentHash, SigSeparator, effectDigest)
}

// CanonicalizeDecisionStrict is like CanonicalizeDecision but returns an error if any
// security-relevant hash field is empty. Use this for new code paths where all fields
// are expected to be populated.
func CanonicalizeDecisionStrict(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("decision ID is required for canonicalization")
	}
	if verdict == "" {
		return "", fmt.Errorf("verdict is required for canonicalization")
	}
	return CanonicalizeDecision(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest), nil
}

// CanonicalizeIntent creates the historical compact intent preimage.
//
// Deprecated: retained only for fixture compatibility. It does not bind the
// authority window and must never be used to grant execution authority.
func CanonicalizeIntent(id, decisionID, allowedTool string, effectDigestHash ...string) string {
	if len(effectDigestHash) == 0 {
		return fmt.Sprintf("%s%s%s%s%s", id, SigSeparator, decisionID, SigSeparator, allowedTool)
	}
	return fmt.Sprintf("%s%s%s%s%s%s%s", id, SigSeparator, decisionID, SigSeparator, allowedTool, SigSeparator, effectDigestHash[0])
}

// CanonicalizeAuthorizedExecutionIntent returns the versioned signing
// preimage for an execution intent. V2 binds the authority window, signer and
// algorithm identity, taint, emergency authority, idempotency, and complete
// portable effect semantics. Legacy unversioned preimages are rejected because
// they do not bind expiry and therefore cannot grant execution authority.
func CanonicalizeAuthorizedExecutionIntent(intent *contracts.AuthorizedExecutionIntent) ([]byte, error) {
	if intent == nil {
		return nil, fmt.Errorf("execution intent is nil")
	}
	if intent.SignatureVersion != contracts.AuthorizedExecutionIntentSignatureV2 {
		return nil, fmt.Errorf("unsupported execution intent signature version %q", intent.SignatureVersion)
	}

	var effectBinding *contracts.EffectDigestBinding
	if intent.EffectBinding != nil {
		var err error
		effectBinding, err = contracts.NormalizeEffectDigestBinding(intent.EffectBinding)
		if err != nil {
			return nil, fmt.Errorf("normalize execution intent effect binding: %w", err)
		}
	}

	return canonicalize.JCS(authorizedExecutionIntentSigningEnvelope{
		SignatureVersion:             intent.SignatureVersion,
		ID:                           intent.ID,
		DecisionID:                   intent.DecisionID,
		EffectDigestHash:             intent.EffectDigestHash,
		EffectBinding:                effectBinding,
		IdempotencyKey:               intent.IdempotencyKey,
		IssuedAt:                     intent.IssuedAt,
		ExpiresAt:                    intent.ExpiresAt,
		Signer:                       intent.Signer,
		SignatureType:                intent.SignatureType,
		AllowedTool:                  intent.AllowedTool,
		Taint:                        contracts.NormalizeTaintLabels(intent.Taint),
		EmergencyActivationID:        intent.EmergencyActivationID,
		EmergencyDelegationSessionID: intent.EmergencyDelegationSessionID,
		EmergencyScopeHash:           intent.EmergencyScopeHash,
	})
}

// prepareAuthorizedExecutionIntent marks a newly signed intent as V2 before
// deriving the preimage. SignatureType is included so algorithm/key-selection
// metadata cannot be changed after signing.
func prepareAuthorizedExecutionIntent(intent *contracts.AuthorizedExecutionIntent, signatureType string) ([]byte, error) {
	if intent == nil {
		return nil, fmt.Errorf("execution intent is nil")
	}
	intent.SignatureVersion = contracts.AuthorizedExecutionIntentSignatureV2
	intent.SignatureType = signatureType
	return CanonicalizeAuthorizedExecutionIntent(intent)
}

//nolint:govet // field order mirrors the public authority contract.
type authorizedExecutionIntentSigningEnvelope struct {
	SignatureVersion             string                         `json:"signature_version"`
	ID                           string                         `json:"id"`
	DecisionID                   string                         `json:"decision_id"`
	EffectDigestHash             string                         `json:"effect_digest_hash"`
	EffectBinding                *contracts.EffectDigestBinding `json:"effect_binding,omitempty"`
	IdempotencyKey               string                         `json:"idempotency_key,omitempty"`
	IssuedAt                     time.Time                      `json:"issued_at"`
	ExpiresAt                    time.Time                      `json:"expires_at"`
	Signer                       string                         `json:"signer"`
	SignatureType                string                         `json:"signature_type"`
	AllowedTool                  string                         `json:"allowed_tool"`
	Taint                        []string                       `json:"taint,omitempty"`
	EmergencyActivationID        string                         `json:"emergency_activation_id,omitempty"`
	EmergencyDelegationSessionID string                         `json:"emergency_delegation_session_id,omitempty"`
	EmergencyScopeHash           string                         `json:"emergency_scope_hash,omitempty"`
}

// CanonicalizeReceipt creates a canonical string representation of a receipt for signing.
// V4: includes ArgsHash for PEP boundary binding.
func CanonicalizeReceipt(receiptID, decisionID, effectID, status, outputHash, prevHash string, lamportClock uint64, argsHash string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%d%s%s", receiptID, SigSeparator, decisionID, SigSeparator, effectID, SigSeparator, status, SigSeparator, outputHash, SigSeparator, prevHash, SigSeparator, lamportClock, SigSeparator, argsHash)
}

// --- HELM-303: V5 receipt / V2 decision signing preimages -----------------

// CanonicalizeReceiptV5 extends the V4 preimage with the receipt's
// governance-meaning fields: verdict, reason_code, policy_hash, session_id.
// With V4, those fields could be rewritten on a persisted receipt without
// invalidating its signature (the chain made it tamper-evident only once a
// successor existed; the chain tip was signature-silent). Field order is
// fixed and versioned; never reorder within a version.
func CanonicalizeReceiptV5(r *contracts.Receipt) string {
	v4 := CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s", v4,
		SigSeparator, contracts.ReceiptSignatureV5,
		SigSeparator, r.Verdict,
		SigSeparator, r.ReasonCode,
		SigSeparator, r.PolicyHash,
		SigSeparator, r.SessionID)
}

// ReceiptSigningPayload stamps the receipt with the current preimage version
// and returns the payload to sign. All signers must use this instead of
// calling a Canonicalize* function directly, so a new preimage revision is a
// one-line change here rather than an eight-site hunt.
func ReceiptSigningPayload(r *contracts.Receipt) string {
	r.SignatureVersion = contracts.ReceiptSignatureV5
	return CanonicalizeReceiptV5(r)
}

// ReceiptVerifyPayload reconstructs the signed payload according to the
// receipt's declared preimage version. Empty = legacy V4 (receipts signed
// before HELM-303 stay verifiable under the preimage they were signed over);
// unknown versions are rejected rather than guessed.
func ReceiptVerifyPayload(r *contracts.Receipt) (string, error) {
	switch r.SignatureVersion {
	case "":
		return CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash), nil
	case contracts.ReceiptSignatureV5:
		return CanonicalizeReceiptV5(r), nil
	default:
		return "", fmt.Errorf("unsupported receipt signature version %q", r.SignatureVersion)
	}
}

// CanonicalizeDecisionV2 signs the machine-readable ReasonCode in place of
// free-text Reason: the exported, keyed-on field is the attested one, and
// prose (which the telemetry contract prohibits from export) leaves the
// preimage entirely.
func CanonicalizeDecisionV2(id, verdict, reasonCode, phenotypeHash, policyContentHash, effectDigest string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%s",
		contracts.DecisionRecordSignatureV2, SigSeparator,
		id, SigSeparator, verdict, SigSeparator, reasonCode, SigSeparator,
		phenotypeHash, SigSeparator, policyContentHash, SigSeparator, effectDigest)
}

// DecisionSigningPayload stamps the record with the current preimage version
// and returns the payload to sign.
func DecisionSigningPayload(d *contracts.DecisionRecord) string {
	d.SignatureVersion = contracts.DecisionRecordSignatureV2
	return CanonicalizeDecisionV2(d.ID, d.Verdict, d.ReasonCode, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
}

// DecisionVerifyPayload reconstructs the signed payload per the record's
// declared preimage version; empty = legacy (free-text Reason).
func DecisionVerifyPayload(d *contracts.DecisionRecord) (string, error) {
	switch d.SignatureVersion {
	case "":
		return CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest), nil
	case contracts.DecisionRecordSignatureV2:
		return CanonicalizeDecisionV2(d.ID, d.Verdict, d.ReasonCode, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest), nil
	default:
		return "", fmt.Errorf("unsupported decision signature version %q", d.SignatureVersion)
	}
}
