package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

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

	// DecisionSignatureSchemaV2 binds the evaluated request and the security
	// relevant decision metadata in a canonical JSON payload. The empty schema
	// remains reserved for legacy v1 signatures so already-issued decisions can
	// still be verified without a silent downgrade.
	DecisionSignatureSchemaV2 = "helm.decision.signature.v2"
)

// CanonicalizeDecision creates the legacy v1 string payload for decision
// signatures. New request-bound decisions use CanonicalizeDecisionV2; this
// helper remains only so historic signatures can be verified.
func CanonicalizeDecision(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s", id, SigSeparator, verdict, SigSeparator, reason, SigSeparator, phenotypeHash, SigSeparator, policyContentHash, SigSeparator, effectDigest)
}

// CanonicalizeDecisionStrict is the validating counterpart to the retained v1
// helper. New request-bound code paths must use the v2 decision schema instead.
func CanonicalizeDecisionStrict(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("decision ID is required for canonicalization")
	}
	if verdict == "" {
		return "", fmt.Errorf("verdict is required for canonicalization")
	}
	return CanonicalizeDecision(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest), nil
}

// decisionSignatureV2 is deliberately an explicit, map-free signing envelope.
// InputContext is excluded: it is caller-supplied explanatory data, while the
// governed effect is bound by EffectDigest. Adding another security-relevant
// field requires a new schema version rather than changing this preimage.
type decisionSignatureV2 struct {
	SignatureSchema        string                          `json:"signature_schema"`
	ID                     string                          `json:"id"`
	ProposalID             string                          `json:"proposal_id"`
	StepID                 string                          `json:"step_id"`
	PhenotypeHash          string                          `json:"phenotype_hash"`
	PolicyVersion          string                          `json:"policy_version"`
	SubjectID              string                          `json:"subject_id"`
	Action                 string                          `json:"action"`
	Resource               string                          `json:"resource"`
	EffectDigest           string                          `json:"effect_digest"`
	PolicyBackend          string                          `json:"policy_backend"`
	PolicyContentHash      string                          `json:"policy_content_hash"`
	PolicyEpoch            string                          `json:"policy_epoch"`
	PolicyDecisionHash     string                          `json:"policy_decision_hash"`
	StateCursor            string                          `json:"state_cursor"`
	Snapshot               string                          `json:"snapshot"`
	EnvFingerprint         string                          `json:"env_fingerprint"`
	Verdict                string                          `json:"verdict"`
	Reason                 string                          `json:"reason"`
	ReasonCode             string                          `json:"reason_code"`
	TrajectoryRiskScore    float64                         `json:"trajectory_risk_score"`
	SessionCentroidHash    string                          `json:"session_centroid_hash"`
	RiskAccumulationWindow int                             `json:"risk_accumulation_window"`
	RequirementSetHash     string                          `json:"requirement_set_hash"`
	SignatureType          string                          `json:"signature_type"`
	Timestamp              time.Time                       `json:"timestamp"`
	Intervention           *contracts.InterventionMetadata `json:"intervention"`
}

func hasRequestBinding(d *contracts.DecisionRecord) bool {
	return d != nil && d.SubjectID != "" && d.Action != "" && d.Resource != ""
}

// PrepareDecisionForSigning assigns a signer-owned signature type and opts a
// complete request-bound decision into the v2 schema. Incomplete decisions
// remain legacy v1 so callers cannot accidentally claim request binding.
func PrepareDecisionForSigning(d *contracts.DecisionRecord, signatureType string) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("decision is required for signing")
	}
	if signatureType == "" {
		return nil, fmt.Errorf("decision signature type is required")
	}
	if d.SignatureSchema == "" && hasRequestBinding(d) {
		d.SignatureSchema = DecisionSignatureSchemaV2
	}
	if d.SignatureSchema == DecisionSignatureSchemaV2 && !hasRequestBinding(d) {
		return nil, fmt.Errorf("decision signature schema %q requires subject_id, action, and resource", DecisionSignatureSchemaV2)
	}
	d.SignatureType = signatureType
	return CanonicalDecisionPayload(d)
}

// CanonicalDecisionPayload returns the exact preimage indicated by the
// persisted decision schema. An empty schema is the legacy v1 format; unknown
// schemas fail closed instead of being treated as legacy.
func CanonicalDecisionPayload(d *contracts.DecisionRecord) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("decision is required for canonicalization")
	}

	switch d.SignatureSchema {
	case "":
		return []byte(CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)), nil
	case DecisionSignatureSchemaV2:
		return CanonicalizeDecisionV2(d)
	default:
		return nil, fmt.Errorf("unsupported decision signature schema %q", d.SignatureSchema)
	}
}

// CanonicalizeDecisionV2 returns the versioned, unambiguous signing payload
// for a request-bound decision. It includes the request identity/effect tuple,
// policy/effect bindings, and the signer-selected signature type.
func CanonicalizeDecisionV2(d *contracts.DecisionRecord) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("decision is required for canonicalization")
	}
	if d.SignatureSchema != DecisionSignatureSchemaV2 {
		return nil, fmt.Errorf("decision signature schema must be %q, got %q", DecisionSignatureSchemaV2, d.SignatureSchema)
	}
	if d.ID == "" {
		return nil, fmt.Errorf("decision ID is required for canonicalization")
	}
	if !hasRequestBinding(d) {
		return nil, fmt.Errorf("decision signature schema %q requires subject_id, action, and resource", DecisionSignatureSchemaV2)
	}
	if d.SignatureType == "" {
		return nil, fmt.Errorf("decision signature type is required for canonicalization")
	}

	return CanonicalMarshal(decisionSignatureV2{
		SignatureSchema:        d.SignatureSchema,
		ID:                     d.ID,
		ProposalID:             d.ProposalID,
		StepID:                 d.StepID,
		PhenotypeHash:          d.PhenotypeHash,
		PolicyVersion:          d.PolicyVersion,
		SubjectID:              d.SubjectID,
		Action:                 d.Action,
		Resource:               d.Resource,
		EffectDigest:           d.EffectDigest,
		PolicyBackend:          d.PolicyBackend,
		PolicyContentHash:      d.PolicyContentHash,
		PolicyEpoch:            d.PolicyEpoch,
		PolicyDecisionHash:     d.PolicyDecisionHash,
		StateCursor:            d.StateCursor,
		Snapshot:               d.Snapshot,
		EnvFingerprint:         d.EnvFingerprint,
		Verdict:                d.Verdict,
		Reason:                 d.Reason,
		ReasonCode:             d.ReasonCode,
		TrajectoryRiskScore:    d.TrajectoryRiskScore,
		SessionCentroidHash:    d.SessionCentroidHash,
		RiskAccumulationWindow: d.RiskAccumulationWindow,
		RequirementSetHash:     d.RequirementSetHash,
		SignatureType:          d.SignatureType,
		Timestamp:              d.Timestamp,
		Intervention:           d.Intervention,
	})
}

// CanonicalizeIntent creates a canonical string representation of an intent for signing.
// New signing paths pass effectDigestHash to bind the intent to the exact
// effect approved by the decision; the variadic form preserves old callers
// that only need to inspect the legacy component ordering.
func CanonicalizeIntent(id, decisionID, allowedTool string, effectDigestHash ...string) string {
	if len(effectDigestHash) == 0 {
		return fmt.Sprintf("%s%s%s%s%s", id, SigSeparator, decisionID, SigSeparator, allowedTool)
	}
	return fmt.Sprintf("%s%s%s%s%s%s%s", id, SigSeparator, decisionID, SigSeparator, allowedTool, SigSeparator, effectDigestHash[0])
}

// CanonicalizeReceipt creates a canonical string representation of a receipt for signing.
// V4: includes ArgsHash for PEP boundary binding.
func CanonicalizeReceipt(receiptID, decisionID, effectID, status, outputHash, prevHash string, lamportClock uint64, argsHash string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%d%s%s", receiptID, SigSeparator, decisionID, SigSeparator, effectID, SigSeparator, status, SigSeparator, outputHash, SigSeparator, prevHash, SigSeparator, lamportClock, SigSeparator, argsHash)
}
