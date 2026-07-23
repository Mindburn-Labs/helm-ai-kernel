// quantum_posture: canonical signing preimages are algorithm-neutral; they do
// not upgrade the posture of the configured signer or external trust edges.
package crypto

// quantum_posture: canonical threat-evidence binding is signature-algorithm
// agnostic; the explicit rollout profiles make no post-quantum certification claim.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
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
	SigSeparator                = ":"
	SigPrefixEd25519            = "ed25519"
	SigPrefixMLDSA65            = "ml-dsa-65"
	SigPrefixEd25519ThreatV1    = "ed25519-threat-v1"
	SigPrefixMLDSA65ThreatV1    = "ml-dsa-65-threat-v1"
	decisionThreatBindingDomain = "helm-decision-threat-binding-v1"
	decisionThreatReasonMarker  = "\n[helm-threat-evidence-v1:"
)

// CanonicalizeDecision creates a canonical string representation of a decision record for signing.
// V2: binds all security-relevant fields including PhenotypeHash, PolicyContentHash, EffectDigest (DRIFT-7 fix).
// Empty security-relevant hashes are permitted for backward compatibility but logged as a warning.
func CanonicalizeDecision(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest string, threatEvidenceHash ...string) string {
	base := fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s", id, SigSeparator, verdict, SigSeparator, reason, SigSeparator, phenotypeHash, SigSeparator, policyContentHash, SigSeparator, effectDigest)
	if len(threatEvidenceHash) == 0 || threatEvidenceHash[0] == "" {
		return base
	}

	// Preserve the legacy preimage byte-for-byte when no threat evidence is
	// present. Evidence-bearing decisions use a separate domain and bind a
	// digest of the complete legacy preimage plus a length-framed evidence
	// digest. This prevents an attacker from stripping ThreatScan and folding
	// the old ":<hash>" suffix into EffectDigest to recover the same preimage.
	baseSum := sha256.Sum256([]byte(base))
	evidenceHash := threatEvidenceHash[0]
	return fmt.Sprintf("%s%s%x%s%d%s%s", decisionThreatBindingDomain, SigSeparator, baseSum, SigSeparator, len(evidenceHash), SigSeparator, evidenceHash)
}

func decisionThreatEvidenceHash(decision *contracts.DecisionRecord) (string, error) {
	if decision == nil || decision.ThreatScan == nil {
		return "", nil
	}
	encoded, err := CanonicalMarshal(decision.ThreatScan)
	if err != nil {
		return "", fmt.Errorf("canonicalize decision threat evidence: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalizeDecisionRecord(decision *contracts.DecisionRecord) (string, error) {
	threatHash, err := decisionThreatEvidenceHash(decision)
	if err != nil {
		return "", err
	}
	return CanonicalizeDecision(
		decision.ID,
		decision.Verdict,
		decision.Reason,
		decision.PhenotypeHash,
		decision.PolicyContentHash,
		decision.EffectDigest,
		threatHash,
	), nil
}

func legacyDecisionPayload(decision *contracts.DecisionRecord) string {
	return CanonicalizeDecision(
		decision.ID,
		decision.Verdict,
		decision.Reason,
		decision.PhenotypeHash,
		decision.PolicyContentHash,
		decision.EffectDigest,
	)
}

// decisionSigningPayloads returns a legacy-compatible primary preimage and,
// when threat evidence exists, a second domain-separated preimage. The signed
// reason marker makes evidence presence immutable even to an upgraded verifier
// receiving a record from which both additive threat fields were stripped.
func decisionSigningPayloads(decision *contracts.DecisionRecord) (string, string, error) {
	if decision == nil {
		return "", "", fmt.Errorf("decision is required")
	}
	threatHash, err := decisionThreatEvidenceHash(decision)
	if err != nil {
		return "", "", err
	}
	if threatHash == "" {
		if strings.Contains(legacyDecisionPayload(decision), decisionThreatReasonMarker) {
			return "", "", fmt.Errorf("reserved threat-evidence marker without threat evidence")
		}
		decision.ThreatScanSignature = ""
		decision.ThreatScanSignatureType = ""
		return legacyDecisionPayload(decision), "", nil
	}

	marker := decisionThreatReasonMarker + threatHash + "]"
	markerCount := strings.Count(decision.Reason, decisionThreatReasonMarker)
	if markerCount == 0 {
		decision.Reason += marker
	} else if markerCount != 1 || !strings.HasSuffix(decision.Reason, marker) {
		return "", "", fmt.Errorf("decision threat-evidence marker does not match typed evidence")
	}
	threatPayload, err := canonicalizeDecisionRecord(decision)
	if err != nil {
		return "", "", err
	}
	return legacyDecisionPayload(decision), threatPayload, nil
}

func decisionVerificationPayloads(decision *contracts.DecisionRecord, expectedLegacyProfile, expectedThreatProfile string) (string, string, error) {
	if decision == nil {
		return "", "", fmt.Errorf("decision is required")
	}
	threatHash, err := decisionThreatEvidenceHash(decision)
	if err != nil {
		return "", "", err
	}
	if threatHash == "" {
		// Search the reconstructed preimage rather than individual fields. The
		// legacy format is delimiter-based, so an attacker can move a delimiter
		// boundary into the marker while preserving the exact signed bytes.
		if strings.Contains(legacyDecisionPayload(decision), decisionThreatReasonMarker) || decision.ThreatScanSignature != "" || decision.ThreatScanSignatureType != "" {
			return "", "", fmt.Errorf("threat-bound decision is missing typed threat evidence")
		}
		return legacyDecisionPayload(decision), "", nil
	}

	legacyProfile, legacyKeyID, legacyOK := splitSignatureType(decision.SignatureType)
	if !legacyOK || legacyProfile != expectedLegacyProfile {
		return "", "", fmt.Errorf("decision signature profile %q does not match required %q", legacyProfile, expectedLegacyProfile)
	}
	threatProfile, threatKeyID, threatOK := splitSignatureType(decision.ThreatScanSignatureType)
	if !threatOK || threatProfile != expectedThreatProfile {
		return "", "", fmt.Errorf("threat signature profile %q does not match required %q", threatProfile, expectedThreatProfile)
	}
	if threatKeyID != legacyKeyID {
		return "", "", fmt.Errorf("threat signature key %q does not match primary signature key %q", threatKeyID, legacyKeyID)
	}
	if decision.ThreatScanSignature == "" {
		return "", "", fmt.Errorf("missing threat-scan signature")
	}
	marker := decisionThreatReasonMarker + threatHash + "]"
	if strings.Count(decision.Reason, decisionThreatReasonMarker) != 1 || !strings.HasSuffix(decision.Reason, marker) {
		return "", "", fmt.Errorf("decision threat-evidence marker does not match typed evidence")
	}
	threatPayload, err := canonicalizeDecisionRecord(decision)
	if err != nil {
		return "", "", err
	}
	return legacyDecisionPayload(decision), threatPayload, nil
}

func splitSignatureType(signatureType string) (string, string, bool) {
	profile, keyID, ok := strings.Cut(signatureType, SigSeparator)
	return profile, keyID, ok && profile != "" && keyID != "" && !strings.Contains(keyID, SigSeparator)
}

// CanonicalizeDecisionStrict is like CanonicalizeDecision but returns an error if any
// security-relevant hash field is empty. Use this for new code paths where all fields
// are expected to be populated.
func CanonicalizeDecisionStrict(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest string, threatEvidenceHash ...string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("decision ID is required for canonicalization")
	}
	if verdict == "" {
		return "", fmt.Errorf("verdict is required for canonicalization")
	}
	return CanonicalizeDecision(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest, threatEvidenceHash...), nil
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
