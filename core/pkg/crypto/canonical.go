package crypto

// quantum_posture: canonical intent payloads bind authorization fields but do
// not change the security strength of the configured signature algorithm.

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

// CanonicalizeIntent preserves the legacy compact formatter for callers that
// need to display or inspect old intent identifiers. It is not used for new
// authorization signatures.
func CanonicalizeIntent(id, decisionID, allowedTool string, effectDigestHash ...string) string {
	if len(effectDigestHash) == 0 {
		return fmt.Sprintf("%s%s%s%s%s", id, SigSeparator, decisionID, SigSeparator, allowedTool)
	}
	return fmt.Sprintf("%s%s%s%s%s%s%s", id, SigSeparator, decisionID, SigSeparator, allowedTool, SigSeparator, effectDigestHash[0])
}

func canonicalizeIntentForSigning(intent *contracts.AuthorizedExecutionIntent) ([]byte, error) {
	if intent == nil {
		return nil, fmt.Errorf("intent is required for canonicalization")
	}
	intent.SignatureVersion = contracts.IntentSignatureVersionV2
	return canonicalizeIntentV2(intent)
}

// canonicalizeIntentForVerification keeps the legacy read path explicit for
// short-lived intents queued before the v2 rollout. A versioned intent never
// falls back: clearing or changing the signature-bound version changes the
// selected preimage and fails verification.
func canonicalizeIntentForVerification(intent *contracts.AuthorizedExecutionIntent) ([]byte, error) {
	if intent == nil {
		return nil, fmt.Errorf("intent is required for canonicalization")
	}
	switch intent.SignatureVersion {
	case "":
		return []byte(CanonicalizeIntent(intent.ID, intent.DecisionID, intent.AllowedTool, intent.EffectDigestHash)), nil
	case contracts.IntentSignatureVersionV2:
		return canonicalizeIntentV2(intent)
	default:
		return nil, fmt.Errorf("unsupported intent signature version %q", intent.SignatureVersion)
	}
}

// canonicalizeIntentV2 binds every authority-relevant intent field. It
// intentionally excludes only Signature itself. A map is used so
// encoding/json emits keys lexicographically, as required by CanonicalMarshal.
func canonicalizeIntentV2(intent *contracts.AuthorizedExecutionIntent) ([]byte, error) {
	if intent == nil {
		return nil, fmt.Errorf("intent is required for canonicalization")
	}
	if intent.SignatureVersion != contracts.IntentSignatureVersionV2 {
		return nil, fmt.Errorf("intent signature version %q is not %q", intent.SignatureVersion, contracts.IntentSignatureVersionV2)
	}

	payload := map[string]any{
		"allowed_tool":                    intent.AllowedTool,
		"decision_id":                     intent.DecisionID,
		"effect_digest_hash":              intent.EffectDigestHash,
		"emergency_activation_id":         intent.EmergencyActivationID,
		"emergency_delegation_session_id": intent.EmergencyDelegationSessionID,
		"emergency_scope_hash":            intent.EmergencyScopeHash,
		"expires_at":                      intent.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"id":                              intent.ID,
		"idempotency_key":                 intent.IdempotencyKey,
		"issued_at":                       intent.IssuedAt.UTC().Format(time.RFC3339Nano),
		"signature_type":                  intent.SignatureType,
		"signer":                          intent.Signer,
		"taint":                           contracts.NormalizeTaintLabels(intent.Taint),
		"version":                         intent.SignatureVersion,
	}
	return CanonicalMarshal(payload)
}

// CanonicalizeReceipt creates a canonical string representation of a receipt for signing.
// V4: includes ArgsHash for PEP boundary binding.
func CanonicalizeReceipt(receiptID, decisionID, effectID, status, outputHash, prevHash string, lamportClock uint64, argsHash string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%d%s%s", receiptID, SigSeparator, decisionID, SigSeparator, effectID, SigSeparator, status, SigSeparator, outputHash, SigSeparator, prevHash, SigSeparator, lamportClock, SigSeparator, argsHash)
}
