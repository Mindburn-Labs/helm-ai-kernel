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

const intentSignatureVersion = "helm.intent.v2"

// canonicalizeIntentForSignature binds every authority-relevant intent field.
// It intentionally excludes only Signature itself.
func canonicalizeIntentForSignature(intent *contracts.AuthorizedExecutionIntent) ([]byte, error) {
	if intent == nil {
		return nil, fmt.Errorf("intent is required for canonicalization")
	}

	payload := struct {
		Version                      string   `json:"version"`
		ID                           string   `json:"id"`
		DecisionID                   string   `json:"decision_id"`
		EffectDigestHash             string   `json:"effect_digest_hash"`
		IdempotencyKey               string   `json:"idempotency_key"`
		IssuedAt                     string   `json:"issued_at"`
		ExpiresAt                    string   `json:"expires_at"`
		Signer                       string   `json:"signer"`
		SignatureType                string   `json:"signature_type"`
		AllowedTool                  string   `json:"allowed_tool"`
		Taint                        []string `json:"taint"`
		EmergencyActivationID        string   `json:"emergency_activation_id"`
		EmergencyDelegationSessionID string   `json:"emergency_delegation_session_id"`
		EmergencyScopeHash           string   `json:"emergency_scope_hash"`
	}{
		Version:                      intentSignatureVersion,
		ID:                           intent.ID,
		DecisionID:                   intent.DecisionID,
		EffectDigestHash:             intent.EffectDigestHash,
		IdempotencyKey:               intent.IdempotencyKey,
		IssuedAt:                     intent.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:                    intent.ExpiresAt.UTC().Format(time.RFC3339Nano),
		Signer:                       intent.Signer,
		SignatureType:                intent.SignatureType,
		AllowedTool:                  intent.AllowedTool,
		Taint:                        contracts.NormalizeTaintLabels(intent.Taint),
		EmergencyActivationID:        intent.EmergencyActivationID,
		EmergencyDelegationSessionID: intent.EmergencyDelegationSessionID,
		EmergencyScopeHash:           intent.EmergencyScopeHash,
	}
	return CanonicalMarshal(payload)
}

// CanonicalizeReceipt creates a canonical string representation of a receipt for signing.
// V4: includes ArgsHash for PEP boundary binding.
func CanonicalizeReceipt(receiptID, decisionID, effectID, status, outputHash, prevHash string, lamportClock uint64, argsHash string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%d%s%s", receiptID, SigSeparator, decisionID, SigSeparator, effectID, SigSeparator, status, SigSeparator, outputHash, SigSeparator, prevHash, SigSeparator, lamportClock, SigSeparator, argsHash)
}
