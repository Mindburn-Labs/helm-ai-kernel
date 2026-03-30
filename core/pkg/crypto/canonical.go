package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
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

// CanonicalizeIntent creates a canonical string representation of an intent for signing.
func CanonicalizeIntent(id, decisionID, allowedTool string) string {
	return fmt.Sprintf("%s%s%s%s%s", id, SigSeparator, decisionID, SigSeparator, allowedTool)
}

// CanonicalizeReceipt creates a canonical string representation of a receipt for signing.
// V4: includes ArgsHash for PEP boundary binding (Phase 2).
func CanonicalizeReceipt(receiptID, decisionID, effectID, status, outputHash, prevHash string, lamportClock uint64, argsHash string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%d%s%s", receiptID, SigSeparator, decisionID, SigSeparator, effectID, SigSeparator, status, SigSeparator, outputHash, SigSeparator, prevHash, SigSeparator, lamportClock, SigSeparator, argsHash)
}
