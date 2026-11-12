// quantum_posture: this adapter retains classical Ed25519 verification only.
package receiptverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"
)

const (
	DocumentSchemaVersion = "helm.receipt-verification.v1"
	MaxDocumentBytes      = 8 << 20
	MaxTrustRootBytes     = 64 << 10
)

// Verdict describes the existing verifier's result, including its explicit
// refusal to verify without an independently supplied trust root or to check
// a legacy receipt.
type Verdict string

const (
	VerdictVerified     Verdict = "VERIFIED"
	VerdictFailed       Verdict = "FAILED"
	VerdictUnverifiable Verdict = "UNVERIFIABLE"
)

// DocumentResult retains every check and limitation emitted by VerifyBundle.
// It does not attest an EvidencePack, a party's identity, or an executed effect.
type DocumentResult struct {
	SchemaVersion string  `json:"schema_version"`
	Verdict       Verdict `json:"verdict"`
	Verification  Result  `json:"verification"`
}

// VerifyJSON accepts a receipt document and a separate caller-supplied trust
// root, encoded as {"keys":{"key-id":"Ed25519-public-key-hex"}}. Empty trust
// input trusts nothing. Artifact-supplied keys never become trusted, and this
// interface deliberately provides no self-attestation opt-in.
//
// It has no legacy opt-in either: a document holding a receipt with no
// signature_version is UNVERIFIABLE, because it was not checked (see
// LegacyV4Refusal). A document whose member names differ from the receipt,
// bundle or permit members only in letter case, or whose bundle form carries a
// receipt member beside "receipts", is FAILED at parsing.
//
// Parsing and all cryptographic/chain/permit checks use the same producer as
// receipt_verify. No clock, configuration discovery, file or network is read.
func VerifyJSON(document, trustRootJSON []byte) DocumentResult {
	out := DocumentResult{SchemaVersion: DocumentSchemaVersion, Verdict: VerdictFailed}
	fail := func(err error) DocumentResult {
		out.Verification.Errors = []string{err.Error()}
		return out
	}
	if len(document) > MaxDocumentBytes {
		return fail(errors.New("receipt document exceeds the 8 MiB limit"))
	}
	if !utf8.Valid(document) {
		return fail(errors.New("receipt document must be UTF-8"))
	}
	if err := validateJSONWork(document); err != nil {
		return fail(fmt.Errorf("receipt document: %w", err))
	}
	bundle, err := ParseBundle(document)
	if err != nil {
		return fail(err)
	}
	keys, err := parseJSONTrustRoot(trustRootJSON)
	if err != nil {
		return fail(err)
	}
	var why refusal
	out.Verification, why = verifyBundle(bundle, TrustRoot{Keys: keys}, Options{})
	if out.Verification.Valid {
		out.Verdict = VerdictVerified
	} else if why == refusedNoTrustedKey || why == refusedLegacyV4 {
		// Translate the producer's explicit refusal: the receipts were not
		// checked. Do not manufacture a successful identity check by
		// inspecting an artifact-carried key, or a failed one for a legacy
		// receipt no check ran on.
		out.Verdict = VerdictUnverifiable
	}
	return out
}

func parseJSONTrustRoot(raw []byte) (map[string]string, error) {
	if len(raw) > MaxTrustRootBytes {
		return nil, errors.New("trust root exceeds the 64 KiB limit")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, nil
	}
	if !utf8.Valid(raw) || raw[0] != '{' {
		return nil, errors.New("trust root must be a UTF-8 JSON object")
	}
	if err := validateJSONWork(raw); err != nil {
		return nil, fmt.Errorf("trust root: %w", err)
	}
	if err := ValidateJSONStructure(raw); err != nil {
		return nil, fmt.Errorf("trust root: %w", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("trust root: %w", err)
	}
	for field := range object {
		if field != "keys" {
			return nil, errors.New("trust root accepts only the keys member")
		}
	}
	if object["keys"] == nil {
		return nil, nil
	}
	var keys map[string]string
	if err := json.Unmarshal(object["keys"], &keys); err != nil {
		return nil, errors.New("trust root keys must map key IDs to public-key hex strings")
	}
	if len(keys) > 128 {
		return nil, errors.New("trust root exceeds the 128-key limit")
	}
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		decoded, err := hex.DecodeString(keys[id])
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, errors.New("trusted keys must be 32-byte Ed25519 public keys encoded as hex")
		}
	}
	return keys, nil
}
