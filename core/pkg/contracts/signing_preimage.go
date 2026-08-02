package contracts

// HELM-303 signing preimages.
//
// They live in contracts, not in crypto, because more than one package has to
// derive them and they must never diverge: pkg/crypto signs and verifies with
// them, and pkg/verifier — the standalone offline verifier, which deliberately
// takes no dependency on pkg/crypto so an adversarial third party can build and
// audit it alone — must reconstruct exactly the same bytes. Two hand-written
// copies of a preimage is how a package ends up rejecting its own signatures.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// HashReason is the digest under which free-text Reason is attested in the V2
// decision preimage. Exported because the standalone verifier reconstructs the
// preimage from a JSON document and must derive the same value.
func HashReason(reason string) string {
	sum := sha256.Sum256([]byte(reason))
	return hex.EncodeToString(sum[:])
}

// canonicalPreimage encodes a signing envelope deterministically: compact, no
// HTML escaping, keys in the struct's declaration order.
//
// The envelope structs below declare their fields in lexicographic order, so
// this yields the same bytes as a JCS object for their shape — flat, with only
// string and integer values — at a fraction of the allocations, which matters
// because decision signing sits on the Guardian hot path. TestPreimage*Golden
// pins the exact bytes and TestPreimage*KeysAreSorted pins the ordering
// invariant, so reordering a field cannot silently change the preimage.
func canonicalPreimage(envelope any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(envelope); err != nil {
		return nil, fmt.Errorf("encode signing preimage: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// receiptSigningEnvelopeV5 is the V5 receipt preimage.
//
// It is a JSON object, not a separator-joined string. The V4 preimage joined
// its fields with a bare ":" and escaped nothing, so a value containing a colon
// shifted the field boundaries and two structurally different receipts produced
// identical signed bytes — one signature authenticating both (F-06). A JSON
// object has no such ambiguity: every field is separately keyed and every string
// is escaped, so the encoding is injective by construction.
//
// No field carries omitempty: an absent key and an empty value must never be the
// same preimage. The field set and its order are fixed and versioned — adding,
// dropping, reordering or retyping a field requires a new version constant,
// never an edit here.
//
//nolint:govet // field order IS the contract; it must stay lexicographic.
type receiptSigningEnvelopeV5 struct {
	ArgsHash         string `json:"args_hash"`
	DecisionID       string `json:"decision_id"`
	EffectID         string `json:"effect_id"`
	LamportClock     uint64 `json:"lamport_clock"`
	OutputHash       string `json:"output_hash"`
	PolicyHash       string `json:"policy_hash"`
	PrevHash         string `json:"prev_hash"`
	ReasonCode       string `json:"reason_code"`
	ReceiptID        string `json:"receipt_id"`
	SessionID        string `json:"session_id"`
	SignatureVersion string `json:"signature_version"`
	Status           string `json:"status"`
	Verdict          string `json:"verdict"`
}

// ReceiptPreimageV5 returns the bytes a ReceiptSignatureV5 signature covers: the
// V4 field list plus the receipt's governance-meaning fields — verdict,
// reason_code, policy_hash, session_id.
//
// Under V4 those four could be rewritten on a persisted receipt without
// invalidating its signature. The chain made that tamper-evident only once a
// successor receipt existed; the chain tip was signature-silent.
func ReceiptPreimageV5(r *Receipt) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("receipt is nil")
	}
	return canonicalPreimage(receiptSigningEnvelopeV5{
		ArgsHash:         r.ArgsHash,
		DecisionID:       r.DecisionID,
		EffectID:         r.EffectID,
		LamportClock:     r.LamportClock,
		OutputHash:       r.OutputHash,
		PolicyHash:       r.PolicyHash,
		PrevHash:         r.PrevHash,
		ReasonCode:       r.ReasonCode,
		ReceiptID:        r.ReceiptID,
		SessionID:        r.SessionID,
		SignatureVersion: ReceiptSignatureV5,
		Status:           r.Status,
		Verdict:          r.Verdict,
	})
}

// decisionSigningEnvelopeV2 is the V2 decision preimage. Same reasoning as
// receiptSigningEnvelopeV5: keyed fields instead of a colon join, so
// colon-bearing values (hashes routinely carry one) cannot shift a boundary and
// let one signature authenticate two different reason/hash splits.
//
//nolint:govet // field order IS the contract; it must stay lexicographic.
type decisionSigningEnvelopeV2 struct {
	EffectDigest      string `json:"effect_digest"`
	ID                string `json:"id"`
	PhenotypeHash     string `json:"phenotype_hash"`
	PolicyContentHash string `json:"policy_content_hash"`
	ReasonCode        string `json:"reason_code"`
	ReasonHash        string `json:"reason_hash"`
	SignatureVersion  string `json:"signature_version"`
	Verdict           string `json:"verdict"`
}

// DecisionPreimageV2 returns the bytes a DecisionRecordSignatureV2 signature
// covers.
//
// V2 promotes the machine-readable ReasonCode to a signed field — it is the
// exported, keyed-on claim and the legacy preimage did not bind it at all.
//
// Free-text Reason stays attested, as the digest reason_hash rather than
// verbatim. Binding the code alone would have been a regression: the legacy
// preimage bound Reason, and ReasonCode is empty by contract on ALLOW (the
// ReasonCode registry is for DENY/ESCALATE), so a V2 record could otherwise
// carry a freely rewritable explanation past verification. Hashing keeps prose
// out of the preimage, which the telemetry contract prohibits from export,
// while still making any edit to the emitted explanation break the signature.
func DecisionPreimageV2(d *DecisionRecord) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("decision record is nil")
	}
	return canonicalPreimage(decisionSigningEnvelopeV2{
		EffectDigest:      d.EffectDigest,
		ID:                d.ID,
		PhenotypeHash:     d.PhenotypeHash,
		PolicyContentHash: d.PolicyContentHash,
		ReasonCode:        d.ReasonCode,
		ReasonHash:        HashReason(d.Reason),
		SignatureVersion:  DecisionRecordSignatureV2,
		Verdict:           d.Verdict,
	})
}
