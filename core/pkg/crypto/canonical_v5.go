package crypto

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ReceiptPreimageV4 reproduces the legacy eight-field preimage — ReceiptID,
// DecisionID, EffectID, Status, OutputHash, PrevHash, LamportClock, ArgsHash,
// joined with a bare ":" — out of roughly eighty receipt fields. Everything
// else was carried unsigned and could be rewritten without invalidating the
// signature, including Verdict, PolicyHash, MerkleRoot, KeyID, PublicKeySet
// and WitnessSignatures (F-05); the unescaped separator also let a
// colon-bearing value shift field boundaries so two distinct receipts shared
// signed bytes (F-06).
//
// Retained solely so previously issued receipts remain verifiable. Never used
// for signing: CanonicalizeReceiptV5 is the active preimage.
func ReceiptPreimageV4(r *contracts.Receipt) []byte {
	return []byte(CanonicalizeReceipt(
		r.ReceiptID, r.DecisionID, r.EffectID, r.Status,
		r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash))
}

// ReceiptPreimageVersion identifies which canonicalization authenticated a
// receipt.
type ReceiptPreimageVersion string

const (
	// ReceiptPreimageCurrent is the HELM-303 preimage: a JCS object over the
	// V4 field list plus verdict, reason_code, policy_hash and session_id.
	// It is what every signer in this package emits.
	ReceiptPreimageCurrent ReceiptPreimageVersion = "v5-fields-jcs"
	// ReceiptPreimageLegacy is the eight-field colon-joined string. Deprecated:
	// it leaves most of the receipt unsigned and its field boundaries collide.
	ReceiptPreimageLegacy ReceiptPreimageVersion = "v4-fields"
)

// VerifyReceiptSignature checks r against pubKeyHex using the preimage its own
// signature_version declares, and reports which one matched.
//
// It deliberately reconstructs exactly one preimage rather than trying several:
// the version tag on the receipt decides, so a v4-signed receipt relabelled
// "receipt.v5" fails instead of falling back into a passing verification. A
// ReceiptPreimageLegacy result means the receipt predates HELM-303 and most of
// its content is unauthenticated — callers should surface that rather than
// treat it as equivalent to the current preimage.
//
// This is the same payload derivation every signer and verifier in this package
// uses (ReceiptSigningPayload / ReceiptVerifyPayload). They must not diverge:
// a package whose public verifier rejects its own signatures is worse than one
// with no public verifier at all.
func VerifyReceiptSignature(pubKeyHex string, r *contracts.Receipt) (bool, ReceiptPreimageVersion, error) {
	if r == nil {
		return false, "", fmt.Errorf("receipt is nil")
	}
	if r.Signature == "" {
		return false, "", fmt.Errorf("missing signature")
	}

	version := ReceiptPreimageCurrent
	if r.SignatureVersion == "" {
		version = ReceiptPreimageLegacy
	}

	payload, err := ReceiptVerifyPayload(r)
	if err != nil {
		return false, "", err
	}
	ok, err := Verify(pubKeyHex, r.Signature, payload)
	if err != nil {
		return false, "", err
	}
	if !ok {
		return false, "", nil
	}
	return true, version, nil
}
