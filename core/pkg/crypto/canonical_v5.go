package crypto

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ReceiptPreimageV5 is the historical whole-receipt JCS canonicalization,
// excluding only the signature field itself.
//
// It replaces the v4 preimage (CanonicalizeReceipt), which bound just eight
// fields — ReceiptID, DecisionID, EffectID, Status, OutputHash, PrevHash,
// LamportClock, ArgsHash — out of roughly eighty. Everything else was carried
// unsigned and could be rewritten without invalidating the signature, including
// Verdict, Timestamp, PolicyHash, MerkleRoot, KeyID, PublicKeySet,
// WitnessSignatures and the transparency-log anchoring fields (F-05).
//
// v4 also joined its fields with a bare ":" and escaped nothing, so a value
// containing a colon shifted the field boundaries and two distinct receipts
// produced identical preimages — one signature verifying both (F-06). A JCS
// object has no such ambiguity: every field is separately keyed and every string
// is escaped.
//
// Active receipt.v5 signing instead uses CanonicalizeReceiptV5's durable narrow
// envelope: the causal fields plus Verdict, ReasonCode, PolicyHash, and
// SessionID. This compatibility helper remains only for unversioned receipts
// issued under the early whole-envelope JCS candidate. Also note
// anchorReceiptTransparency mutates the receipt after signing, which is why the
// three transparency fields are excluded below.
func ReceiptPreimageV5(r *contracts.Receipt) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("receipt is nil")
	}
	// Copy so the caller's receipt is never mutated, and clear the signature:
	// it cannot be an input to the value it authenticates.
	unsigned := *r
	unsigned.Signature = ""

	// Transparency-log anchoring is assigned after the receipt is signed —
	// anchorReceiptTransparency runs on the already-signed receipt — so the
	// signer cannot attest to it. contracts.ReceiptChainHash excludes the same
	// three fields for the same reason; the two canonicalizations must agree on
	// what is and is not signer-attestable.
	//
	// This is a deliberate, bounded carve-out: these fields record where an
	// external log placed the receipt, not what the kernel decided. They remain
	// outside the signature and must be verified against the transparency log
	// itself, never trusted from the receipt.
	unsigned.Transparency = nil
	unsigned.LogID = ""
	unsigned.LeafIndex = 0

	payload, err := canonicalize.JCS(&unsigned)
	if err != nil {
		return nil, fmt.Errorf("canonicalize receipt for signing: %w", err)
	}
	return payload, nil
}

// ReceiptPreimageV4 reproduces the legacy eight-field preimage. Retained solely
// so previously issued receipts remain verifiable; never used for signing.
func ReceiptPreimageV4(r *contracts.Receipt) []byte {
	return []byte(CanonicalizeReceipt(
		r.ReceiptID, r.DecisionID, r.EffectID, r.Status,
		r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash))
}

// ReceiptPreimageVersion identifies which canonicalization authenticated a
// receipt.
type ReceiptPreimageVersion string

const (
	// ReceiptPreimageCurrent is the historical, wider JCS envelope over the
	// whole receipt. It is retained for callers that issued it before
	// receipt.v5 was introduced; it is not the active receipt.v5 wire format.
	ReceiptPreimageCurrent ReceiptPreimageVersion = "v5-jcs"
	// ReceiptPreimageSignedFieldsV5 is the active HELM-303 receipt.v5 payload:
	// the durable V4 fields plus governance-meaning fields in a narrow JCS
	// envelope. It is deliberately distinct from ReceiptPreimageCurrent.
	ReceiptPreimageSignedFieldsV5 ReceiptPreimageVersion = contracts.ReceiptSignatureV5
	// ReceiptPreimageLegacy is the eight-field colon-joined string. Deprecated:
	// it leaves most of the receipt unsigned and its field boundaries collide.
	ReceiptPreimageLegacy ReceiptPreimageVersion = "v4-fields"
)

// VerifyReceiptSignature verifies the payload declared by r.SignatureVersion.
//
// A declared receipt.v5 must verify under the active narrow signing envelope;
// it must never be silently retried as a legacy payload. Empty versions retain
// compatibility for the pre-HELM-303 JCS helper and then V4 history.
func VerifyReceiptSignature(pubKeyHex string, r *contracts.Receipt) (bool, ReceiptPreimageVersion, error) {
	if r == nil {
		return false, "", fmt.Errorf("receipt is nil")
	}
	if r.Signature == "" {
		return false, "", fmt.Errorf("missing signature")
	}

	switch r.SignatureVersion {
	case contracts.ReceiptSignatureV5:
		payload, err := ReceiptVerifyPayload(r)
		if err != nil {
			return false, "", err
		}
		ok, err := Verify(pubKeyHex, r.Signature, payload)
		if err != nil {
			return false, "", err
		}
		if ok {
			return true, ReceiptPreimageSignedFieldsV5, nil
		}
		return false, "", nil
	case "":
		payload, err := ReceiptPreimageV5(r)
		if err != nil {
			return false, "", err
		}
		ok, err := Verify(pubKeyHex, r.Signature, payload)
		if err != nil {
			return false, "", err
		}
		if ok {
			return true, ReceiptPreimageCurrent, nil
		}

		ok, err = Verify(pubKeyHex, r.Signature, ReceiptPreimageV4(r))
		if err != nil {
			return false, "", err
		}
		if ok {
			return true, ReceiptPreimageLegacy, nil
		}
		return false, "", nil
	default:
		return false, "", fmt.Errorf("unsupported receipt signature version %q", r.SignatureVersion)
	}
}
