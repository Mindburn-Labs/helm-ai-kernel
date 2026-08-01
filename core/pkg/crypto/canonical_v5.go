package crypto

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ReceiptPreimageV5 is the JCS canonicalization of a receipt, excluding only
// the signature field itself.
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
// STATUS: NOT THE ACTIVE PREIMAGE, and not what the "receipt.v5" wire version
// means. HELM-303 shipped a narrower V5 — CanonicalizeReceiptV5 in canonical.go,
// which extends the V4 field list with verdict, reason_code, policy_hash and
// session_id. That is what ReceiptSigningPayload emits, what ReceiptVerifyPayload
// checks, and what every signer/verifier in this package calls; it stays inside
// the columns the receipt store round-trips.
//
// This file is the wider, still-unshipped ambition: whole-envelope JCS. It has
// no non-test callers — including VerifyReceiptSignature below, which would
// compute a DIFFERENT preimage for the same "receipt.v5" tag. Do not wire it
// without giving it its own version constant.
//
// Switching the signer over is blocked on the receipt store, which cannot
// round-trip a full receipt: receiptColumns in core/pkg/store/receipt_store.go
// has no column for key_id, public_key_set, signature_profile,
// signature_algorithm or correlation_id. Those fields come back empty after a
// load, so a signature covering them cannot match once the receipt has been
// persisted. Whole-envelope signing therefore needs a schema migration first;
// signing a subset that happens to survive the store would silently reintroduce
// F-05 for everything the store drops.
//
// Migration once that lands: signers emit v5, verifiers accept v5 first and v4
// second so previously issued receipts keep verifying, and
// VerifyReceiptSignature reports which preimage matched so callers can surface
// v4 as deprecated. Also note anchorReceiptTransparency mutates the receipt
// after signing, which is why the three transparency fields are excluded below.
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
	// ReceiptPreimageCurrent is the JCS envelope over the whole receipt.
	ReceiptPreimageCurrent ReceiptPreimageVersion = "v5-jcs"
	// ReceiptPreimageLegacy is the eight-field colon-joined string. Deprecated:
	// it leaves most of the receipt unsigned and its field boundaries collide.
	ReceiptPreimageLegacy ReceiptPreimageVersion = "v4-fields"
)

// VerifyReceiptSignature checks r against pubKeyHex under v5, then v4.
//
// It returns the version that matched. A v4 match means the receipt predates
// the envelope change and most of its content is unauthenticated — callers
// should surface that rather than treat it as equivalent to v5.
func VerifyReceiptSignature(pubKeyHex string, r *contracts.Receipt) (bool, ReceiptPreimageVersion, error) {
	if r == nil {
		return false, "", fmt.Errorf("receipt is nil")
	}
	if r.Signature == "" {
		return false, "", fmt.Errorf("missing signature")
	}

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
}
