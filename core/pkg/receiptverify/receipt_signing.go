package receiptverify

// quantum_posture: Receipt preimages and signature verification use classical Ed25519.

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// sigSeparator matches crypto.SigSeparator. Duplicated rather than imported so
// this package stays a leaf; canonicalizationAgreement in the test file pins
// the two together so a change to one fails the build of the other.
const sigSeparator = ":"

// ClassicalEd25519MetadataCompatible reports whether optional receipt
// signature metadata is compatible with this classical-only verifier. Empty
// values retain receipts issued before these routing fields were populated;
// once declared, each value must name the profile this verifier actually uses.
func ClassicalEd25519MetadataCompatible(profile, algorithm string) bool {
	return (profile == "" && algorithm == "") ||
		(profile == "classical" && algorithm == "ed25519")
}

// receiptV5SigningEnvelope mirrors crypto.receiptV5SigningEnvelope field for
// field, including json tags and order. It is the active receipt.v5 payload:
// the durable causal fields plus the four governance-meaning fields.
//
// This is a narrow, explicitly enumerated envelope by design. A whole-struct
// canonicalization would mean every future field added to contracts.Receipt
// silently changed the preimage and broke every previously issued signature —
// the opposite of what a receipt is for.
type receiptV5SigningEnvelope struct {
	SignatureVersion string `json:"signature_version"`
	ReceiptID        string `json:"receipt_id"`
	DecisionID       string `json:"decision_id"`
	EffectID         string `json:"effect_id"`
	Status           string `json:"status"`
	OutputHash       string `json:"output_hash"`
	PrevHash         string `json:"prev_hash"`
	LamportClock     uint64 `json:"lamport_clock"`
	ArgsHash         string `json:"args_hash"`
	Verdict          string `json:"verdict"`
	ReasonCode       string `json:"reason_code"`
	PolicyHash       string `json:"policy_hash"`
	SessionID        string `json:"session_id"`
}

// ReceiptV5SignedMembers returns the names of the receipt members a
// receipt.v5 signature covers, in envelope order. Every other member of a
// receipt is covered by no signature of its own: a caller that reports on a
// receipt uses this to say which of the members it shows were checked.
func ReceiptV5SignedMembers() []string {
	envelope := reflect.TypeFor[receiptV5SigningEnvelope]()
	names := make([]string, 0, envelope.NumField())
	for i := 0; i < envelope.NumField(); i++ {
		name, _, _ := strings.Cut(envelope.Field(i).Tag.Get("json"), ",")
		names = append(names, name)
	}
	return names
}

// canonicalizeV5 reproduces crypto.CanonicalizeReceiptV5.
func canonicalizeV5(r *contracts.Receipt) ([]byte, error) {
	if r == nil {
		return nil, errors.New("receipt is nil")
	}
	return canonicalize.InteroperableJCS(receiptV5SigningEnvelope{
		SignatureVersion: contracts.ReceiptSignatureV5,
		ReceiptID:        r.ReceiptID,
		DecisionID:       r.DecisionID,
		EffectID:         r.EffectID,
		Status:           r.Status,
		OutputHash:       r.OutputHash,
		PrevHash:         r.PrevHash,
		LamportClock:     r.LamportClock,
		ArgsHash:         r.ArgsHash,
		Verdict:          r.Verdict,
		ReasonCode:       r.ReasonCode,
		PolicyHash:       r.PolicyHash,
		SessionID:        r.SessionID,
	})
}

// legacyV4Members names what canonicalizeV4 joins, for the messages that tell a
// reader what a legacy signature covers.
const legacyV4Members = "receipt_id, decision_id, effect_id, status, output_hash, prev_hash, lamport_clock and args_hash"

// canonicalizeV4 reproduces crypto.CanonicalizeReceipt, the legacy colon-joined
// preimage. Retained solely so receipts issued before receipt.v5 stay
// verifiable by a caller that opts in. Never used to verify a receipt that
// declares a version.
func canonicalizeV4(r *contracts.Receipt) []byte {
	return []byte(fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%d%s%s",
		r.ReceiptID, sigSeparator, r.DecisionID, sigSeparator, r.EffectID,
		sigSeparator, r.Status, sigSeparator, r.OutputHash, sigSeparator,
		r.PrevHash, sigSeparator, r.LamportClock, sigSeparator, r.ArgsHash))
}

// verifyEd25519 checks a hex signature over data with a hex public key.
func verifyEd25519(pubKeyHex, sigHex string, data []byte) (bool, error) {
	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key hex: %w", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: got %d, want %d", len(pubKey), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature size: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	return ed25519.Verify(ed25519.PublicKey(pubKey), data, sig), nil
}
