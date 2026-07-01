package crypto

// quantum_posture: hybrid/PQ receipt verification; fail closed on downgrade.

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// Receipt signature profiles per the PQ-hybrid receipt profile RFC
// (protocols/specs/rfc/receipt-pq-hybrid-profile-v1.md).
const (
	ReceiptProfileClassical = "classical"
	ReceiptProfileHybrid    = "hybrid"
)

// ReceiptSignatureProfile detects the signature profile of a receipt
// signature envelope. A composite "hybrid:<ed25519_hex>:<mldsa_hex>"
// envelope is the hybrid profile; anything else is the classical profile.
func ReceiptSignatureProfile(signature string) string {
	if strings.HasPrefix(signature, HybridSigPrefix+HybridSigSeparator) {
		return ReceiptProfileHybrid
	}
	return ReceiptProfileClassical
}

// HybridVerifier implements Verifier for hybrid Ed25519+ML-DSA-65 composite
// envelopes using public keys only. Verification is fail-closed: both
// sub-signatures must be valid; a malformed envelope, a failing component,
// or a non-hybrid signature all fail verification. There is no downgrade to
// classical-only acceptance.
type HybridVerifier struct {
	ed    *Ed25519Verifier
	mldsa *MLDSAVerifier
}

// NewHybridVerifier creates a verifier from raw Ed25519 and ML-DSA-65 public
// key bytes.
func NewHybridVerifier(edPubBytes, mldsaPubBytes []byte) (*HybridVerifier, error) {
	ed, err := NewEd25519Verifier(edPubBytes)
	if err != nil {
		return nil, fmt.Errorf("hybrid verifier: %w", err)
	}
	mldsa, err := NewMLDSAVerifier(mldsaPubBytes)
	if err != nil {
		return nil, fmt.Errorf("hybrid verifier: %w", err)
	}
	return &HybridVerifier{ed: ed, mldsa: mldsa}, nil
}

// Verify checks a composite envelope (passed as raw bytes of the envelope
// string) against a message. Both sub-signatures must verify.
func (v *HybridVerifier) Verify(message []byte, signature []byte) bool {
	ok, err := v.verifyEnvelope(message, string(signature))
	return err == nil && ok
}

// VerifyDecision verifies a hybrid-signed DecisionRecord.
func (v *HybridVerifier) VerifyDecision(d *contracts.DecisionRecord) (bool, error) {
	payload := CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
	return v.verifyEnvelope([]byte(payload), d.Signature)
}

// VerifyIntent verifies a hybrid-signed AuthorizedExecutionIntent.
func (v *HybridVerifier) VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error) {
	payload := CanonicalizeIntent(i.ID, i.DecisionID, i.AllowedTool)
	return v.verifyEnvelope([]byte(payload), i.Signature)
}

// VerifyReceipt verifies a hybrid-signed Receipt over the canonical receipt
// preimage (same preimage as the classical profile).
func (v *HybridVerifier) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	payload := CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)
	return v.verifyEnvelope([]byte(payload), r.Signature)
}

func (v *HybridVerifier) verifyEnvelope(message []byte, envelope string) (bool, error) {
	if envelope == "" {
		return false, fmt.Errorf("missing signature")
	}
	edSigHex, mldsaSigHex, err := parseHybridSignature(envelope)
	if err != nil {
		return false, err
	}
	edSig, err := hex.DecodeString(edSigHex)
	if err != nil {
		return false, fmt.Errorf("hybrid: invalid ed25519 signature hex: %w", err)
	}
	if !v.ed.Verify(message, edSig) {
		return false, nil
	}
	mldsaSig, err := hex.DecodeString(mldsaSigHex)
	if err != nil {
		return false, fmt.Errorf("hybrid: invalid ml-dsa-65 signature hex: %w", err)
	}
	if !v.mldsa.Verify(message, mldsaSig) {
		return false, nil
	}
	return true, nil
}

// VerifyReceiptProfile is the SDK-agnostic, profile-aware receipt
// verification entry point. It detects the signature profile and applies the
// RFC verification policy:
//
//   - classical profile: the Ed25519 signature must verify against edPubHex.
//   - hybrid profile: BOTH the Ed25519 and ML-DSA-65 sub-signatures must
//     verify (fail-closed on either). If mldsaPubHex is empty, hybrid
//     verification fails — there is no silent downgrade to classical-only.
//
// It returns the detected profile alongside the verification result so
// callers can enforce issuance-policy cutovers (e.g. "hybrid required after
// date X") on top of cryptographic validity.
func VerifyReceiptProfile(edPubHex, mldsaPubHex string, r *contracts.Receipt) (profile string, valid bool, err error) {
	if r == nil {
		return "", false, fmt.Errorf("nil receipt")
	}
	if r.Signature == "" {
		return "", false, fmt.Errorf("missing signature")
	}
	profile = ReceiptSignatureProfile(r.Signature)
	payload := CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)

	switch profile {
	case ReceiptProfileHybrid:
		if mldsaPubHex == "" {
			return profile, false, fmt.Errorf("hybrid receipt requires ml-dsa-65 public key: no downgrade to classical-only verification")
		}
		mldsaPub, decErr := hex.DecodeString(mldsaPubHex)
		if decErr != nil {
			return profile, false, fmt.Errorf("invalid ml-dsa-65 public key hex: %w", decErr)
		}
		edPub, decErr := hex.DecodeString(edPubHex)
		if decErr != nil {
			return profile, false, fmt.Errorf("invalid ed25519 public key hex: %w", decErr)
		}
		hv, vErr := NewHybridVerifier(edPub, mldsaPub)
		if vErr != nil {
			return profile, false, vErr
		}
		ok, vErr := hv.verifyEnvelope([]byte(payload), r.Signature)
		return profile, ok, vErr
	default:
		ok, vErr := Verify(edPubHex, r.Signature, []byte(payload))
		return profile, ok, vErr
	}
}

// VerifyReceiptRequiredProfile verifies a receipt and fails closed when the
// detected signature profile is below the caller's required profile.
func VerifyReceiptRequiredProfile(edPubHex, mldsaPubHex string, r *contracts.Receipt, requiredProfile string) (profile string, valid bool, err error) {
	if r == nil || r.Signature == "" {
		return VerifyReceiptProfile(edPubHex, mldsaPubHex, r)
	}

	required := strings.ToLower(strings.TrimSpace(requiredProfile))
	switch required {
	case "":
		return VerifyReceiptProfile(edPubHex, mldsaPubHex, r)
	case ReceiptProfileClassical, ReceiptProfileHybrid:
	default:
		return "", false, fmt.Errorf("unsupported required receipt profile %q", requiredProfile)
	}

	profile = ReceiptSignatureProfile(r.Signature)
	if required == ReceiptProfileHybrid && profile != ReceiptProfileHybrid {
		return profile, false, fmt.Errorf("receipt profile %q does not satisfy required profile %q", profile, required)
	}
	return VerifyReceiptProfile(edPubHex, mldsaPubHex, r)
}

// Compile-time interface check: HybridVerifier must implement Verifier.
var _ Verifier = (*HybridVerifier)(nil)
