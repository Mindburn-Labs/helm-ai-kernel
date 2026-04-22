package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// MLDSAVerifier implements Verifier using ML-DSA-65 (FIPS 204).
// Use this for verification-only scenarios where you have only a public key.
type MLDSAVerifier struct {
	publicKey *mldsa65.PublicKey
}

// NewMLDSAVerifier creates a new ML-DSA-65 verifier from raw public key bytes.
func NewMLDSAVerifier(pubKeyBytes []byte) (*MLDSAVerifier, error) {
	if len(pubKeyBytes) != mldsa65.PublicKeySize {
		return nil, fmt.Errorf("invalid ml-dsa-65 public key size: %d, expected %d", len(pubKeyBytes), mldsa65.PublicKeySize)
	}
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pubKeyBytes); err != nil {
		return nil, fmt.Errorf("invalid ml-dsa-65 public key: %w", err)
	}
	return &MLDSAVerifier{publicKey: &pk}, nil
}

// Verify verifies a message against a raw signature using ML-DSA-65.
func (v *MLDSAVerifier) Verify(message []byte, signature []byte) bool {
	return mldsa65.Verify(v.publicKey, message, nil, signature)
}

// VerifyDecision verifies a DecisionRecord signature using ML-DSA-65.
func (v *MLDSAVerifier) VerifyDecision(d *contracts.DecisionRecord) (bool, error) {
	if d.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload := CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
	sig, err := hex.DecodeString(d.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}
	return mldsa65.Verify(v.publicKey, []byte(payload), nil, sig), nil
}

// VerifyIntent verifies an AuthorizedExecutionIntent signature using ML-DSA-65.
func (v *MLDSAVerifier) VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error) {
	if i.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload := CanonicalizeIntent(i.ID, i.DecisionID, i.AllowedTool)
	sig, err := hex.DecodeString(i.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}
	return mldsa65.Verify(v.publicKey, []byte(payload), nil, sig), nil
}

// VerifyReceipt verifies a Receipt signature using ML-DSA-65.
func (v *MLDSAVerifier) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	if r.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload := CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}
	return mldsa65.Verify(v.publicKey, []byte(payload), nil, sig), nil
}

// VerifyMLDSA65 verifies a hex-encoded ML-DSA-65 signature against a hex-encoded public key.
// This is the ML-DSA-65 counterpart to the package-level Verify function for Ed25519.
func VerifyMLDSA65(pubKeyHex, sigHex string, data []byte) (bool, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key hex: %w", err)
	}

	v, err := NewMLDSAVerifier(pubKeyBytes)
	if err != nil {
		return false, err
	}

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}

	return v.Verify(data, sig), nil
}
