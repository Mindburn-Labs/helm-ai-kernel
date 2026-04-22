package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// Verifier defines the interface for signature verification.
type Verifier interface {
	Verify(message []byte, signature []byte) bool
	VerifyDecision(d *contracts.DecisionRecord) (bool, error)
	VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error)
	VerifyReceipt(r *contracts.Receipt) (bool, error)
}

// Ed25519Verifier implements Verifier using Ed25519.
type Ed25519Verifier struct {
	PublicKey ed25519.PublicKey
}

// NewEd25519Verifier creates a new verifier.
func NewEd25519Verifier(pubKeyBytes []byte) (*Ed25519Verifier, error) {
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(pubKeyBytes))
	}
	return &Ed25519Verifier{PublicKey: ed25519.PublicKey(pubKeyBytes)}, nil
}

func (v *Ed25519Verifier) Verify(message []byte, signature []byte) bool {
	return ed25519.Verify(v.PublicKey, message, signature)
}

func (v *Ed25519Verifier) VerifyDecision(d *contracts.DecisionRecord) (bool, error) {
	if d.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload := CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
	sig, err := hex.DecodeString(d.Signature)
	if err != nil {
		return false, err
	}
	return v.Verify([]byte(payload), sig), nil
}

func (v *Ed25519Verifier) VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error) {
	if i.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload := CanonicalizeIntent(i.ID, i.DecisionID, i.AllowedTool)
	sig, err := hex.DecodeString(i.Signature)
	if err != nil {
		return false, err
	}
	return v.Verify([]byte(payload), sig), nil
}

func (v *Ed25519Verifier) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	if r.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload := CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return false, err
	}
	return v.Verify([]byte(payload), sig), nil
}
