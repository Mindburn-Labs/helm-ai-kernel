// quantum_posture: this is a classical Ed25519 verifier; no post-quantum
// protection is provided or claimed by this implementation.
package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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
	return &Ed25519Verifier{
		PublicKey: ed25519.PublicKey(pubKeyBytes),
	}, nil
}

// Verify checks a detached Ed25519 signature over message.
//
// As in package-level Verify, there is deliberately no result cache: the
// previous key was sha256(message ‖ signature) with no length framing, so an
// over-long message paired with a truncated signature collided with a genuine
// pair and inherited its cached `true` without ed25519.Verify running.
func (v *Ed25519Verifier) Verify(message []byte, signature []byte) bool {
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(v.PublicKey, message, signature)
}

func (v *Ed25519Verifier) VerifyDecision(d *contracts.DecisionRecord) (bool, error) {
	if d.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload, perr := DecisionVerifyPayload(d)
	if perr != nil {
		return false, perr
	}
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
	payload, err := CanonicalizeAuthorizedExecutionIntent(i)
	if err != nil {
		return false, err
	}
	sig, err := hex.DecodeString(i.Signature)
	if err != nil {
		return false, err
	}
	return v.Verify(payload, sig), nil
}

func (v *Ed25519Verifier) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	if r.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload, perr := ReceiptVerifyPayload(r)
	if perr != nil {
		return false, perr
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return false, err
	}
	return v.Verify([]byte(payload), sig), nil
}
