// quantum_posture: workstation signer trust verification uses classical
// Ed25519 public keys only; this trust set does not add post-quantum or hybrid
// cryptographic protection.
package workstation

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// TrustedSignerSet is a caller-owned set of approved receipt signer keys. It
// deliberately contains public keys only; receipt integrity remains a separate
// check against the key declared by each receipt.
type TrustedSignerSet struct {
	keys map[string]ed25519.PublicKey
}

// NewTrustedSignerSet validates an explicit signer allowlist. Verification
// permanently rejects the retired source-derived signer even if a caller keeps
// it in a migration-era file, so old receipts can still report integrity.
func NewTrustedSignerSet(keys []ed25519.PublicKey) (TrustedSignerSet, error) {
	if len(keys) == 0 {
		return TrustedSignerSet{}, errors.New("at least one trusted signer key is required")
	}
	trusted := TrustedSignerSet{keys: make(map[string]ed25519.PublicKey, len(keys))}
	for _, key := range keys {
		if len(key) != ed25519.PublicKeySize {
			return TrustedSignerSet{}, fmt.Errorf("trusted signer key must be %d bytes", ed25519.PublicKeySize)
		}
		keyID := ed25519SignerKeyID(key)
		if _, exists := trusted.keys[keyID]; exists {
			return TrustedSignerSet{}, errors.New("duplicate trusted signer key")
		}
		trusted.keys[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	return trusted, nil
}

func (trusted TrustedSignerSet) contains(keyID string) bool {
	_, ok := trusted.keys[keyID]
	return ok
}

// VerifyReceiptWithTrustedSigners verifies integrity only when the receipt's
// declared signer is explicitly present in the caller-owned trusted signer set.
func VerifyReceiptWithTrustedSigners(receipt *contracts.AgentRunReceipt, trusted TrustedSignerSet) (bool, error) {
	if receipt == nil {
		return false, errors.New("receipt is nil")
	}
	if receipt.SignerKeyID == retiredObserveOnlySignerKeyID {
		return false, nil
	}
	if !trusted.contains(receipt.SignerKeyID) {
		return false, nil
	}
	return VerifyReceiptSignature(receipt)
}

// VerifyDecisionReceiptWithTrustedSigners verifies integrity only when the
// decision receipt's signer is present in the caller-owned trust set.
func VerifyDecisionReceiptWithTrustedSigners(receipt *contracts.WorkstationPolicyDecisionReceipt, trusted TrustedSignerSet) (bool, error) {
	if receipt == nil {
		return false, errors.New("decision receipt is nil")
	}
	if receipt.SignerKeyID == retiredObserveOnlySignerKeyID {
		return false, nil
	}
	if !trusted.contains(receipt.SignerKeyID) {
		return false, nil
	}
	return VerifyDecisionReceiptSignature(receipt)
}
