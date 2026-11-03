package approvalceremony

// quantum_posture: classical Ed25519 effect-close v3 signing and verification;
// no hybrid or post-quantum claim.

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	connectorEffectAcknowledgementSignatureDomainV3 = "HELM/ConnectorEffectAcknowledgementSignature/v3"
	effectCloseReceiptSignatureDomainV3             = "HELM/EffectCloseReceiptSignature/v3"
)

func EffectCloseReceiptV3SigningPayload(receipt contracts.EffectCloseReceiptV3, algorithm string) ([]byte, error) {
	if algorithm != GrantSignatureEd25519 {
		return nil, fmt.Errorf("%w: unsupported effect close receipt algorithm", ErrGrantSignatureRejected)
	}
	if err := receipt.ValidateIntegrity(); err != nil {
		return nil, fmt.Errorf("%w: effect close receipt integrity mismatch: %v", ErrGrantSignatureRejected, err)
	}
	payload, err := canonicalize.JCS(struct {
		Domain                 string `json:"domain"`
		ContractVersion        string `json:"contract_version"`
		ReceiptHash            string `json:"receipt_hash"`
		ActivationRecordHash   string `json:"activation_record_hash"`
		AdapterCapabilityHash  string `json:"adapter_capability_hash"`
		DispositionReceiptHash string `json:"disposition_receipt_hash,omitempty"`
		KernelTrustRootID      string `json:"kernel_trust_root_id"`
		SigningKeyRef          string `json:"signing_key_ref"`
		Algorithm              string `json:"algorithm"`
	}{
		Domain: effectCloseReceiptSignatureDomainV3, ContractVersion: receipt.ContractVersion,
		ReceiptHash: receipt.ReceiptHash, ActivationRecordHash: receipt.ActivationRecordHash,
		AdapterCapabilityHash:  receipt.AdapterCapabilityHash,
		DispositionReceiptHash: receipt.DispositionReceiptHash,
		KernelTrustRootID:      receipt.KernelTrustRootID, SigningKeyRef: receipt.SigningKeyRef, Algorithm: algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize effect close receipt signing payload: %v", ErrGrantSignatureRejected, err)
	}
	return payload, nil
}

func (v *Ed25519GrantSignatureVerifier) VerifyEffectCloseReceiptV3Signature(
	receipt contracts.EffectCloseReceiptV3,
	algorithm, signature string,
) error {
	if v == nil || len(v.publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	if algorithm != GrantSignatureEd25519 || receipt.SigningKeyRef != v.signingKeyRef ||
		receipt.KernelTrustRootID != v.kernelTrustRootID {
		return fmt.Errorf("%w: effect close receipt trust-root metadata mismatch", ErrGrantSignatureRejected)
	}
	payload, err := EffectCloseReceiptV3SigningPayload(receipt, algorithm)
	if err != nil {
		return err
	}
	rawSignature, err := hex.DecodeString(signature)
	if err != nil || len(rawSignature) != ed25519.SignatureSize || hex.EncodeToString(rawSignature) != signature {
		return fmt.Errorf("%w: effect close receipt signature encoding is invalid", ErrGrantSignatureRejected)
	}
	if !ed25519.Verify(v.publicKey, payload, rawSignature) {
		return fmt.Errorf("%w: bad effect close receipt ed25519 signature", ErrGrantSignatureRejected)
	}
	return nil
}
