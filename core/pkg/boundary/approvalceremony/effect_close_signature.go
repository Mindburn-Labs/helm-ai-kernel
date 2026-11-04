package approvalceremony

// quantum_posture: classical Ed25519 connector effect-close acknowledgement and
// receipt signing/verification only; no hybrid or post-quantum claim.

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	connectorEffectAcknowledgementSignatureDomainV1 = "HELM/ConnectorEffectAcknowledgementSignature/v1"
	connectorEffectAcknowledgementSignatureDomainV2 = "HELM/ConnectorEffectAcknowledgementSignature/v2"
	effectCloseReceiptSignatureDomainV1             = "HELM/EffectCloseReceiptSignature/v1"
	effectCloseReceiptSignatureDomainV2             = "HELM/EffectCloseReceiptSignature/v2"
)

var ErrEffectAcknowledgementRejected = errors.New("connector effect acknowledgement rejected")

// TrustedEffectAcknowledgementKey is deployment-pinned connector-runtime
// trust. The certified release still binds the issuer identity; this keyring
// provides the public key needed to verify its detached acknowledgements.
type TrustedEffectAcknowledgementKey struct {
	IssuerID         string
	SigningKeyRef    string
	ConnectorID      string
	ConnectorVersion string
	PublicKey        ed25519.PublicKey
	Enabled          bool
	NotBefore        time.Time
	NotAfter         time.Time
}

type Ed25519EffectAcknowledgementVerifier struct {
	keys map[string]TrustedEffectAcknowledgementKey
}

func EffectCloseReceiptSigningPayload(receipt contracts.EffectCloseReceipt, algorithm string) ([]byte, error) {
	if algorithm != GrantSignatureEd25519 {
		return nil, fmt.Errorf("%w: unsupported effect close receipt algorithm", ErrGrantSignatureRejected)
	}
	if err := receipt.ValidateIntegrity(); err != nil {
		return nil, fmt.Errorf("%w: effect close receipt integrity mismatch: %v", ErrGrantSignatureRejected, err)
	}
	payload, err := canonicalize.JCS(struct {
		Domain            string `json:"domain"`
		ContractVersion   string `json:"contract_version"`
		ReceiptHash       string `json:"receipt_hash"`
		KernelTrustRootID string `json:"kernel_trust_root_id"`
		SigningKeyRef     string `json:"signing_key_ref"`
		Algorithm         string `json:"algorithm"`
	}{
		Domain: effectCloseReceiptSignatureDomainV1, ContractVersion: receipt.ContractVersion,
		ReceiptHash: receipt.ReceiptHash, KernelTrustRootID: receipt.KernelTrustRootID,
		SigningKeyRef: receipt.SigningKeyRef, Algorithm: algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize effect close receipt signing payload: %v", ErrGrantSignatureRejected, err)
	}
	return payload, nil
}

func EffectCloseReceiptV2SigningPayload(receipt contracts.EffectCloseReceiptV2, algorithm string) ([]byte, error) {
	if algorithm != GrantSignatureEd25519 {
		return nil, fmt.Errorf("%w: unsupported effect close receipt algorithm", ErrGrantSignatureRejected)
	}
	if err := receipt.ValidateIntegrity(); err != nil {
		return nil, fmt.Errorf("%w: effect close receipt integrity mismatch: %v", ErrGrantSignatureRejected, err)
	}
	payload, err := canonicalize.JCS(struct {
		Domain                string `json:"domain"`
		ContractVersion       string `json:"contract_version"`
		ReceiptHash           string `json:"receipt_hash"`
		ActivationRecordHash  string `json:"activation_record_hash"`
		AdapterCapabilityHash string `json:"adapter_capability_hash"`
		KernelTrustRootID     string `json:"kernel_trust_root_id"`
		SigningKeyRef         string `json:"signing_key_ref"`
		Algorithm             string `json:"algorithm"`
	}{
		Domain: effectCloseReceiptSignatureDomainV2, ContractVersion: receipt.ContractVersion,
		ReceiptHash: receipt.ReceiptHash, ActivationRecordHash: receipt.ActivationRecordHash,
		AdapterCapabilityHash: receipt.AdapterCapabilityHash,
		KernelTrustRootID:     receipt.KernelTrustRootID, SigningKeyRef: receipt.SigningKeyRef, Algorithm: algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize effect close receipt signing payload: %v", ErrGrantSignatureRejected, err)
	}
	return payload, nil
}

func (v *Ed25519GrantSignatureVerifier) VerifyEffectCloseReceiptV2Signature(
	receipt contracts.EffectCloseReceiptV2,
	algorithm, signature string,
) error {
	if v == nil || len(v.publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	if algorithm != GrantSignatureEd25519 || receipt.SigningKeyRef != v.signingKeyRef ||
		receipt.KernelTrustRootID != v.kernelTrustRootID {
		return fmt.Errorf("%w: effect close receipt trust-root metadata mismatch", ErrGrantSignatureRejected)
	}
	payload, err := EffectCloseReceiptV2SigningPayload(receipt, algorithm)
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
