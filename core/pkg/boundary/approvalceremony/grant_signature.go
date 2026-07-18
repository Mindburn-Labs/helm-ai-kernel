package approvalceremony

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

const (
	approvalGrantSignatureDomainV1             = "HELM/ApprovalGrantSignature/v1"
	approvalGrantConsumptionSignatureDomainV1  = "HELM/ApprovalGrantConsumptionSignature/v1"
	approvalDispatchAdmissionSignatureDomainV1 = "HELM/ApprovalDispatchAdmissionSignature/v1"
)

var ErrGrantSignatureRejected = errors.New("approval ceremony grant signature rejected")

// GrantSignatureVerifier is the pinned Kernel trust-root check required before
// a durable ceremony may enter GRANT_ISSUED or persist a consumption record.
type GrantSignatureVerifier interface {
	VerifyGrantSignature(contracts.ApprovalGrant, string, string) error
	VerifyGrantConsumptionSignature(contracts.ApprovalGrantConsumption, string, string) error
	VerifyDispatchAdmissionSignature(contracts.ApprovalDispatchAdmission, string, string) error
	VerifyEffectCloseReceiptSignature(contracts.EffectCloseReceipt, string, string) error
	VerifyEffectDispositionReceiptSignature(contracts.EffectDispositionReceipt, string, string) error
}

type Ed25519GrantSignatureVerifier struct {
	publicKey         ed25519.PublicKey
	signingKeyRef     string
	kernelTrustRootID string
}

func NewEd25519GrantSignatureVerifier(publicKey []byte, signingKeyRef, kernelTrustRootID string) (*Ed25519GrantSignatureVerifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid public key size", ErrGrantSignatureRejected)
	}
	if !validToken(signingKeyRef) || !validToken(kernelTrustRootID) {
		return nil, fmt.Errorf("%w: signing key ref and trust root are required", ErrGrantSignatureRejected)
	}
	return &Ed25519GrantSignatureVerifier{
		publicKey: append(ed25519.PublicKey(nil), publicKey...), signingKeyRef: signingKeyRef,
		kernelTrustRootID: kernelTrustRootID,
	}, nil
}

func (v *Ed25519GrantSignatureVerifier) VerifyGrantSignature(grant contracts.ApprovalGrant, algorithm, signature string) error {
	if v == nil || len(v.publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	if algorithm != GrantSignatureEd25519 || grant.SigningKeyRef != v.signingKeyRef || grant.KernelTrustRootID != v.kernelTrustRootID {
		return fmt.Errorf("%w: trust-root metadata mismatch", ErrGrantSignatureRejected)
	}
	payload, err := ApprovalGrantSigningPayload(grant, algorithm)
	if err != nil {
		return err
	}
	rawSignature, err := hex.DecodeString(signature)
	if err != nil || len(rawSignature) != ed25519.SignatureSize || hex.EncodeToString(rawSignature) != signature {
		return fmt.Errorf("%w: signature encoding is invalid", ErrGrantSignatureRejected)
	}
	if !ed25519.Verify(v.publicKey, payload, rawSignature) {
		return fmt.Errorf("%w: bad ed25519 signature", ErrGrantSignatureRejected)
	}
	return nil
}

func (v *Ed25519GrantSignatureVerifier) VerifyGrantConsumptionSignature(consumption contracts.ApprovalGrantConsumption, algorithm, signature string) error {
	if v == nil || len(v.publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	if algorithm != GrantSignatureEd25519 || consumption.SigningKeyRef != v.signingKeyRef ||
		consumption.KernelTrustRootID != v.kernelTrustRootID {
		return fmt.Errorf("%w: consumption trust-root metadata mismatch", ErrGrantSignatureRejected)
	}
	payload, err := ApprovalGrantConsumptionSigningPayload(consumption, algorithm)
	if err != nil {
		return err
	}
	rawSignature, err := hex.DecodeString(signature)
	if err != nil || len(rawSignature) != ed25519.SignatureSize || hex.EncodeToString(rawSignature) != signature {
		return fmt.Errorf("%w: consumption signature encoding is invalid", ErrGrantSignatureRejected)
	}
	if !ed25519.Verify(v.publicKey, payload, rawSignature) {
		return fmt.Errorf("%w: bad consumption ed25519 signature", ErrGrantSignatureRejected)
	}
	return nil
}

func (v *Ed25519GrantSignatureVerifier) VerifyDispatchAdmissionSignature(admission contracts.ApprovalDispatchAdmission, algorithm, signature string) error {
	if v == nil || len(v.publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	if algorithm != GrantSignatureEd25519 || admission.SigningKeyRef != v.signingKeyRef ||
		admission.KernelTrustRootID != v.kernelTrustRootID {
		return fmt.Errorf("%w: dispatch admission trust-root metadata mismatch", ErrGrantSignatureRejected)
	}
	payload, err := ApprovalDispatchAdmissionSigningPayload(admission, algorithm)
	if err != nil {
		return err
	}
	rawSignature, err := hex.DecodeString(signature)
	if err != nil || len(rawSignature) != ed25519.SignatureSize || hex.EncodeToString(rawSignature) != signature {
		return fmt.Errorf("%w: dispatch admission signature encoding is invalid", ErrGrantSignatureRejected)
	}
	if !ed25519.Verify(v.publicKey, payload, rawSignature) {
		return fmt.Errorf("%w: bad dispatch admission ed25519 signature", ErrGrantSignatureRejected)
	}
	return nil
}

func (v *Ed25519GrantSignatureVerifier) VerifyEffectCloseReceiptSignature(receipt contracts.EffectCloseReceipt, algorithm, signature string) error {
	if v == nil || len(v.publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	if algorithm != GrantSignatureEd25519 || receipt.SigningKeyRef != v.signingKeyRef ||
		receipt.KernelTrustRootID != v.kernelTrustRootID {
		return fmt.Errorf("%w: effect close receipt trust-root metadata mismatch", ErrGrantSignatureRejected)
	}
	payload, err := EffectCloseReceiptSigningPayload(receipt, algorithm)
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

func (v *Ed25519GrantSignatureVerifier) VerifyEffectDispositionReceiptSignature(receipt contracts.EffectDispositionReceipt, algorithm, signature string) error {
	if v == nil || len(v.publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	if algorithm != GrantSignatureEd25519 || receipt.SigningKeyRef != v.signingKeyRef ||
		receipt.KernelTrustRootID != v.kernelTrustRootID {
		return fmt.Errorf("%w: effect disposition receipt trust-root metadata mismatch", ErrGrantSignatureRejected)
	}
	payload, err := EffectDispositionReceiptSigningPayload(receipt, algorithm)
	if err != nil {
		return err
	}
	rawSignature, err := hex.DecodeString(signature)
	if err != nil || len(rawSignature) != ed25519.SignatureSize || hex.EncodeToString(rawSignature) != signature {
		return fmt.Errorf("%w: effect disposition receipt signature encoding is invalid", ErrGrantSignatureRejected)
	}
	if !ed25519.Verify(v.publicKey, payload, rawSignature) {
		return fmt.Errorf("%w: bad effect disposition receipt ed25519 signature", ErrGrantSignatureRejected)
	}
	return nil
}

// ApprovalGrantSigningPayload binds the exact sealed grant and the declared
// trust-root metadata under a dedicated domain. It is not a permit and cannot
// be executed without durable single-use consumption.
func ApprovalGrantSigningPayload(grant contracts.ApprovalGrant, algorithm string) ([]byte, error) {
	if algorithm != GrantSignatureEd25519 {
		return nil, fmt.Errorf("%w: unsupported algorithm", ErrGrantSignatureRejected)
	}
	if grant.GrantHash == "" {
		return nil, fmt.Errorf("%w: grant_hash is required", ErrGrantSignatureRejected)
	}
	sealed, err := grant.Seal()
	if err != nil || sealed.GrantHash != grant.GrantHash {
		return nil, fmt.Errorf("%w: grant integrity mismatch", ErrGrantSignatureRejected)
	}
	payload, err := canonicalize.JCS(struct {
		Domain            string `json:"domain"`
		ContractVersion   string `json:"contract_version"`
		GrantHash         string `json:"grant_hash"`
		KernelTrustRootID string `json:"kernel_trust_root_id"`
		SigningKeyRef     string `json:"signing_key_ref"`
		Algorithm         string `json:"algorithm"`
	}{
		Domain: approvalGrantSignatureDomainV1, ContractVersion: grant.ContractVersion,
		GrantHash: grant.GrantHash, KernelTrustRootID: grant.KernelTrustRootID,
		SigningKeyRef: grant.SigningKeyRef, Algorithm: algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize signing payload: %v", ErrGrantSignatureRejected, err)
	}
	return payload, nil
}

func SignApprovalGrant(grant contracts.ApprovalGrant, signer crypto.Signer) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("%w: signer is not configured", ErrGrantSignatureRejected)
	}
	payload, err := ApprovalGrantSigningPayload(grant, GrantSignatureEd25519)
	if err != nil {
		return "", err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("%w: sign grant: %v", ErrGrantSignatureRejected, err)
	}
	if !validEd25519Signature(signature) {
		return "", fmt.Errorf("%w: signer returned invalid signature", ErrGrantSignatureRejected)
	}
	return signature, nil
}

func ApprovalGrantConsumptionSigningPayload(consumption contracts.ApprovalGrantConsumption, algorithm string) ([]byte, error) {
	if algorithm != GrantSignatureEd25519 {
		return nil, fmt.Errorf("%w: unsupported consumption algorithm", ErrGrantSignatureRejected)
	}
	if consumption.ConsumptionHash == "" {
		return nil, fmt.Errorf("%w: consumption_hash is required", ErrGrantSignatureRejected)
	}
	sealed, err := consumption.Seal()
	if err != nil || sealed.ConsumptionHash != consumption.ConsumptionHash {
		return nil, fmt.Errorf("%w: consumption integrity mismatch", ErrGrantSignatureRejected)
	}
	payload, err := canonicalize.JCS(struct {
		Domain            string `json:"domain"`
		ContractVersion   string `json:"contract_version"`
		ConsumptionHash   string `json:"consumption_hash"`
		KernelTrustRootID string `json:"kernel_trust_root_id"`
		SigningKeyRef     string `json:"signing_key_ref"`
		Algorithm         string `json:"algorithm"`
	}{
		Domain: approvalGrantConsumptionSignatureDomainV1, ContractVersion: consumption.ContractVersion,
		ConsumptionHash: consumption.ConsumptionHash, KernelTrustRootID: consumption.KernelTrustRootID,
		SigningKeyRef: consumption.SigningKeyRef, Algorithm: algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize consumption signing payload: %v", ErrGrantSignatureRejected, err)
	}
	return payload, nil
}

func SignApprovalGrantConsumption(consumption contracts.ApprovalGrantConsumption, signer crypto.Signer) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("%w: signer is not configured", ErrGrantSignatureRejected)
	}
	payload, err := ApprovalGrantConsumptionSigningPayload(consumption, GrantSignatureEd25519)
	if err != nil {
		return "", err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("%w: sign consumption: %v", ErrGrantSignatureRejected, err)
	}
	if !validEd25519Signature(signature) {
		return "", fmt.Errorf("%w: signer returned invalid consumption signature", ErrGrantSignatureRejected)
	}
	return signature, nil
}

func ApprovalDispatchAdmissionSigningPayload(admission contracts.ApprovalDispatchAdmission, algorithm string) ([]byte, error) {
	if algorithm != GrantSignatureEd25519 {
		return nil, fmt.Errorf("%w: unsupported dispatch admission algorithm", ErrGrantSignatureRejected)
	}
	if err := admission.ValidateIntegrity(); err != nil {
		return nil, fmt.Errorf("%w: dispatch admission integrity mismatch: %v", ErrGrantSignatureRejected, err)
	}
	payload, err := canonicalize.JCS(struct {
		Domain            string `json:"domain"`
		ContractVersion   string `json:"contract_version"`
		AdmissionHash     string `json:"admission_hash"`
		KernelTrustRootID string `json:"kernel_trust_root_id"`
		SigningKeyRef     string `json:"signing_key_ref"`
		Algorithm         string `json:"algorithm"`
	}{
		Domain: approvalDispatchAdmissionSignatureDomainV1, ContractVersion: admission.ContractVersion,
		AdmissionHash: admission.AdmissionHash, KernelTrustRootID: admission.KernelTrustRootID,
		SigningKeyRef: admission.SigningKeyRef, Algorithm: algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize dispatch admission signing payload: %v", ErrGrantSignatureRejected, err)
	}
	return payload, nil
}

func SignApprovalDispatchAdmission(admission contracts.ApprovalDispatchAdmission, signer crypto.Signer) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("%w: signer is not configured", ErrGrantSignatureRejected)
	}
	payload, err := ApprovalDispatchAdmissionSigningPayload(admission, GrantSignatureEd25519)
	if err != nil {
		return "", err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("%w: sign dispatch admission: %v", ErrGrantSignatureRejected, err)
	}
	if !validEd25519Signature(signature) {
		return "", fmt.Errorf("%w: signer returned invalid dispatch admission signature", ErrGrantSignatureRejected)
	}
	return signature, nil
}
