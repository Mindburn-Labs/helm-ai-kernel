// quantum_posture: GeneratedSpec approval grant and consumption signatures are
// classical Ed25519 only. No hybrid or post-quantum compatibility is implied.
package generatedspecapproval

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

const (
	SignatureAlgorithmEd25519    = "ed25519"
	grantSignatureDomainV1       = "HELM/GeneratedSpecApprovalGrantSignature/v1"
	consumptionSignatureDomainV1 = "HELM/GeneratedSpecApprovalConsumptionSignature/v1"
)

var ErrSignatureRejected = errors.New("generated spec approval signature rejected")

// SignedGrant is the transport envelope for a sealed Kernel-issued grant. A
// receiver must validate its lifetime, verify the pinned signature, and still
// use a durable single-use transition before treating it as approval evidence.
type SignedGrant struct {
	Grant     contracts.GeneratedSpecApprovalGrant `json:"grant"`
	Algorithm string                               `json:"algorithm"`
	Signature string                               `json:"signature"`
}

// SignedConsumption is the transport envelope for the durable consume event.
type SignedConsumption struct {
	Consumption contracts.GeneratedSpecApprovalConsumption `json:"consumption"`
	Algorithm   string                                     `json:"algorithm"`
	Signature   string                                     `json:"signature"`
}

// Ed25519Verifier pins one Kernel signing public key and trust-root metadata.
// Deployments rotate this verifier by installing a new source-owned key set;
// callers must not accept arbitrary keys sent alongside a grant.
type Ed25519Verifier struct {
	publicKey         ed25519.PublicKey
	signingKeyRef     string
	kernelTrustRootID string
}

func NewEd25519Verifier(publicKey []byte, signingKeyRef, kernelTrustRootID string) (*Ed25519Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid public key size", ErrSignatureRejected)
	}
	if signingKeyRef == "" || kernelTrustRootID == "" {
		return nil, fmt.Errorf("%w: signing key ref and trust root are required", ErrSignatureRejected)
	}
	return &Ed25519Verifier{
		publicKey: append(ed25519.PublicKey(nil), publicKey...), signingKeyRef: signingKeyRef,
		kernelTrustRootID: kernelTrustRootID,
	}, nil
}

func SignGrant(grant contracts.GeneratedSpecApprovalGrant, signer crypto.Signer) (SignedGrant, error) {
	if signer == nil {
		return SignedGrant{}, fmt.Errorf("%w: signer is not configured", ErrSignatureRejected)
	}
	payload, err := GrantSigningPayload(grant, SignatureAlgorithmEd25519)
	if err != nil {
		return SignedGrant{}, err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return SignedGrant{}, fmt.Errorf("%w: sign grant: %v", ErrSignatureRejected, err)
	}
	if !validSignature(signature) {
		return SignedGrant{}, fmt.Errorf("%w: signer returned invalid signature", ErrSignatureRejected)
	}
	return SignedGrant{Grant: grant, Algorithm: SignatureAlgorithmEd25519, Signature: signature}, nil
}

func SignConsumption(consumption contracts.GeneratedSpecApprovalConsumption, signer crypto.Signer) (SignedConsumption, error) {
	if signer == nil {
		return SignedConsumption{}, fmt.Errorf("%w: signer is not configured", ErrSignatureRejected)
	}
	payload, err := ConsumptionSigningPayload(consumption, SignatureAlgorithmEd25519)
	if err != nil {
		return SignedConsumption{}, err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return SignedConsumption{}, fmt.Errorf("%w: sign consumption: %v", ErrSignatureRejected, err)
	}
	if !validSignature(signature) {
		return SignedConsumption{}, fmt.Errorf("%w: signer returned invalid signature", ErrSignatureRejected)
	}
	return SignedConsumption{Consumption: consumption, Algorithm: SignatureAlgorithmEd25519, Signature: signature}, nil
}

func (v *Ed25519Verifier) VerifyGrant(signed SignedGrant, now time.Time) error {
	if err := signed.Grant.ValidateAt(now); err != nil {
		return fmt.Errorf("%w: grant: %v", ErrSignatureRejected, err)
	}
	return v.VerifyGrantSignature(signed)
}

func (v *Ed25519Verifier) VerifyGrantSignature(signed SignedGrant) error {
	if v == nil || len(v.publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: verifier is not configured", ErrSignatureRejected)
	}
	if signed.Algorithm != SignatureAlgorithmEd25519 || signed.Grant.SigningKeyRef != v.signingKeyRef || signed.Grant.KernelTrustRootID != v.kernelTrustRootID {
		return fmt.Errorf("%w: trust-root metadata mismatch", ErrSignatureRejected)
	}
	payload, err := GrantSigningPayload(signed.Grant, signed.Algorithm)
	if err != nil {
		return err
	}
	if !verify(v.publicKey, payload, signed.Signature) {
		return fmt.Errorf("%w: bad grant ed25519 signature", ErrSignatureRejected)
	}
	return nil
}

func (v *Ed25519Verifier) VerifyConsumption(signed SignedConsumption, grant SignedGrant) error {
	if v == nil || len(v.publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: verifier is not configured", ErrSignatureRejected)
	}
	if err := v.VerifyGrantSignature(grant); err != nil {
		return fmt.Errorf("%w: source grant: %v", ErrSignatureRejected, err)
	}
	if err := signed.Consumption.ValidateGrant(grant.Grant); err != nil {
		return fmt.Errorf("%w: consumption grant projection: %v", ErrSignatureRejected, err)
	}
	if signed.Algorithm != SignatureAlgorithmEd25519 || signed.Consumption.SigningKeyRef != v.signingKeyRef || signed.Consumption.KernelTrustRootID != v.kernelTrustRootID {
		return fmt.Errorf("%w: consumption trust-root metadata mismatch", ErrSignatureRejected)
	}
	payload, err := ConsumptionSigningPayload(signed.Consumption, signed.Algorithm)
	if err != nil {
		return err
	}
	if !verify(v.publicKey, payload, signed.Signature) {
		return fmt.Errorf("%w: bad consumption ed25519 signature", ErrSignatureRejected)
	}
	return nil
}

func GrantSigningPayload(grant contracts.GeneratedSpecApprovalGrant, algorithm string) ([]byte, error) {
	if algorithm != SignatureAlgorithmEd25519 {
		return nil, fmt.Errorf("%w: unsupported algorithm", ErrSignatureRejected)
	}
	if grant.GrantHash == "" {
		return nil, fmt.Errorf("%w: grant_hash is required", ErrSignatureRejected)
	}
	sealed, err := grant.Seal()
	if err != nil || sealed.GrantHash != grant.GrantHash {
		return nil, fmt.Errorf("%w: grant integrity mismatch", ErrSignatureRejected)
	}
	payload, err := canonicalize.JCS(struct {
		Domain            string `json:"domain"`
		ContractVersion   string `json:"contract_version"`
		GrantHash         string `json:"grant_hash"`
		KernelTrustRootID string `json:"kernel_trust_root_id"`
		SigningKeyRef     string `json:"signing_key_ref"`
		Algorithm         string `json:"algorithm"`
	}{
		Domain: grantSignatureDomainV1, ContractVersion: grant.ContractVersion, GrantHash: grant.GrantHash,
		KernelTrustRootID: grant.KernelTrustRootID, SigningKeyRef: grant.SigningKeyRef, Algorithm: algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize grant signing payload: %v", ErrSignatureRejected, err)
	}
	return payload, nil
}

func ConsumptionSigningPayload(consumption contracts.GeneratedSpecApprovalConsumption, algorithm string) ([]byte, error) {
	if algorithm != SignatureAlgorithmEd25519 {
		return nil, fmt.Errorf("%w: unsupported algorithm", ErrSignatureRejected)
	}
	if consumption.ConsumptionHash == "" {
		return nil, fmt.Errorf("%w: consumption_hash is required", ErrSignatureRejected)
	}
	sealed, err := consumption.Seal()
	if err != nil || sealed.ConsumptionHash != consumption.ConsumptionHash {
		return nil, fmt.Errorf("%w: consumption integrity mismatch", ErrSignatureRejected)
	}
	payload, err := canonicalize.JCS(struct {
		Domain            string `json:"domain"`
		ContractVersion   string `json:"contract_version"`
		ConsumptionHash   string `json:"consumption_hash"`
		KernelTrustRootID string `json:"kernel_trust_root_id"`
		SigningKeyRef     string `json:"signing_key_ref"`
		Algorithm         string `json:"algorithm"`
	}{
		Domain: consumptionSignatureDomainV1, ContractVersion: consumption.ContractVersion,
		ConsumptionHash: consumption.ConsumptionHash, KernelTrustRootID: consumption.KernelTrustRootID,
		SigningKeyRef: consumption.SigningKeyRef, Algorithm: algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize consumption signing payload: %v", ErrSignatureRejected, err)
	}
	return payload, nil
}

func verify(publicKey ed25519.PublicKey, payload []byte, signature string) bool {
	if !validSignature(signature) {
		return false
	}
	raw, _ := hex.DecodeString(signature)
	return ed25519.Verify(publicKey, payload, raw)
}

func validSignature(signature string) bool {
	if len(signature) != ed25519.SignatureSize*2 {
		return false
	}
	decoded, err := hex.DecodeString(signature)
	return err == nil && len(decoded) == ed25519.SignatureSize && hex.EncodeToString(decoded) == signature
}
