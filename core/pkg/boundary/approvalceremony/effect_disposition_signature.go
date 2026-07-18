package approvalceremony

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
	effectDispositionCommandSignatureDomainV1 = "HELM/EffectDispositionCommandSignature/v1"
	effectDispositionReceiptSignatureDomainV1 = "HELM/EffectDispositionReceiptSignature/v1"
)

var ErrEffectDispositionCommandRejected = errors.New("effect disposition command rejected")

type TrustedEffectDispositionCommandKey struct {
	AuthorityID   string
	SigningKeyRef string
	Audience      string
	PublicKey     ed25519.PublicKey
	Enabled       bool
	NotBefore     time.Time
	NotAfter      time.Time
}

type EffectDispositionCommandVerifier interface {
	VerifyEnvelope(contracts.EffectDispositionCommandEnvelope) error
}

type Ed25519EffectDispositionCommandVerifier struct {
	keys map[string]TrustedEffectDispositionCommandKey
}

func NewEd25519EffectDispositionCommandVerifier(keys []TrustedEffectDispositionCommandKey) (*Ed25519EffectDispositionCommandVerifier, error) {
	if len(keys) == 0 {
		return nil, effectDispositionCommandRejected("at least one pinned key is required")
	}
	trusted := make(map[string]TrustedEffectDispositionCommandKey, len(keys))
	for _, key := range keys {
		if !validToken(key.AuthorityID) || !validToken(key.SigningKeyRef) || !validToken(key.Audience) ||
			len(key.PublicKey) != ed25519.PublicKeySize || key.NotBefore.IsZero() || key.NotAfter.IsZero() ||
			key.NotBefore.Location() != time.UTC || key.NotAfter.Location() != time.UTC || !key.NotAfter.After(key.NotBefore) {
			return nil, effectDispositionCommandRejected("pinned command key metadata is invalid")
		}
		identity := effectDispositionCommandKeyIdentity(key.AuthorityID, key.SigningKeyRef, key.Audience)
		if _, exists := trusted[identity]; exists {
			return nil, effectDispositionCommandRejected("duplicate pinned command key")
		}
		key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
		trusted[identity] = key
	}
	return &Ed25519EffectDispositionCommandVerifier{keys: trusted}, nil
}

func EffectDispositionCommandSigningPayload(command contracts.EffectDispositionCommand) ([]byte, error) {
	if err := command.ValidateIntegrity(); err != nil {
		return nil, effectDispositionCommandRejected("command integrity mismatch: " + err.Error())
	}
	payload, err := canonicalize.JCS(struct {
		Domain          string `json:"domain"`
		ContractVersion string `json:"contract_version"`
		CommandHash     string `json:"command_hash"`
		AuthorityID     string `json:"authority_id"`
		SigningKeyRef   string `json:"signing_key_ref"`
		Audience        string `json:"audience"`
		Algorithm       string `json:"algorithm"`
	}{
		Domain: effectDispositionCommandSignatureDomainV1, ContractVersion: command.ContractVersion,
		CommandHash: command.CommandHash, AuthorityID: command.AuthorityID,
		SigningKeyRef: command.SigningKeyRef, Audience: command.Audience, Algorithm: command.Algorithm,
	})
	if err != nil {
		return nil, effectDispositionCommandRejected("canonicalize command signing payload: " + err.Error())
	}
	return payload, nil
}

func SignEffectDispositionCommand(
	command contracts.EffectDispositionCommand,
	signer crypto.Signer,
) (contracts.EffectDispositionCommandEnvelope, error) {
	if signer == nil {
		return contracts.EffectDispositionCommandEnvelope{}, effectDispositionCommandRejected("signer is not configured")
	}
	payload, err := EffectDispositionCommandSigningPayload(command)
	if err != nil {
		return contracts.EffectDispositionCommandEnvelope{}, err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return contracts.EffectDispositionCommandEnvelope{}, effectDispositionCommandRejected("sign command: " + err.Error())
	}
	envelope := contracts.EffectDispositionCommandEnvelope{Command: command, Signature: signature}
	if err := envelope.Validate(); err != nil {
		return contracts.EffectDispositionCommandEnvelope{}, effectDispositionCommandRejected("signer returned invalid signature encoding")
	}
	return envelope, nil
}

func (v *Ed25519EffectDispositionCommandVerifier) VerifyEnvelope(envelope contracts.EffectDispositionCommandEnvelope) error {
	if v == nil || len(v.keys) == 0 {
		return effectDispositionCommandRejected("verifier is not configured")
	}
	if err := envelope.Validate(); err != nil {
		return effectDispositionCommandRejected(err.Error())
	}
	command := envelope.Command
	identity := effectDispositionCommandKeyIdentity(command.AuthorityID, command.SigningKeyRef, command.Audience)
	key, ok := v.keys[identity]
	if !ok || !key.Enabled {
		return effectDispositionCommandRejected("command key is not currently trusted for this authority and audience")
	}
	if command.IssuedAt.Before(key.NotBefore) || !command.IssuedAt.Before(key.NotAfter) {
		return effectDispositionCommandRejected("command was issued outside the pinned key lifetime")
	}
	payload, err := EffectDispositionCommandSigningPayload(command)
	if err != nil {
		return err
	}
	raw, err := hex.DecodeString(envelope.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(key.PublicKey, payload, raw) {
		return effectDispositionCommandRejected("bad Ed25519 signature")
	}
	return nil
}

func EffectDispositionReceiptSigningPayload(receipt contracts.EffectDispositionReceipt, algorithm string) ([]byte, error) {
	if algorithm != GrantSignatureEd25519 {
		return nil, fmt.Errorf("%w: unsupported effect disposition receipt algorithm", ErrGrantSignatureRejected)
	}
	if err := receipt.ValidateIntegrity(); err != nil {
		return nil, fmt.Errorf("%w: effect disposition receipt integrity mismatch: %v", ErrGrantSignatureRejected, err)
	}
	payload, err := canonicalize.JCS(struct {
		Domain            string `json:"domain"`
		ContractVersion   string `json:"contract_version"`
		ReceiptHash       string `json:"receipt_hash"`
		KernelTrustRootID string `json:"kernel_trust_root_id"`
		SigningKeyRef     string `json:"signing_key_ref"`
		Algorithm         string `json:"algorithm"`
	}{
		Domain: effectDispositionReceiptSignatureDomainV1, ContractVersion: receipt.ContractVersion,
		ReceiptHash: receipt.ReceiptHash, KernelTrustRootID: receipt.KernelTrustRootID,
		SigningKeyRef: receipt.SigningKeyRef, Algorithm: algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize effect disposition receipt signing payload: %v", ErrGrantSignatureRejected, err)
	}
	return payload, nil
}

func SignEffectDispositionReceipt(receipt contracts.EffectDispositionReceipt, signer crypto.Signer) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("%w: signer is not configured", ErrGrantSignatureRejected)
	}
	payload, err := EffectDispositionReceiptSigningPayload(receipt, GrantSignatureEd25519)
	if err != nil {
		return "", err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("%w: sign effect disposition receipt: %v", ErrGrantSignatureRejected, err)
	}
	if !validEd25519Signature(signature) {
		return "", fmt.Errorf("%w: signer returned invalid effect disposition receipt signature", ErrGrantSignatureRejected)
	}
	return signature, nil
}

func effectDispositionCommandKeyIdentity(authorityID, signingKeyRef, audience string) string {
	return authorityID + "\x00" + signingKeyRef + "\x00" + audience
}

func effectDispositionCommandRejected(message string) error {
	return fmt.Errorf("%w: %s", ErrEffectDispositionCommandRejected, message)
}
