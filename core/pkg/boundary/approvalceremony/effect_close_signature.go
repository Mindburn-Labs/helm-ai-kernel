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
	connectorEffectAcknowledgementSignatureDomainV1 = "HELM/ConnectorEffectAcknowledgementSignature/v1"
	effectCloseReceiptSignatureDomainV1             = "HELM/EffectCloseReceiptSignature/v1"
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

func NewEd25519EffectAcknowledgementVerifier(keys []TrustedEffectAcknowledgementKey) (*Ed25519EffectAcknowledgementVerifier, error) {
	if len(keys) == 0 {
		return nil, effectAcknowledgementRejected("at least one pinned key is required")
	}
	trusted := make(map[string]TrustedEffectAcknowledgementKey, len(keys))
	for _, key := range keys {
		if !validToken(key.IssuerID) || !validToken(key.SigningKeyRef) ||
			!validToken(key.ConnectorID) || !validToken(key.ConnectorVersion) ||
			len(key.PublicKey) != ed25519.PublicKeySize || key.NotBefore.IsZero() || key.NotAfter.IsZero() ||
			key.NotBefore.Location() != time.UTC || key.NotAfter.Location() != time.UTC || !key.NotAfter.After(key.NotBefore) {
			return nil, effectAcknowledgementRejected("pinned key metadata is invalid")
		}
		identity := effectAcknowledgementKeyIdentity(key.IssuerID, key.SigningKeyRef, key.ConnectorID, key.ConnectorVersion)
		if _, exists := trusted[identity]; exists {
			return nil, effectAcknowledgementRejected("duplicate pinned acknowledgement key")
		}
		key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
		trusted[identity] = key
	}
	return &Ed25519EffectAcknowledgementVerifier{keys: trusted}, nil
}

func ConnectorEffectAcknowledgementSigningPayload(acknowledgement contracts.ConnectorEffectAcknowledgement) ([]byte, error) {
	if err := acknowledgement.ValidateIntegrity(); err != nil {
		return nil, effectAcknowledgementRejected("acknowledgement integrity mismatch: " + err.Error())
	}
	payload, err := canonicalize.JCS(struct {
		Domain              string `json:"domain"`
		ContractVersion     string `json:"contract_version"`
		AcknowledgementHash string `json:"acknowledgement_hash"`
		IssuerID            string `json:"issuer_id"`
		SigningKeyRef       string `json:"signing_key_ref"`
		ConnectorID         string `json:"connector_id"`
		ConnectorVersion    string `json:"connector_version"`
		Algorithm           string `json:"algorithm"`
	}{
		Domain:              connectorEffectAcknowledgementSignatureDomainV1,
		ContractVersion:     acknowledgement.ContractVersion,
		AcknowledgementHash: acknowledgement.AcknowledgementHash,
		IssuerID:            acknowledgement.IssuerID, SigningKeyRef: acknowledgement.SigningKeyRef,
		ConnectorID: acknowledgement.ConnectorID, ConnectorVersion: acknowledgement.ConnectorVersion,
		Algorithm: acknowledgement.Algorithm,
	})
	if err != nil {
		return nil, effectAcknowledgementRejected("canonicalize signing payload: " + err.Error())
	}
	return payload, nil
}

func SignConnectorEffectAcknowledgement(
	acknowledgement contracts.ConnectorEffectAcknowledgement,
	signer crypto.Signer,
) (contracts.ConnectorEffectAcknowledgementEnvelope, error) {
	if signer == nil {
		return contracts.ConnectorEffectAcknowledgementEnvelope{}, effectAcknowledgementRejected("signer is not configured")
	}
	payload, err := ConnectorEffectAcknowledgementSigningPayload(acknowledgement)
	if err != nil {
		return contracts.ConnectorEffectAcknowledgementEnvelope{}, err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return contracts.ConnectorEffectAcknowledgementEnvelope{}, effectAcknowledgementRejected("sign acknowledgement: " + err.Error())
	}
	envelope := contracts.ConnectorEffectAcknowledgementEnvelope{Acknowledgement: acknowledgement, Signature: signature}
	if err := envelope.Validate(); err != nil {
		return contracts.ConnectorEffectAcknowledgementEnvelope{}, effectAcknowledgementRejected("signer returned invalid signature encoding")
	}
	return envelope, nil
}

func (v *Ed25519EffectAcknowledgementVerifier) VerifyEnvelope(envelope contracts.ConnectorEffectAcknowledgementEnvelope) error {
	if v == nil || len(v.keys) == 0 {
		return effectAcknowledgementRejected("verifier is not configured")
	}
	if err := envelope.Validate(); err != nil {
		return effectAcknowledgementRejected(err.Error())
	}
	a := envelope.Acknowledgement
	identity := effectAcknowledgementKeyIdentity(a.IssuerID, a.SigningKeyRef, a.ConnectorID, a.ConnectorVersion)
	key, ok := v.keys[identity]
	if !ok || !key.Enabled {
		return effectAcknowledgementRejected("signing key is not currently trusted for this connector release")
	}
	if a.ObservedAt.Before(key.NotBefore) || !a.ObservedAt.Before(key.NotAfter) {
		return effectAcknowledgementRejected("acknowledgement was observed outside the pinned key lifetime")
	}
	payload, err := ConnectorEffectAcknowledgementSigningPayload(a)
	if err != nil {
		return err
	}
	raw, err := hex.DecodeString(envelope.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(key.PublicKey, payload, raw) {
		return effectAcknowledgementRejected("bad Ed25519 signature")
	}
	return nil
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

func SignEffectCloseReceipt(receipt contracts.EffectCloseReceipt, signer crypto.Signer) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("%w: signer is not configured", ErrGrantSignatureRejected)
	}
	payload, err := EffectCloseReceiptSigningPayload(receipt, GrantSignatureEd25519)
	if err != nil {
		return "", err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("%w: sign effect close receipt: %v", ErrGrantSignatureRejected, err)
	}
	if !validEd25519Signature(signature) {
		return "", fmt.Errorf("%w: signer returned invalid effect close receipt signature", ErrGrantSignatureRejected)
	}
	return signature, nil
}

func effectAcknowledgementKeyIdentity(issuerID, signingKeyRef, connectorID, connectorVersion string) string {
	return issuerID + "\x00" + signingKeyRef + "\x00" + connectorID + "\x00" + connectorVersion
}

func effectAcknowledgementRejected(message string) error {
	return fmt.Errorf("%w: %s", ErrEffectAcknowledgementRejected, message)
}
