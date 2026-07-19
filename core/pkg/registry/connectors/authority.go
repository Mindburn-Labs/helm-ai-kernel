// quantum_posture: connector release authority verification uses classical
// Ed25519 keys only; no hybrid or post-quantum verification is claimed.
package connectors

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

const connectorReleaseAuthoritySignatureDomainV1 = "HELM/ConnectorReleaseAuthoritySignature/v1"

var ErrReleaseAuthorityRejected = errors.New("connector release authority rejected")

// TrustedReleaseAuthorityKey is deployment-pinned trust metadata. Historical
// keys may remain present for verification, but disabled keys cannot authorize
// newly loaded registry statements.
type TrustedReleaseAuthorityKey struct {
	AuthorityID   string
	SigningKeyRef string
	PublicKey     ed25519.PublicKey
	Enabled       bool
	NotBefore     time.Time
	NotAfter      time.Time
}

type Ed25519ReleaseAuthorityVerifier struct {
	authorityID string
	keys        map[string]TrustedReleaseAuthorityKey
}

func NewEd25519ReleaseAuthorityVerifier(authorityID string, keys []TrustedReleaseAuthorityKey) (*Ed25519ReleaseAuthorityVerifier, error) {
	if !releaseAuthorityToken(authorityID) || len(keys) == 0 {
		return nil, releaseAuthorityRejected("authority_id and at least one pinned key are required")
	}
	trusted := make(map[string]TrustedReleaseAuthorityKey, len(keys))
	for _, key := range keys {
		if key.AuthorityID != authorityID || !releaseAuthorityToken(key.SigningKeyRef) ||
			len(key.PublicKey) != ed25519.PublicKeySize || key.NotBefore.IsZero() || key.NotAfter.IsZero() ||
			key.NotBefore.Location() != time.UTC || key.NotAfter.Location() != time.UTC || !key.NotAfter.After(key.NotBefore) {
			return nil, releaseAuthorityRejected("pinned key metadata is invalid")
		}
		if _, exists := trusted[key.SigningKeyRef]; exists {
			return nil, releaseAuthorityRejected("duplicate signing_key_ref")
		}
		key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
		trusted[key.SigningKeyRef] = key
	}
	return &Ed25519ReleaseAuthorityVerifier{authorityID: authorityID, keys: trusted}, nil
}

// ConnectorReleaseAuthoritySigningPayload is the only signed representation
// of a sealed release-authority statement. JCS and a dedicated domain prevent
// cross-contract signature reuse.
func ConnectorReleaseAuthoritySigningPayload(authority contracts.ConnectorReleaseAuthority) ([]byte, error) {
	if err := authority.ValidateIntegrity(); err != nil {
		return nil, releaseAuthorityRejected("authority integrity mismatch: " + err.Error())
	}
	payload, err := canonicalize.JCS(struct {
		Domain           string `json:"domain"`
		ContractVersion  string `json:"contract_version"`
		AuthorityHash    string `json:"authority_hash"`
		AuthorityID      string `json:"authority_id"`
		SigningKeyRef    string `json:"signing_key_ref"`
		RegistryRevision uint64 `json:"registry_revision"`
		Algorithm        string `json:"algorithm"`
	}{
		Domain:           connectorReleaseAuthoritySignatureDomainV1,
		ContractVersion:  authority.ContractVersion,
		AuthorityHash:    authority.AuthorityHash,
		AuthorityID:      authority.AuthorityID,
		SigningKeyRef:    authority.SigningKeyRef,
		RegistryRevision: authority.RegistryRevision,
		Algorithm:        authority.Algorithm,
	})
	if err != nil {
		return nil, releaseAuthorityRejected("canonicalize signing payload: " + err.Error())
	}
	return payload, nil
}

func SignConnectorReleaseAuthority(authority contracts.ConnectorReleaseAuthority, signer crypto.Signer) (contracts.ConnectorReleaseAuthorityEnvelope, error) {
	if signer == nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, releaseAuthorityRejected("signer is not configured")
	}
	payload, err := ConnectorReleaseAuthoritySigningPayload(authority)
	if err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, releaseAuthorityRejected("sign authority: " + err.Error())
	}
	envelope := contracts.ConnectorReleaseAuthorityEnvelope{Authority: authority, Signature: signature}
	if err := envelope.Validate(); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, releaseAuthorityRejected("signer returned invalid signature encoding")
	}
	return envelope, nil
}

func (v *Ed25519ReleaseAuthorityVerifier) VerifyEnvelope(envelope contracts.ConnectorReleaseAuthorityEnvelope) error {
	if v == nil || !releaseAuthorityToken(v.authorityID) || len(v.keys) == 0 {
		return releaseAuthorityRejected("verifier is not configured")
	}
	if err := envelope.Validate(); err != nil {
		return releaseAuthorityRejected(err.Error())
	}
	authority := envelope.Authority
	if authority.AuthorityID != v.authorityID || authority.Algorithm != contracts.ConnectorReleaseAuthorityAlgorithmV1 {
		return releaseAuthorityRejected("authority identity or algorithm mismatch")
	}
	key, ok := v.keys[authority.SigningKeyRef]
	if !ok || !key.Enabled || key.AuthorityID != authority.AuthorityID {
		return releaseAuthorityRejected("signing key is not currently trusted")
	}
	if authority.SignedAt.Before(key.NotBefore) || !authority.SignedAt.Before(key.NotAfter) {
		return releaseAuthorityRejected("authority was signed outside the pinned key lifetime")
	}
	payload, err := ConnectorReleaseAuthoritySigningPayload(authority)
	if err != nil {
		return err
	}
	raw, err := hex.DecodeString(envelope.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(key.PublicKey, payload, raw) {
		return releaseAuthorityRejected("bad Ed25519 signature")
	}
	return nil
}

// VerifyCurrentCertifiedAt proves cryptographic provenance and local liveness.
// A durable store must additionally prove that no later revision exists.
func (v *Ed25519ReleaseAuthorityVerifier) VerifyCurrentCertifiedAt(envelope contracts.ConnectorReleaseAuthorityEnvelope, now time.Time) error {
	if err := v.VerifyEnvelope(envelope); err != nil {
		return err
	}
	if err := envelope.Authority.ValidateAt(now); err != nil {
		return releaseAuthorityRejected(err.Error())
	}
	return nil
}

func releaseAuthorityToken(value string) bool {
	return value != "" && len(value) <= 512 && strings.IndexFunc(value, unicode.IsSpace) == -1
}

func releaseAuthorityRejected(message string) error {
	return fmt.Errorf("%w: %s", ErrReleaseAuthorityRejected, message)
}
