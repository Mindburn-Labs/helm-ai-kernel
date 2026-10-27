// quantum_posture: this contract verifies classical Ed25519 DSSE signatures only.
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

var ErrRecoveryCheckpointUntrusted = errors.New("recovery checkpoint trust policy refused")

// RecoveryCheckpointVerificationPolicy MUST come from an authenticated owner,
// never from the artifact being verified. Expected binds every declared field
// to the independently supplied capture/native/installed-cohort context.
// Verification is historical evidence checking, not freshness, persistence,
// replay consumption or authority to restore/resume.
type RecoveryCheckpointVerificationPolicy struct {
	KeyID          string
	PublicKey      ed25519.PublicKey
	Purpose        string
	PayloadType    string
	Expected       contracts.RecoveryCheckpointDescriptor
	ValidFromUnix  uint64
	ValidUntilUnix uint64
	VerifyAtUnix   uint64
	Revoked        bool
	// Once custody/logging freezes an envelope, its exact hash is required on
	// replay. Do not replace it by re-signing after an uncertain acknowledgement.
	FrozenEnvelopeDigest string
}

type VerifiedRecoveryCheckpoint struct {
	Descriptor       contracts.RecoveryCheckpointDescriptor
	PayloadBytes     []byte
	EnvelopeBytes    []byte
	SnapshotDigest   string
	DescriptorDigest string
	EnvelopeDigest   string
}

// RecoveryCheckpointPAE implements DSSEv1 with decimal BYTE lengths, including
// UTF-8 bytes. It uses the original validated payload; it never re-serializes it.
func RecoveryCheckpointPAE(payload []byte) ([]byte, error) {
	if _, err := contracts.DecodeRecoveryCheckpoint(payload); err != nil {
		return nil, err
	}
	payloadType := contracts.RecoveryCheckpointPayloadType
	var preimage bytes.Buffer
	preimage.WriteString("DSSEv1 ")
	preimage.WriteString(strconv.Itoa(len(payloadType)))
	preimage.WriteByte(' ')
	preimage.WriteString(payloadType)
	preimage.WriteByte(' ')
	preimage.WriteString(strconv.Itoa(len(payload)))
	preimage.WriteByte(' ')
	preimage.Write(payload)
	return preimage.Bytes(), nil
}

// NewRecoveryCheckpointEnvelope assembles a signature returned by the existing
// Ed25519 evidence signer. No private key or local signing authority is created.
func NewRecoveryCheckpointEnvelope(payload []byte, keyID string, signature []byte) ([]byte, error) {
	if _, err := RecoveryCheckpointPAE(payload); err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature length", contracts.ErrRecoveryCheckpointInvalid)
	}
	envelope := contracts.RecoveryCheckpointEnvelope{
		PayloadType: contracts.RecoveryCheckpointPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []contracts.RecoveryCheckpointSignature{{KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(signature)}},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	if _, _, _, err := contracts.DecodeRecoveryCheckpointEnvelope(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func VerifyRecoveryCheckpointEnvelope(raw []byte, policy RecoveryCheckpointVerificationPolicy) (*VerifiedRecoveryCheckpoint, error) {
	if len(policy.PublicKey) != ed25519.PublicKeySize || policy.Purpose != contracts.RecoveryCheckpointPurpose || policy.PayloadType != contracts.RecoveryCheckpointPayloadType || policy.Revoked || policy.ValidFromUnix > policy.ValidUntilUnix || policy.ValidUntilUnix == 0 || policy.ValidUntilUnix > contracts.RecoveryCheckpointMaxInteger || policy.VerifyAtUnix < policy.ValidFromUnix || policy.VerifyAtUnix >= policy.ValidUntilUnix || policy.Expected.Validate() != nil {
		return nil, ErrRecoveryCheckpointUntrusted
	}
	envelope, payload, signature, err := contracts.DecodeRecoveryCheckpointEnvelope(raw)
	if err != nil {
		return nil, err
	}
	if policy.KeyID == "" || envelope.Signatures[0].KeyID != policy.KeyID {
		return nil, ErrRecoveryCheckpointUntrusted
	}
	descriptor, err := contracts.DecodeRecoveryCheckpoint(payload)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(descriptor, policy.Expected) {
		return nil, ErrRecoveryCheckpointUntrusted
	}
	preimage, err := RecoveryCheckpointPAE(payload)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(policy.PublicKey, preimage, signature) {
		return nil, ErrRecoveryCheckpointUntrusted
	}
	envelopeDigest := contracts.RecoveryCheckpointHash(raw)
	if policy.FrozenEnvelopeDigest != "" && policy.FrozenEnvelopeDigest != envelopeDigest {
		return nil, ErrRecoveryCheckpointUntrusted
	}
	return &VerifiedRecoveryCheckpoint{
		Descriptor:   descriptor,
		PayloadBytes: bytes.Clone(payload), EnvelopeBytes: bytes.Clone(raw),
		SnapshotDigest:   descriptor.Snapshot.Digest,
		DescriptorDigest: contracts.RecoveryCheckpointHash(payload), EnvelopeDigest: envelopeDigest,
	}, nil
}
