package artifacts

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

var (
	ErrSignerNotConfigured = errors.New("artifacts: signer not configured (fail-closed)")
)

type artifactEnvelopeSignaturePayload struct {
	Type          string          `json:"type"`
	SchemaVersion string          `json:"schema_version"`
	ProducerID    string          `json:"producer_id"`
	Timestamp     time.Time       `json:"timestamp"`
	Payload       json.RawMessage `json:"payload"`
}

// SignEnvelope signs the envelope identity tuple and stamps signature metadata.
func SignEnvelope(env *ArtifactEnvelope, signer crypto.Signer) error {
	if env == nil {
		return errors.New("artifacts: nil envelope")
	}
	if signer == nil {
		return ErrSignerNotConfigured
	}
	if len(env.Payload) == 0 {
		return errors.New("artifacts: missing payload")
	}

	payload, err := envelopeSigningPayload(env)
	if err != nil {
		return err
	}

	sig, err := signer.Sign(payload)
	if err != nil {
		return fmt.Errorf("artifacts: sign failed: %w", err)
	}
	env.Signature = sig

	// Best-effort key identity. For Registry.VerifyArtifact, this is informational.
	env.SignatureKeyID = signer.PublicKey()

	return nil
}

func envelopeSigningPayload(env *ArtifactEnvelope) ([]byte, error) {
	if env == nil {
		return nil, errors.New("artifacts: nil envelope")
	}
	if env.Type == "" {
		return nil, errors.New("artifacts: missing artifact type")
	}
	if env.SchemaVersion == "" {
		return nil, errors.New("artifacts: missing schema_version")
	}
	if env.ProducerID == "" {
		return nil, errors.New("artifacts: missing producer_id")
	}
	if env.Timestamp.IsZero() {
		return nil, errors.New("artifacts: missing timestamp")
	}
	if len(env.Payload) == 0 {
		return nil, errors.New("artifacts: missing payload")
	}

	payload := artifactEnvelopeSignaturePayload{
		Type:          env.Type,
		SchemaVersion: env.SchemaVersion,
		ProducerID:    env.ProducerID,
		Timestamp:     env.Timestamp,
		Payload:       env.Payload,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("artifacts: marshal signature payload: %w", err)
	}
	return data, nil
}
