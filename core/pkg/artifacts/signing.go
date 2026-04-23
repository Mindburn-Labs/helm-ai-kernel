package artifacts

import (
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

var (
	ErrSignerNotConfigured = errors.New("artifacts: signer not configured (fail-closed)")
)

// SignEnvelope signs the envelope payload and stamps signature metadata.
//
// Note: Artifact verification in Registry.VerifyArtifact currently verifies signatures
// over Payload bytes, so we sign the Payload directly.
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

	sig, err := signer.Sign(env.Payload)
	if err != nil {
		return fmt.Errorf("artifacts: sign failed: %w", err)
	}
	env.Signature = sig

	// Best-effort key identity. For Registry.VerifyArtifact, this is informational.
	env.SignatureKeyID = signer.PublicKey()

	return nil
}
