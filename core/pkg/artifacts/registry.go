package artifacts

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

// Registry manages the storage and verification of Evidence Artifacts.
type Registry struct {
	store    Store
	verifier crypto.Verifier // Optional: If set, enforces signatures
}

// NewRegistry creates a new Registry. validKeys is optional.
func NewRegistry(store Store, verifier crypto.Verifier) *Registry {
	return &Registry{
		store:    store,
		verifier: verifier,
	}
}

// PutArtifact validates and persists an artifact envelope.
// It returns the Content Hash of the stored envelope.
func (r *Registry) PutArtifact(ctx context.Context, envelope *ArtifactEnvelope) (string, error) {
	if envelope == nil {
		return "", errors.New("nil envelope")
	}
	if envelope.Type == "" {
		return "", errors.New("missing artifact type")
	}
	if len(envelope.Payload) == 0 {
		return "", errors.New("missing payload")
	}

	// Security Check: Artifact Bloat (Red Team Fix)
	const MaxArtifactSize = 10 * 1024 * 1024 // 10MB
	if len(envelope.Payload) > MaxArtifactSize {
		return "", fmt.Errorf("artifact payload exceeds limit of %d bytes", MaxArtifactSize)
	}

	// 1. Marshal the envelope to canonical JSON
	data, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("failed to marshal envelope: %w", err)
	}

	// 2. Store in CAS
	return r.store.Store(ctx, data)
}

// GetArtifact retrieves and unmarshals an artifact by hash.
func (r *Registry) GetArtifact(ctx context.Context, hash string) (*ArtifactEnvelope, error) {
	data, err := r.store.Get(ctx, hash)
	if err != nil {
		return nil, err
	}

	var envelope ArtifactEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("corrupt artifact data: %w", err)
	}

	return &envelope, nil
}

// VerifyArtifact checks the integrity and signature of an artifacts.
func (r *Registry) VerifyArtifact(ctx context.Context, hash string) (bool, []string, error) {
	envelope, err := r.GetArtifact(ctx, hash)
	if err != nil {
		return false, nil, err
	}

	reasons := []string{}
	valid := true

	// 1. Verify Schema (Type check)
	if envelope.Type == "" {
		valid = false
		reasons = append(reasons, "missing type")
	}

	// 2. Verify Key ID Presence
	if envelope.Signature == "" || envelope.SignatureKeyID == "" {
		valid = false
		reasons = append(reasons, "missing signature or key_id")
		// Cannot proceed to crypto verification
		return valid, reasons, nil
	}

	// 3. Cryptographic Verification
	// Fail closed if verifier is missing; unsigned or unverifiable artifacts must not be treated as valid.
	if r.verifier == nil {
		return false, append(reasons, "artifact signature verifier not configured (fail-closed)"), nil
	}

	// Signatures are expected to be hex-encoded (Ed25519Signer produces hex).
	// For compatibility, allow a "hex:" prefix.
	sigHex := strings.TrimPrefix(envelope.Signature, "hex:")
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, append(reasons, "signature decode failed"), nil
	}

	if !r.verifier.Verify(envelope.Payload, sigBytes) {
		valid = false
		reasons = append(reasons, "signature invalid")
	}

	return valid, reasons, nil
}
