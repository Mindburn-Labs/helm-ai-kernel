package signals

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// Normalizer normalizes raw inbound events into SignalEnvelopes.
type Normalizer interface {
	// Normalize takes a partially populated SignalEnvelope (with RawPayload, Source, Class set)
	// and fills in ContentHash, IdempotencyKey, Provenance, and ReceivedAt.
	Normalize(env *SignalEnvelope) error
}

// DefaultNormalizer is the standard signal normalizer that computes
// content hashes via JCS canonicalization and generates idempotency keys.
type DefaultNormalizer struct {
	// Clock provides the current time. Defaults to time.Now if nil.
	Clock func() time.Time
}

// NewDefaultNormalizer creates a normalizer with default settings.
func NewDefaultNormalizer() *DefaultNormalizer {
	return &DefaultNormalizer{}
}

// Normalize fills in computed fields on the signal envelope.
func (n *DefaultNormalizer) Normalize(env *SignalEnvelope) error {
	if env == nil {
		return fmt.Errorf("signals: cannot normalize nil envelope")
	}

	if !env.Class.IsValid() {
		return fmt.Errorf("signals: invalid signal class %q", env.Class)
	}

	if !env.Sensitivity.IsValid() {
		return fmt.Errorf("signals: invalid sensitivity %q", env.Sensitivity)
	}

	if env.Source.SourceID == "" {
		return fmt.Errorf("signals: source_id is required")
	}

	if env.Source.ConnectorID == "" {
		return fmt.Errorf("signals: connector_id is required")
	}

	if len(env.RawPayload) == 0 {
		return fmt.Errorf("signals: raw_payload is required")
	}

	now := n.now()

	// Compute content hash via JCS canonicalization + SHA-256
	contentHash, err := canonicalize.CanonicalHash(env.RawPayload)
	if err != nil {
		return fmt.Errorf("signals: content hash failed: %w", err)
	}
	env.ContentHash = "sha256:" + contentHash

	// Compute idempotency key: source_id + external_id + content_hash
	idempotencyInput := env.Source.SourceID + ":" + env.ExternalID + ":" + env.ContentHash
	idempotencyHash := canonicalize.HashBytes([]byte(idempotencyInput))
	env.IdempotencyKey = idempotencyHash

	// Set timing
	env.ReceivedAt = now
	env.Provenance.NormalizedAt = now
	if env.Provenance.IngestedAt.IsZero() {
		env.Provenance.IngestedAt = now
	}

	return nil
}

func (n *DefaultNormalizer) now() time.Time {
	if n.Clock != nil {
		return n.Clock()
	}
	return time.Now().UTC()
}
