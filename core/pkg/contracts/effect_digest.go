package contracts

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// CanonicalEffectDigest returns the source-owned digest used by Guardian,
// execution intents, and effect consumers. EffectID, DecisionID, and Example
// are intentionally excluded because they identify or explain an invocation;
// the returned digest binds its executable semantics and compensation graph.
func CanonicalEffectDigest(effect *Effect) (string, error) {
	if effect == nil {
		return "", fmt.Errorf("effect is nil")
	}
	effectBytes, err := canonicalize.JCS(canonicalEffectDigestEnvelopeFrom(effect))
	if err != nil {
		return "", err
	}
	return canonicalize.HashBytes(effectBytes), nil
}

type canonicalEffectDigestEnvelope struct {
	EffectType     string                         `json:"effect_type"`
	Params         map[string]any                 `json:"params,omitempty"`
	IdempotencyKey string                         `json:"idempotency_key,omitempty"`
	Irreversible   bool                           `json:"irreversible,omitempty"`
	ArgsHash       string                         `json:"args_hash,omitempty"`
	OutputHash     string                         `json:"output_hash,omitempty"`
	Taint          []string                       `json:"taint,omitempty"`
	Compensation   *canonicalEffectDigestEnvelope `json:"compensation,omitempty"`
}

func canonicalEffectDigestEnvelopeFrom(effect *Effect) *canonicalEffectDigestEnvelope {
	if effect == nil {
		return nil
	}
	return &canonicalEffectDigestEnvelope{
		EffectType:     effect.EffectType,
		Params:         effect.Params,
		IdempotencyKey: effect.IdempotencyKey,
		Irreversible:   effect.Irreversible,
		ArgsHash:       effect.ArgsHash,
		OutputHash:     effect.OutputHash,
		Taint:          NormalizeTaintLabels(effect.Taint),
		Compensation:   canonicalEffectDigestEnvelopeFrom(effect.Compensation),
	}
}
