// Package effectdigest defines the one canonical effect digest used by the
// Guardian, executor, and durable outbox boundary.
package effectdigest

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// Canonical returns the digest that an executable decision and execution
// intent must bind. Keeping this in a shared package prevents a durable
// boundary from accepting an effect whose digest was checked only upstream.
func Canonical(effect *contracts.Effect) (string, error) {
	if effect == nil {
		return "", fmt.Errorf("effect is nil")
	}
	effectBytes, err := canonicalize.JCS(envelopeFrom(effect))
	if err != nil {
		return "", err
	}
	return canonicalize.HashBytes(effectBytes), nil
}

type envelope struct {
	EffectType     string         `json:"effect_type"`
	Params         map[string]any `json:"params,omitempty"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
	Irreversible   bool           `json:"irreversible,omitempty"`
	ArgsHash       string         `json:"args_hash,omitempty"`
	OutputHash     string         `json:"output_hash,omitempty"`
	Taint          []string       `json:"taint,omitempty"`
	Compensation   *envelope      `json:"compensation,omitempty"`
}

func envelopeFrom(effect *contracts.Effect) *envelope {
	if effect == nil {
		return nil
	}
	return &envelope{
		EffectType:     effect.EffectType,
		Params:         effect.Params,
		IdempotencyKey: effect.IdempotencyKey,
		Irreversible:   effect.Irreversible,
		ArgsHash:       effect.ArgsHash,
		OutputHash:     effect.OutputHash,
		Taint:          contracts.NormalizeTaintLabels(effect.Taint),
		Compensation:   envelopeFrom(effect.Compensation),
	}
}
