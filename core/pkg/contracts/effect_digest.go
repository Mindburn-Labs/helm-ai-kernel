package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// CanonicalEffectDigest binds executable semantics, excluding display identity.
func CanonicalEffectDigest(effect *Effect) (string, error) {
	if effect == nil {
		return "", fmt.Errorf("effect is nil")
	}
	binding, err := effectDigestBindingFromEffect(effect, make(map[*Effect]struct{}), false)
	if err != nil {
		return "", err
	}
	return hashEffectDigestBinding(binding)
}

// EffectDigestBinding is the portable, identity-free effect projection.
//
//nolint:govet // field order follows the canonical wire contract.
type EffectDigestBinding struct {
	EffectType     string               `json:"effect_type"`
	Params         map[string]any       `json:"params,omitempty"`
	IdempotencyKey string               `json:"idempotency_key,omitempty"`
	Irreversible   bool                 `json:"irreversible,omitempty"`
	ArgsHash       string               `json:"args_hash,omitempty"`
	OutputHash     string               `json:"output_hash,omitempty"`
	Taint          []string             `json:"taint,omitempty"`
	Compensation   *EffectDigestBinding `json:"compensation,omitempty"`
}

// NewEffectDigestBinding projects an Effect into its canonical portable
// semantics and rejects cyclic compensation graphs fail-closed.
func NewEffectDigestBinding(effect *Effect) (*EffectDigestBinding, error) {
	if effect == nil {
		return nil, fmt.Errorf("effect is nil")
	}
	return effectDigestBindingFromEffect(effect, make(map[*Effect]struct{}), true)
}

// NormalizeEffectDigestBinding returns a canonical projection and rejects
// cyclic binding graphs. It is used before signing transported bindings.
func NormalizeEffectDigestBinding(binding *EffectDigestBinding) (*EffectDigestBinding, error) {
	if binding == nil {
		return nil, fmt.Errorf("effect digest binding is nil")
	}
	return normalizeEffectDigestBinding(binding, make(map[*EffectDigestBinding]struct{}), true)
}

// CanonicalEffectDigestFromBinding verifies and hashes a portable binding
// using the same JCS contract as CanonicalEffectDigest.
func CanonicalEffectDigestFromBinding(binding *EffectDigestBinding) (string, error) {
	if binding == nil {
		return "", fmt.Errorf("effect digest binding is nil")
	}
	normalized, err := normalizeEffectDigestBinding(binding, make(map[*EffectDigestBinding]struct{}), false)
	if err != nil {
		return "", err
	}
	return hashEffectDigestBinding(normalized)
}

func hashEffectDigestBinding(binding *EffectDigestBinding) (string, error) {
	effectBytes, err := canonicalize.JCS(binding)
	if err != nil {
		return "", err
	}
	return canonicalize.HashBytes(effectBytes), nil
}

func effectDigestBindingFromEffect(effect *Effect, ancestors map[*Effect]struct{}, cloneParams bool) (*EffectDigestBinding, error) {
	if effect == nil {
		return nil, nil
	}
	if _, exists := ancestors[effect]; exists {
		return nil, fmt.Errorf("effect compensation graph contains a cycle")
	}
	ancestors[effect] = struct{}{}
	defer delete(ancestors, effect)

	compensation, err := effectDigestBindingFromEffect(effect.Compensation, ancestors, cloneParams)
	if err != nil {
		return nil, err
	}
	params := effect.Params
	if cloneParams {
		params, err = cloneEffectDigestParams(effect.Params)
		if err != nil {
			return nil, fmt.Errorf("canonicalize effect parameters: %w", err)
		}
	}
	return &EffectDigestBinding{
		EffectType:     effect.EffectType,
		Params:         params,
		IdempotencyKey: effect.IdempotencyKey,
		Irreversible:   effect.Irreversible,
		ArgsHash:       effect.ArgsHash,
		OutputHash:     effect.OutputHash,
		Taint:          NormalizeTaintLabels(effect.Taint),
		Compensation:   compensation,
	}, nil
}

func normalizeEffectDigestBinding(binding *EffectDigestBinding, ancestors map[*EffectDigestBinding]struct{}, cloneParams bool) (*EffectDigestBinding, error) {
	if binding == nil {
		return nil, nil
	}
	if _, exists := ancestors[binding]; exists {
		return nil, fmt.Errorf("effect digest binding compensation graph contains a cycle")
	}
	ancestors[binding] = struct{}{}
	defer delete(ancestors, binding)

	compensation, err := normalizeEffectDigestBinding(binding.Compensation, ancestors, cloneParams)
	if err != nil {
		return nil, err
	}
	params := binding.Params
	if cloneParams {
		params, err = cloneEffectDigestParams(binding.Params)
		if err != nil {
			return nil, fmt.Errorf("canonicalize effect binding parameters: %w", err)
		}
	}
	return &EffectDigestBinding{
		EffectType:     binding.EffectType,
		Params:         params,
		IdempotencyKey: binding.IdempotencyKey,
		Irreversible:   binding.Irreversible,
		ArgsHash:       binding.ArgsHash,
		OutputHash:     binding.OutputHash,
		Taint:          NormalizeTaintLabels(binding.Taint),
		Compensation:   compensation,
	}, nil
}

func cloneEffectDigestParams(params map[string]any) (map[string]any, error) {
	if params == nil {
		return nil, nil
	}
	payload, err := canonicalize.JCS(params)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var cloned map[string]any
	if err := decoder.Decode(&cloned); err != nil {
		return nil, err
	}
	return cloned, nil
}
