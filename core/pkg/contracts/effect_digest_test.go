package contracts_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestCanonicalEffectDigestBindsExecutableSemantics(t *testing.T) {
	effect := &contracts.Effect{
		EffectID:   "effect-display-id",
		EffectType: contracts.EffectTypeRunSandboxedCode,
		Params:     map[string]any{"command": []string{"/bin/example"}},
		Taint:      []string{"untrusted", "untrusted"},
	}
	digest, err := contracts.CanonicalEffectDigest(effect)
	if err != nil {
		t.Fatal(err)
	}

	identityOnly := *effect
	identityOnly.EffectID = "another-display-id"
	identityOnly.Example = "human-only explanation"
	identityDigest, err := contracts.CanonicalEffectDigest(&identityOnly)
	if err != nil {
		t.Fatal(err)
	}
	if identityDigest != digest {
		t.Fatal("effect identity or explanation changed the semantic digest")
	}

	changed := *effect
	changed.Params = map[string]any{"command": []string{"/bin/substituted"}}
	changedDigest, err := contracts.CanonicalEffectDigest(&changed)
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == digest {
		t.Fatal("executable parameter mutation did not change the effect digest")
	}
}

func TestCanonicalEffectDigestRejectsNilEffect(t *testing.T) {
	if _, err := contracts.CanonicalEffectDigest(nil); err == nil {
		t.Fatal("nil effect received a digest")
	}
}

func TestCanonicalEffectDigestRejectsCompensationCycle(t *testing.T) {
	effect := &contracts.Effect{EffectType: contracts.EffectTypeRunSandboxedCode}
	effect.Compensation = effect

	if _, err := contracts.CanonicalEffectDigest(effect); err == nil {
		t.Fatal("cyclic compensation graph received a digest")
	}
}

func TestEffectDigestBindingPreservesAllExecutableSemantics(t *testing.T) {
	effect := &contracts.Effect{
		EffectType:     contracts.EffectTypeRunSandboxedCode,
		Params:         map[string]any{"command": []string{"/bin/example"}},
		IdempotencyKey: "mission:step:1",
		Irreversible:   true,
		ArgsHash:       "sha256:args",
		OutputHash:     "sha256:output",
		Taint:          []string{"untrusted", "untrusted"},
		Compensation: &contracts.Effect{
			EffectType: contracts.EffectTypeGeneric,
			Params:     map[string]any{"action": "undo"},
		},
	}

	binding, err := contracts.NewEffectDigestBinding(effect)
	if err != nil {
		t.Fatal(err)
	}
	fromEffect, err := contracts.CanonicalEffectDigest(effect)
	if err != nil {
		t.Fatal(err)
	}
	fromBinding, err := contracts.CanonicalEffectDigestFromBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	if fromBinding != fromEffect {
		t.Fatalf("transported effect binding changed digest: effect=%s binding=%s", fromEffect, fromBinding)
	}
	if binding.IdempotencyKey != effect.IdempotencyKey || !binding.Irreversible || binding.Compensation == nil {
		t.Fatal("portable effect binding omitted executable semantics")
	}
}

func TestCanonicalEffectDigestRejectsBindingCycle(t *testing.T) {
	binding := &contracts.EffectDigestBinding{EffectType: contracts.EffectTypeRunSandboxedCode}
	binding.Compensation = binding

	if _, err := contracts.CanonicalEffectDigestFromBinding(binding); err == nil {
		t.Fatal("cyclic transported binding received a digest")
	}
}
