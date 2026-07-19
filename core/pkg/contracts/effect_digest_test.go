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
