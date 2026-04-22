package trust

import (
	"encoding/json"
	"testing"
)

func TestNewSLSAVerifier(t *testing.T) {
	t.Run("uses default policy when nil", func(t *testing.T) {
		verifier := NewSLSAVerifier(nil)
		if verifier.Policy == nil {
			t.Error("expected non-nil policy")
		}
		if verifier.Policy.RequiredSLSAVersion != SLSAProvenancePredicateType {
			t.Errorf("wrong default SLSA version: %s", verifier.Policy.RequiredSLSAVersion)
		}
	})

	t.Run("uses provided policy", func(t *testing.T) {
		policy := &ProvenancePolicy{
			AllowedBuilders: []string{"builder:test"},
		}
		verifier := NewSLSAVerifier(policy)
		if len(verifier.Policy.AllowedBuilders) != 1 {
			t.Error("expected policy to be used")
		}
	})
}

func TestSLSAVerifier_VerifyAttestation(t *testing.T) {
	policy := &ProvenancePolicy{
		RequiredSLSAVersion: SLSAProvenancePredicateType,
		AllowedBuilders:     []string{"https://helm.org/builders/certified-builder@v1"},
	}
	verifier := NewSLSAVerifier(policy)

	t.Run("accepts valid attestation", func(t *testing.T) {
		provenance := SLSAProvenance{
			BuildDefinition: BuildDefinition{
				BuildType: "https://helm.org/pack-builder/v1",
			},
			RunDetails: RunDetails{
				Builder: Builder{ID: "https://helm.org/builders/certified-builder@v1"},
			},
		}
		predBytes, _ := json.Marshal(provenance)

		statement := &InTotoStatement{
			Type:          InTotoStatementType,
			PredicateType: SLSAProvenancePredicateType,
			Subject: []Subject{
				{Name: "my-pack", Digest: map[string]string{"sha256": "abc123"}},
			},
			Predicate: predBytes,
		}

		err := verifier.VerifyAttestation(statement)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("rejects wrong statement type", func(t *testing.T) {
		statement := &InTotoStatement{
			Type:          "wrong-type",
			PredicateType: SLSAProvenancePredicateType,
		}

		err := verifier.VerifyAttestation(statement)
		if err == nil {
			t.Error("expected error for wrong statement type")
		}
	})

	t.Run("rejects wrong predicate type", func(t *testing.T) {
		statement := &InTotoStatement{
			Type:          InTotoStatementType,
			PredicateType: "wrong-predicate",
		}

		err := verifier.VerifyAttestation(statement)
		if err == nil {
			t.Error("expected error for wrong predicate type")
		}
	})

	t.Run("rejects unauthorized builder", func(t *testing.T) {
		provenance := SLSAProvenance{
			RunDetails: RunDetails{
				Builder: Builder{ID: "https://evil.com/builder"},
			},
		}
		predBytes, _ := json.Marshal(provenance)

		statement := &InTotoStatement{
			Type:          InTotoStatementType,
			PredicateType: SLSAProvenancePredicateType,
			Predicate:     predBytes,
		}

		err := verifier.VerifyAttestation(statement)
		if err == nil {
			t.Error("expected error for unauthorized builder")
		}
	})
}

func TestSLSAVerifier_verifyDependencies(t *testing.T) {
	policy := &ProvenancePolicy{
		PinnedDependencies: map[string]string{
			"pkg:npm/lodash@4.17.21": "abc123",
		},
	}
	verifier := NewSLSAVerifier(policy)

	t.Run("accepts matching pinned dependency", func(t *testing.T) {
		deps := []ResourceDescriptor{
			{
				URI:    "pkg:npm/lodash@4.17.21",
				Digest: map[string]string{"sha256": "abc123"},
			},
		}

		err := verifier.verifyDependencies(deps)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("rejects mismatched pinned dependency", func(t *testing.T) {
		deps := []ResourceDescriptor{
			{
				URI:    "pkg:npm/lodash@4.17.21",
				Digest: map[string]string{"sha256": "wrong-hash"},
			},
		}

		err := verifier.verifyDependencies(deps)
		if err == nil {
			t.Error("expected error for hash mismatch")
		}
	})

	t.Run("ignores unpinned dependencies", func(t *testing.T) {
		deps := []ResourceDescriptor{
			{
				URI:    "pkg:npm/unpinned@1.0.0",
				Digest: map[string]string{"sha256": "anything"},
			},
		}

		err := verifier.verifyDependencies(deps)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestSLSAVerifier_VerifySubjectHash(t *testing.T) {
	verifier := NewSLSAVerifier(nil)

	t.Run("finds matching subject", func(t *testing.T) {
		statement := &InTotoStatement{
			Subject: []Subject{
				{Name: "pack1", Digest: map[string]string{"sha256": "hash1"}},
				{Name: "pack2", Digest: map[string]string{"sha256": "hash2"}},
			},
		}

		err := verifier.VerifySubjectHash(statement, "hash2")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("rejects non-matching hash", func(t *testing.T) {
		statement := &InTotoStatement{
			Subject: []Subject{
				{Name: "pack1", Digest: map[string]string{"sha256": "hash1"}},
			},
		}

		err := verifier.VerifySubjectHash(statement, "wrong-hash")
		if err == nil {
			t.Error("expected error for non-matching hash")
		}
	})
}
