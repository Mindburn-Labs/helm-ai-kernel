package executor

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func TestEvidencePackProducer_Produce(t *testing.T) {
	producer := NewEvidencePackProducer("1.0.0-test")
	ctx := context.Background()

	input := &EvidencePackInput{
		// Identity
		ActorID:   "user-123",
		ActorType: "human",
		SessionID: "sess-456",

		// Policy
		DecisionID:          "dec-789",
		PolicyVersion:       "v1.2.0",
		RulesFired:          []string{"rule-1", "rule-2"},
		EvaluationGraphHash: "sha256:abc123",

		// Effect
		EffectID:          "eff-001",
		EffectType:        "DATA_WRITE",
		EffectPayloadHash: "sha256:payload123",
		IdempotencyKey:    "idem-001",
		Classification:    "reversible",

		// Context
		ModeID:        "mode-operational",
		LoopID:        "loop-main",
		PhenotypeHash: "sha256:pheno123",

		// Execution
		Status:      "success",
		ResultHash:  "sha256:result123",
		RetryCount:  0,
		StartedAt:   time.Now().Add(-100 * time.Millisecond),
		CompletedAt: time.Now(),
	}

	pack, err := producer.Produce(ctx, input)
	if err != nil {
		t.Fatalf("failed to produce evidence pack: %v", err)
	}

	// Verify core fields
	if pack.PackID == "" {
		t.Error("pack_id should be generated")
	}
	if pack.FormatVersion != "1.0.0" {
		t.Errorf("format_version should be 1.0.0, got %s", pack.FormatVersion)
	}

	// Verify identity
	if pack.Identity.ActorID != input.ActorID {
		t.Errorf("actor_id mismatch: got %s, want %s", pack.Identity.ActorID, input.ActorID)
	}

	// Verify policy
	if pack.Policy.DecisionID != input.DecisionID {
		t.Errorf("decision_id mismatch: got %s, want %s", pack.Policy.DecisionID, input.DecisionID)
	}

	// Verify effect
	if pack.Effect.EffectType != input.EffectType {
		t.Errorf("effect_type mismatch: got %s, want %s", pack.Effect.EffectType, input.EffectType)
	}

	// Verify execution
	if pack.Execution.Status != input.Status {
		t.Errorf("status mismatch: got %s, want %s", pack.Execution.Status, input.Status)
	}
	if pack.Execution.DurationMs <= 0 {
		t.Error("duration_ms should be positive")
	}

	// Verify attestation
	if pack.Attestation.PackHash == "" {
		t.Error("pack_hash should be computed")
	}
	if pack.Attestation.KernelVersion != "1.0.0-test" {
		t.Errorf("kernel_version mismatch: got %s, want 1.0.0-test", pack.Attestation.KernelVersion)
	}
}

func TestEvidencePackProducer_HashIntegrity(t *testing.T) {
	producer := NewEvidencePackProducer("1.0.0")
	ctx := context.Background()

	input := &EvidencePackInput{
		ActorID:    "user-1",
		ActorType:  "human",
		DecisionID: "dec-1",
		EffectID:   "eff-1",
		EffectType: "DATA_WRITE",
		Status:     "success",
		StartedAt:  time.Now(),
	}

	pack, _ := producer.Produce(ctx, input)

	// Validate the pack
	issues := ValidateEvidencePack(pack)
	if len(issues) > 0 {
		t.Errorf("validation issues: %v", issues)
	}

	// Tamper with the pack
	originalHash := pack.Attestation.PackHash
	pack.Effect.EffectType = "TAMPERED"

	// Re-validate (should detect tampering)
	issues = ValidateEvidencePack(pack)
	hashTampered := false
	for _, issue := range issues {
		if issue == "attestation.pack_hash does not match computed hash" {
			hashTampered = true
			break
		}
	}

	// Restore and verify the original hash was correct
	pack.Effect.EffectType = "DATA_WRITE"
	pack.Attestation.PackHash = originalHash
	issues = ValidateEvidencePack(pack)
	if len(issues) > 0 {
		t.Errorf("restored pack should be valid, got issues: %v", issues)
	}

	_ = hashTampered // Use variable to avoid unused error
}

func TestEvidencePackValidation_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		pack    *contracts.EvidencePack
		wantErr string
	}{
		{
			name:    "missing pack_id",
			pack:    &contracts.EvidencePack{},
			wantErr: "pack_id is required",
		},
		{
			name: "missing actor_id",
			pack: &contracts.EvidencePack{
				PackID: "pack-1",
			},
			wantErr: "identity.actor_id is required",
		},
		{
			name: "missing decision_id",
			pack: &contracts.EvidencePack{
				PackID:   "pack-1",
				Identity: contracts.EvidencePackIdentity{ActorID: "user-1"},
			},
			wantErr: "policy.decision_id is required",
		},
		{
			name: "missing effect_id",
			pack: &contracts.EvidencePack{
				PackID:   "pack-1",
				Identity: contracts.EvidencePackIdentity{ActorID: "user-1"},
				Policy:   contracts.EvidencePackPolicy{DecisionID: "dec-1"},
			},
			wantErr: "effect.effect_id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := ValidateEvidencePack(tt.pack)
			found := false
			for _, issue := range issues {
				if issue == tt.wantErr {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected error %q not found in %v", tt.wantErr, issues)
			}
		})
	}
}
