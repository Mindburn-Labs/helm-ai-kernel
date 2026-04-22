package guardian_test

import (
	"context"
	"testing"
	"time"

	pkg_artifact "github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGuardian_SignDecision_TemporalInterventions verifies that temporal interventions
// correctly override or annotate the decision process.
func TestGuardian_SignDecision_TemporalInterventions(t *testing.T) {
	// 1. Setup Guardian
	signer, _ := crypto.NewEd25519Signer("test-key")
	// Empty PRG/Registry for simplicity - we want to test Intervention logic which runs BEFORE PRG in strict cases
	g := guardian.NewGuardian(signer, prg.NewGraph(), pkg_artifact.NewRegistry(nil, nil))
	ctx := context.Background()

	effect := &contracts.Effect{
		Params: map[string]any{"tool_name": "test_tool"},
	}

	t.Run("Intervention: Interrupt", func(t *testing.T) {
		decision := &contracts.DecisionRecord{ID: "dec-1"}
		intervention := &contracts.InterventionMetadata{
			Type:         contracts.InterventionInterrupt,
			ReasonCode:   "VELOCITY_LIMIT_EXCEEDED",
			WaitDuration: 5 * time.Second,
		}

		err := g.SignDecision(ctx, decision, effect, []string{}, intervention)
		// Should NOT error, but Verdict should be INTERVENE
		require.NoError(t, err)
		assert.Equal(t, "ESCALATE", decision.Verdict)
		assert.Contains(t, decision.Reason, "VELOCITY_LIMIT_EXCEEDED")
		assert.NotNil(t, decision.Intervention)
		assert.Equal(t, contracts.InterventionInterrupt, decision.Intervention.Type)
	})

	t.Run("Intervention: Quarantine", func(t *testing.T) {
		decision := &contracts.DecisionRecord{ID: "dec-2"}
		intervention := &contracts.InterventionMetadata{
			Type:       contracts.InterventionQuarantine,
			ReasonCode: "SUSPICIOUS_PATTERN",
		}

		err := g.SignDecision(ctx, decision, effect, []string{}, intervention)
		require.NoError(t, err)
		assert.Equal(t, "ESCALATE", decision.Verdict)
		assert.Contains(t, decision.Reason, "SUSPICIOUS_PATTERN")
	})

	t.Run("Intervention: None (Fallthrough to PRG)", func(t *testing.T) {
		decision := &contracts.DecisionRecord{ID: "dec-3"}

		// PRG is empty, so "test_tool" is not allowed -> FAIL
		// But we want to ensure Intervention didn't force INTERVENE
		err := g.SignDecision(ctx, decision, effect, []string{}, nil)
		require.NoError(t, err) // Sign fails? No, returns error if signing fails, but Verdict is FAIL
		assert.Equal(t, "DENY", decision.Verdict)
		assert.NotEqual(t, "ESCALATE", decision.Verdict)
	})

	t.Run("Determinism: Same Input -> Identical Intervention", func(t *testing.T) {
		interventionData := &contracts.InterventionMetadata{
			Type:         contracts.InterventionThrottle,
			ReasonCode:   "THROTTLE_A",
			WaitDuration: 100 * time.Millisecond,
		}

		// Run 1
		d1 := &contracts.DecisionRecord{ID: "run-1"}
		_ = g.SignDecision(ctx, d1, effect, []string{}, interventionData)

		// Run 2
		d2 := &contracts.DecisionRecord{ID: "run-2"}
		_ = g.SignDecision(ctx, d2, effect, []string{}, interventionData)

		// Check Intervention Metadata Equality
		assert.Equal(t, d1.Intervention.Type, d2.Intervention.Type)
		assert.Equal(t, d1.Intervention.ReasonCode, d2.Intervention.ReasonCode)
		assert.Equal(t, d1.Intervention.WaitDuration, d2.Intervention.WaitDuration)
	})
}
