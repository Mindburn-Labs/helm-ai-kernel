package guardian

import (
	"context"
	"testing"

	pkg_artifact "github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AC-REG-09: Guardian override blocks forbidden effect types (Intervention)
func TestGuardian_Intervention(t *testing.T) {
	// Setup
	mockStore := NewMockStore()
	registry := pkg_artifact.NewRegistry(mockStore, nil)
	signer := &MockSigner{}
	ruleGraph := prg.NewGraph()
	// No rules needed, intervention happens before PRG

	subject := NewGuardian(signer, ruleGraph, registry)
	ctx := context.Background()

	t.Run("Intervention Interrupts Execution", func(t *testing.T) {
		decision := &contracts.DecisionRecord{ID: "dec-int-1"}
		effect := &contracts.Effect{
			EffectID: "eff-int-1",
			Params:   map[string]any{"tool_name": "any_tool"},
		}

		intervention := &contracts.InterventionMetadata{
			Type:       contracts.InterventionInterrupt,
			ReasonCode: "MANUAL_OVERRIDE",
		}

		err := subject.SignDecision(ctx, decision, effect, nil, intervention)
		require.NoError(t, err)

		assert.Equal(t, "ESCALATE", decision.Verdict)
		assert.Equal(t, "mock_decision_sig", decision.Signature)
		assert.Contains(t, decision.Reason, "MANUAL_OVERRIDE")
	})
}
