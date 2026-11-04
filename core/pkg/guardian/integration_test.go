package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// TestIntegration_FullPipeline tests the complete Guardian pipeline with the
// behavioral trust scorer enabled against a real Ed25519 signer.
func TestIntegration_FullPipeline(t *testing.T) {
	ctx := context.Background()
	signer, err := crypto.NewEd25519Signer("integration-key")
	if err != nil {
		t.Fatal(err)
	}

	graph := prg.NewGraph()
	_ = graph.AddRule("safe-tool", prg.RequirementSet{ID: "allow-safe", Logic: prg.AND})

	scorer := trust.NewBehavioralTrustScorer()

	g := NewGuardian(signer, graph, nil,
		WithBehavioralTrustScorer(scorer),
	)

	t.Run("allow_path_with_behavioral_trust", func(t *testing.T) {
		decision, err := g.EvaluateDecision(ctx, DecisionRequest{
			Principal: "agent-1",
			Action:    "EXECUTE_TOOL",
			Resource:  "safe-tool",
		})
		if err != nil {
			t.Fatalf("EvaluateDecision failed: %v", err)
		}
		if decision.Verdict != string(contracts.VerdictAllow) {
			t.Errorf("expected ALLOW, got %s (reason: %s)", decision.Verdict, decision.Reason)
		}
	})

	t.Run("trust_score_injected_to_context", func(t *testing.T) {
		// Score some events to move away from initial
		scorer.RecordEvent("agent-2", trust.ScoreEvent{
			EventType: trust.EventPolicyComply,
			Delta:     200,
		})

		decision, err := g.EvaluateDecision(ctx, DecisionRequest{
			Principal: "agent-2",
			Action:    "EXECUTE_TOOL",
			Resource:  "safe-tool",
		})
		if err != nil {
			t.Fatalf("EvaluateDecision failed: %v", err)
		}

		// Trust score should be injected into context
		if decision.InputContext == nil {
			t.Fatal("InputContext should not be nil")
		}
		ts, ok := decision.InputContext["trust_score"]
		if !ok {
			t.Fatal("trust_score should be in InputContext")
		}
		if ts.(float64) < 0.5 {
			t.Errorf("trust_score should be > 0.5 after +200 boost, got %v", ts)
		}
	})

	t.Run("behavioral_score_recorded_on_allow", func(t *testing.T) {
		initial := scorer.GetScore("scoring-agent")

		_, err := g.EvaluateDecision(ctx, DecisionRequest{
			Principal: "scoring-agent",
			Action:    "EXECUTE_TOOL",
			Resource:  "safe-tool",
		})
		if err != nil {
			t.Fatalf("EvaluateDecision failed: %v", err)
		}

		after := scorer.GetScore("scoring-agent")
		if after.Score <= initial.Score {
			t.Errorf("score should increase after ALLOW, got %d -> %d", initial.Score, after.Score)
		}
	})

	t.Run("denied_tool_records_violation", func(t *testing.T) {
		initial := scorer.GetScore("unknown-agent")

		_, err := g.EvaluateDecision(ctx, DecisionRequest{
			Principal: "unknown-agent",
			Action:    "EXECUTE_TOOL",
			Resource:  "nonexistent-tool",
		})
		if err != nil {
			t.Fatalf("EvaluateDecision failed: %v", err)
		}

		after := scorer.GetScore("unknown-agent")
		if after.Score >= initial.Score {
			t.Errorf("score should decrease after DENY, got %d -> %d", initial.Score, after.Score)
		}
	})
}
