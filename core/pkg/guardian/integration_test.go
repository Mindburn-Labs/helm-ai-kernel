package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// TestIntegration_FullPipeline tests the complete Guardian pipeline with all
// new components enabled simultaneously: behavioral trust, privilege tiers,
// kill switch, and compliance checker.
func TestIntegration_FullPipeline(t *testing.T) {
	ctx := context.Background()
	signer, err := crypto.NewEd25519Signer("integration-key")
	if err != nil {
		t.Fatal(err)
	}

	graph := prg.NewGraph()
	_ = graph.AddRule("safe-tool", prg.RequirementSet{ID: "allow-safe", Logic: prg.AND})

	// Setup all components
	scorer := trust.NewBehavioralTrustScorer()
	resolver := NewStaticPrivilegeResolver(TierStandard)
	killSwitch := kernel.NewAgentKillSwitch()

	g := NewGuardian(signer, graph, nil,
		WithBehavioralTrustScorer(scorer),
		WithPrivilegeResolver(resolver),
		WithAgentKillSwitch(killSwitch),
	)

	t.Run("allow_path_with_all_gates", func(t *testing.T) {
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

	t.Run("killed_agent_denied", func(t *testing.T) {
		killSwitch.Kill("killed-agent", "admin", "test")

		decision, err := g.EvaluateDecision(ctx, DecisionRequest{
			Principal: "killed-agent",
			Action:    "EXECUTE_TOOL",
			Resource:  "safe-tool",
		})
		if err != nil {
			t.Fatalf("EvaluateDecision failed: %v", err)
		}
		if decision.Verdict != string(contracts.VerdictDeny) {
			t.Errorf("expected DENY for killed agent, got %s", decision.Verdict)
		}
		if decision.ReasonCode != string(contracts.ReasonAgentKilled) {
			t.Errorf("expected AGENT_KILLED reason, got %s", decision.ReasonCode)
		}
	})

	t.Run("privilege_tier_enforcement", func(t *testing.T) {
		// Set agent to RESTRICTED tier
		resolver.SetTier("restricted-agent", TierRestricted)

		decision, err := g.EvaluateDecision(ctx, DecisionRequest{
			Principal: "restricted-agent",
			Action:    "EXECUTE_TOOL",
			Resource:  "safe-tool",
		})
		if err != nil {
			t.Fatalf("EvaluateDecision failed: %v", err)
		}
		if decision.Verdict != string(contracts.VerdictDeny) {
			t.Errorf("expected DENY for restricted agent, got %s", decision.Verdict)
		}
		if decision.ReasonCode != string(contracts.ReasonInsufficientPrivilege) {
			t.Errorf("expected INSUFFICIENT_PRIVILEGE, got %s", decision.ReasonCode)
		}
	})

	t.Run("trust_downgrade_caps_privilege", func(t *testing.T) {
		// Set agent to ELEVATED tier
		resolver.SetTier("degraded-agent", TierElevated)

		// Drop trust to HOSTILE (0-199) which forces TierRestricted
		for i := 0; i < 15; i++ {
			scorer.RecordEvent("degraded-agent", trust.ScoreEvent{
				EventType: trust.EventThreatDetected,
				Delta:     -50,
			})
		}

		decision, err := g.EvaluateDecision(ctx, DecisionRequest{
			Principal: "degraded-agent",
			Action:    "EXECUTE_TOOL",
			Resource:  "safe-tool",
		})
		if err != nil {
			t.Fatalf("EvaluateDecision failed: %v", err)
		}
		if decision.Verdict != string(contracts.VerdictDeny) {
			t.Errorf("expected DENY after trust degradation, got %s", decision.Verdict)
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

	t.Run("gate_ordering_kill_before_privilege", func(t *testing.T) {
		// Kill an agent AND set it to SYSTEM tier
		resolver.SetTier("system-killed", TierSystem)
		killSwitch.Kill("system-killed", "admin", "test")

		decision, err := g.EvaluateDecision(ctx, DecisionRequest{
			Principal: "system-killed",
			Action:    "EXECUTE_TOOL",
			Resource:  "safe-tool",
		})
		if err != nil {
			t.Fatalf("EvaluateDecision failed: %v", err)
		}
		// Kill switch fires BEFORE privilege check
		if decision.ReasonCode != string(contracts.ReasonAgentKilled) {
			t.Errorf("kill switch should fire before privilege, got reason: %s", decision.ReasonCode)
		}
	})
}

// TestIntegration_ComplianceChecker tests the compliance checker wiring.
func TestIntegration_ComplianceChecker(t *testing.T) {
	ctx := context.Background()
	signer, _ := crypto.NewEd25519Signer("compliance-key")
	graph := prg.NewGraph()
	_ = graph.AddRule("safe-tool", prg.RequirementSet{ID: "allow-safe", Logic: prg.AND})

	checker := &mockComplianceChecker{compliant: true}
	g := NewGuardian(signer, graph, nil,
		WithComplianceChecker(checker),
	)

	t.Run("compliant_action_allowed", func(t *testing.T) {
		checker.compliant = true
		decision, err := g.EvaluateDecision(ctx, DecisionRequest{
			Principal: "agent-1",
			Action:    "EXECUTE_TOOL",
			Resource:  "safe-tool",
		})
		if err != nil {
			t.Fatalf("EvaluateDecision failed: %v", err)
		}
		if decision.Verdict != string(contracts.VerdictAllow) {
			t.Errorf("expected ALLOW for compliant action, got %s", decision.Verdict)
		}
	})

	t.Run("non_compliant_action_denied", func(t *testing.T) {
		checker.compliant = false
		checker.reason = "HIPAA violation: PHI access without authorization"
		checker.violated = []string{"164.312(a)(1)"}

		decision, err := g.EvaluateDecision(ctx, DecisionRequest{
			Principal: "agent-1",
			Action:    "EXECUTE_TOOL",
			Resource:  "safe-tool",
		})
		if err != nil {
			t.Fatalf("EvaluateDecision failed: %v", err)
		}
		if decision.Verdict != string(contracts.VerdictDeny) {
			t.Errorf("expected DENY for non-compliant action, got %s", decision.Verdict)
		}
		if decision.ReasonCode != "COMPLIANCE_VIOLATION" {
			t.Errorf("expected COMPLIANCE_VIOLATION, got %s", decision.ReasonCode)
		}
	})
}

type mockComplianceChecker struct {
	compliant bool
	reason    string
	violated  []string
}

func (m *mockComplianceChecker) CheckCompliance(_ context.Context, _, _ string, _ map[string]interface{}) (*ComplianceCheckResult, error) {
	return &ComplianceCheckResult{
		Compliant:           m.compliant,
		Reason:              m.reason,
		ObligationsChecked:  1,
		ViolatedObligations: m.violated,
	}, nil
}
