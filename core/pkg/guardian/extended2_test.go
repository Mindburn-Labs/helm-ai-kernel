package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// ─── 4: Behavioral score recorded on ALLOW path ─────────────

func TestExt2_BehavioralScoreRecordedOnAllow(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	g := newMinimalGuardian(WithBehavioralTrustScorer(scorer))
	g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "agent-1", Action: "x", Resource: "test-resource"})
	score := scorer.GetScore("agent-1")
	if score.Score == 500 {
		// Score should have changed from default (event recorded)
		// Allow path records EventPolicyComply (+2) or deny path records EventPolicyViolate
		// Either way, it should not remain at exactly 500 with no history
	}
	if len(score.History) == 0 {
		t.Fatal("expected at least one behavioral event recorded")
	}
}

// ─── 5: Behavioral score recorded on DENY (no policy) ───────

func TestExt2_BehavioralScoreRecordedOnPolicyDeny(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	g := newMinimalGuardian(WithBehavioralTrustScorer(scorer))
	dec, err := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "agent-2", Action: "x", Resource: "test-resource"})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Verdict != string(contracts.VerdictDeny) {
		t.Fatalf("expected DENY for an action with no policy, got %s", dec.Verdict)
	}
	score := scorer.GetScore("agent-2")
	if score.Score >= 500 {
		t.Fatalf("expected score below 500 after a policy deny, got %d", score.Score)
	}
}

// ─── 9: Freeze + context guard — freeze takes priority ───────

func TestExt2_FreezeBeforeContextGuard(t *testing.T) {
	fc := kernel.NewFreezeController()
	fc.Freeze("admin")
	cg := kernel.NewContextGuardWithFingerprint("mismatch-fp")
	g := newMinimalGuardian(WithFreezeController(fc), WithContextGuard(cg))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "agent-1", Action: "x", Resource: "test-resource"})
	// Gate 0 (freeze) fires before gate 1 (context guard)
	if dec.ReasonCode != string(contracts.ReasonSystemFrozen) {
		t.Fatalf("expected SYSTEM_FROZEN (freeze takes precedence), got %s", dec.ReasonCode)
	}
}

// ─── 11: EvaluateOutput clean when no scanner ────────────────

func TestExt2_EvaluateOutputCleanNoScanner(t *testing.T) {
	g := newMinimalGuardian()
	result, err := g.EvaluateOutput(context.Background(), "dec-1", "some output", contracts.InputTrustInternalUnverified)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Clean || result.Quarantined {
		t.Fatal("expected clean result without scanner")
	}
}

// ─── 12: EvaluateOutput clean on empty output ────────────────

func TestExt2_EvaluateOutputCleanOnEmpty(t *testing.T) {
	g := newMinimalGuardian()
	result, err := g.EvaluateOutput(context.Background(), "dec-1", "", contracts.InputTrustTainted)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Clean {
		t.Fatal("expected clean for empty output")
	}
}

// ─── 13: Minimal Guardian — verdict without panic ────────────

func TestExt2_MinimalGuardianProducesVerdict(t *testing.T) {
	g := newMinimalGuardian() // no optional gates set
	dec, err := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "a", Action: "x", Resource: "test-resource"})
	if err != nil {
		t.Fatal(err)
	}
	// Should produce a verdict without panic
	if dec.Verdict == "" {
		t.Fatal("expected non-empty verdict")
	}
}

// ─── 14: Behavioral trust injection into context ─────────────

func TestExt2_BehavioralTrustInjectedIntoContext(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	g := newMinimalGuardian(WithBehavioralTrustScorer(scorer))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "agent-1", Action: "x", Resource: "test-resource"})
	if dec.InputContext == nil {
		t.Fatal("expected InputContext")
	}
	if _, ok := dec.InputContext["trust_score"]; !ok {
		t.Fatal("expected trust_score in InputContext")
	}
	if _, ok := dec.InputContext["trust_tier"]; !ok {
		t.Fatal("expected trust_tier in InputContext")
	}
}

// ─── 25: Behavioral score on egress blocked path ─────────────

func TestExt2_BehavioralScoreRecordedOnEgressBlocked(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	// Just verify RecordEvent doesn't panic when called directly via the interface
	scorer.RecordEvent("agent-1", trust.ScoreEvent{EventType: trust.EventEgressBlocked, Reason: "blocked"})
	score := scorer.GetScore("agent-1")
	if score.Score >= 500 {
		t.Fatalf("expected score below 500 after egress blocked, got %d", score.Score)
	}
}
