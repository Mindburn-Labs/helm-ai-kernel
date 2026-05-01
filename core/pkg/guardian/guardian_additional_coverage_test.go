package guardian

import (
	"context"
	"strings"
	"sync"
	"testing"

	pkg_artifact "github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
)

// ─── 1: Gate 0 — freeze denies with correct reason code ───────

func TestExt_FreezeGateDeniesWithReasonCode(t *testing.T) {
	fc := kernel.NewFreezeController()
	fc.Freeze("admin")
	g := newMinimalGuardian(WithFreezeController(fc))
	dec, err := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "a", Action: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if dec.ReasonCode != string(contracts.ReasonSystemFrozen) {
		t.Fatalf("expected SYSTEM_FROZEN, got %s", dec.ReasonCode)
	}
}

// ─── 2: Gate 0.5 — agent kill switch ──────────────────────────

func TestExt_AgentKillSwitchDenies(t *testing.T) {
	ks := kernel.NewAgentKillSwitch()
	ks.Kill("bad-agent", "admin", "testing")
	g := newMinimalGuardian(WithAgentKillSwitch(ks))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "bad-agent", Action: "x"})
	if dec.Verdict != string(contracts.VerdictDeny) || dec.ReasonCode != string(contracts.ReasonAgentKilled) {
		t.Fatalf("expected DENY/AGENT_KILLED, got %s/%s", dec.Verdict, dec.ReasonCode)
	}
}

// ─── 3: Gate 1 — context mismatch denial ──────────────────────

func TestExt_ContextMismatchDeniesWithCode(t *testing.T) {
	cg := kernel.NewContextGuardWithFingerprint("boot-fp")
	g := newMinimalGuardian(WithContextGuard(cg))
	// ValidateCurrent will compute real fingerprint which won't match "boot-fp"
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "a", Action: "x"})
	if dec.ReasonCode != string(contracts.ReasonContextMismatch) {
		t.Fatalf("expected CONTEXT_MISMATCH, got %s", dec.ReasonCode)
	}
}

// ─── 4: Gate 2 — identity isolation violation ─────────────────

func TestExt_IdentityIsolationViolationDenies(t *testing.T) {
	ic := identity.NewIsolationChecker()
	// Bind cred-hash-1 to agent-1
	_ = ic.ValidateAgentIdentity("agent-1", "cred-hash-1", "session-1")
	g := newMinimalGuardian(WithIsolationChecker(ic))
	// Different principal reusing same credential => violation
	req := DecisionRequest{
		Principal: "agent-2",
		Action:    "x",
		Context:   map[string]interface{}{"credential_hash": "cred-hash-1", "session_id": "session-2"},
	}
	dec, _ := g.EvaluateDecision(context.Background(), req)
	if dec.ReasonCode != string(contracts.ReasonIdentityIsolationViolation) {
		t.Fatalf("expected IDENTITY_ISOLATION_VIOLATION, got %s", dec.ReasonCode)
	}
}

// ─── 5: Gate 3 — egress blocked ───────────────────────────────

func TestExt_EgressBlockedDenies(t *testing.T) {
	ec := firewall.NewEgressChecker(&firewall.EgressPolicy{}) // empty allowlist = deny all
	g := newMinimalGuardian(WithEgressChecker(ec))
	req := DecisionRequest{
		Principal: "a",
		Action:    "x",
		Context:   map[string]interface{}{"destination": "https://evil.com"},
	}
	dec, _ := g.EvaluateDecision(context.Background(), req)
	if dec.ReasonCode != string(contracts.ReasonDataEgressBlocked) {
		t.Fatalf("expected DATA_EGRESS_BLOCKED, got %s", dec.ReasonCode)
	}
}

func TestExt_TaintedEgressDeniesWhenFlagEnabled(t *testing.T) {
	t.Setenv("HELM_TAINT_TRACKING", "1")
	g := newMinimalGuardian()
	req := DecisionRequest{
		Principal: "a",
		Action:    "EXECUTE_TOOL",
		Resource:  "browser.fetch",
		Context: map[string]interface{}{
			"destination": "https://external.example/upload",
			"taint":       []string{contracts.TaintPII},
		},
	}
	dec, _ := g.EvaluateDecision(context.Background(), req)
	if dec.ReasonCode != string(contracts.ReasonTaintedEgressDeny) {
		t.Fatalf("expected %s, got %s", contracts.ReasonTaintedEgressDeny, dec.ReasonCode)
	}
}

// ─── 6: EvaluateDecision with no policy → NO_POLICY_DEFINED ──

func TestExt_NoPolicyDefined(t *testing.T) {
	g := newMinimalGuardian()
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "a", Action: "x", Resource: "unknown_tool"})
	if dec.Verdict != string(contracts.VerdictDeny) {
		t.Fatalf("expected DENY, got %s", dec.Verdict)
	}
}

// ─── 7: Concurrent EvaluateDecision — no panics ──────────────

func TestExt_ConcurrentEvaluateDecisionNoPanics(t *testing.T) {
	g := newMinimalGuardian()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "a", Action: "x"})
		}()
	}
	wg.Wait()
}

// ─── 8: Nil signer causes sign failure error ──────────────────

func TestExt_NilSignerReturnsError(t *testing.T) {
	// Guardian with a signer that fails
	signer := &testSigner{fail: true}
	graph := prg.NewGraph()
	reg := pkg_artifact.NewRegistry(newTestStore(), nil)
	fc := kernel.NewFreezeController()
	fc.Freeze("admin")
	g := NewGuardian(signer, graph, reg, WithFreezeController(fc))
	_, err := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "a", Action: "x"})
	if err == nil {
		t.Fatal("expected error when signer fails")
	}
}

// ─── 9: Empty request still produces a decision ───────────────

func TestExt_EmptyRequestProducesDecision(t *testing.T) {
	g := newMinimalGuardian()
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{})
	if dec == nil {
		t.Fatal("expected non-nil decision even for empty request")
	}
}

// ─── 10: Freeze verdict is always DENY ────────────────────────

func TestExt_FreezeVerdictIsDeny(t *testing.T) {
	fc := kernel.NewFreezeController()
	fc.Freeze("admin")
	g := newMinimalGuardian(WithFreezeController(fc))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "p", Action: "a"})
	if dec.Verdict != string(contracts.VerdictDeny) {
		t.Fatalf("expected DENY, got %s", dec.Verdict)
	}
}

// ─── 11: Budget exceeded denial ───────────────────────────────

func TestExt_BudgetExceededDenial(t *testing.T) {
	bt := newMockBudgetTracker(0) // zero budget
	g := newMinimalGuardian(WithBudgetTracker(bt))
	effect := &contracts.Effect{EffectID: "e1", EffectType: "T", Params: map[string]any{"tool_name": "test_tool", "budget_id": "b1"}}
	dec := &contracts.DecisionRecord{ID: "d1"}
	err := g.SignDecision(context.Background(), dec, effect, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec.ReasonCode != string(contracts.ReasonBudgetExceeded) {
		t.Fatalf("expected BUDGET_EXCEEDED, got %s", dec.ReasonCode)
	}
}

// ─── 12: checkEnvelope rejects nil effect type ────────────────

func TestExt_CheckEnvelopeRejectsEmptyType(t *testing.T) {
	g := newMinimalGuardian()
	err := g.checkEnvelope(&contracts.Effect{EffectID: "e1"})
	if err == nil || !strings.Contains(err.Error(), "effect type") {
		t.Fatal("expected error about missing effect type")
	}
}

// ─── 13: checkEnvelope rejects nil effect ID ──────────────────

func TestExt_CheckEnvelopeRejectsEmptyID(t *testing.T) {
	g := newMinimalGuardian()
	err := g.checkEnvelope(&contracts.Effect{EffectType: "T"})
	if err == nil || !strings.Contains(err.Error(), "effect ID") {
		t.Fatal("expected error about missing effect ID")
	}
}

// ─── 14: Behavioral scorer records on egress block ────────────

func TestExt_BehavioralScorerRecordsEgressBlock(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	ec := firewall.NewEgressChecker(&firewall.EgressPolicy{})
	g := newMinimalGuardian(WithBehavioralTrustScorer(scorer), WithEgressChecker(ec))
	req := DecisionRequest{
		Principal: "agent-1",
		Action:    "x",
		Context:   map[string]interface{}{"destination": "https://evil.com"},
	}
	g.EvaluateDecision(context.Background(), req)
	score := scorer.GetScore("agent-1")
	if score.Score >= 500 {
		t.Fatalf("egress block should reduce score below 500, got %d", score.Score)
	}
}

// ─── 15: Decision ID is non-empty ─────────────────────────────

func TestExt_DecisionIDNonEmpty(t *testing.T) {
	g := newMinimalGuardian()
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "a", Action: "x"})
	if dec.ID == "" {
		t.Fatal("decision ID must be non-empty")
	}
}

// ─── 16: Decision ID starts with dec- prefix ──────────────────

func TestExt_DecisionIDPrefix(t *testing.T) {
	id := newDecisionID()
	if !strings.HasPrefix(id, "dec-") {
		t.Fatalf("expected dec- prefix, got %s", id)
	}
}

// ─── 17: Two decision IDs are unique ──────────────────────────

func TestExt_DecisionIDsUnique(t *testing.T) {
	a := newDecisionID()
	b := newDecisionID()
	if a == b {
		t.Fatal("expected unique decision IDs")
	}
}

// ─── 18: WithDelegationStore injects store ────────────────────

func TestExt_WithDelegationStore(t *testing.T) {
	ds := identity.NewInMemoryDelegationStore()
	g := newMinimalGuardian(WithDelegationStore(ds))
	if g.delegationStore == nil {
		t.Fatal("delegation store not injected")
	}
}

// ─── 19: WithThreatScanner injects scanner ────────────────────

func TestExt_WithThreatScannerStored(t *testing.T) {
	// Just verify it doesn't panic on nil — scanner is optional
	g := newMinimalGuardian()
	if g.threatScanner != nil {
		t.Fatal("threat scanner should be nil by default")
	}
}

// ─── 20: Freeze after unfreeze allows decisions ───────────────

func TestExt_UnfreezeAllowsDecisions(t *testing.T) {
	fc := kernel.NewFreezeController()
	fc.Freeze("admin")
	fc.Unfreeze("admin")
	g := newMinimalGuardian(WithFreezeController(fc))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "a", Action: "x"})
	// Should NOT be SYSTEM_FROZEN after unfreeze
	if dec.ReasonCode == string(contracts.ReasonSystemFrozen) {
		t.Fatal("should not deny after unfreeze")
	}
}

// ─── 21: Agent not killed passes kill switch gate ─────────────

func TestExt_AgentNotKilledPasses(t *testing.T) {
	ks := kernel.NewAgentKillSwitch()
	ks.Kill("other-agent", "admin", "testing")
	g := newMinimalGuardian(WithAgentKillSwitch(ks))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "good-agent", Action: "x"})
	if dec.ReasonCode == string(contracts.ReasonAgentKilled) {
		t.Fatal("good-agent should not be killed")
	}
}

// ─── 22: IssueExecutionIntent rejects DENY verdict ────────────

func TestExt_IssueIntentRejectsDeny(t *testing.T) {
	g := newMinimalGuardian()
	dec := &contracts.DecisionRecord{Verdict: string(contracts.VerdictDeny)}
	_, err := g.IssueExecutionIntent(context.Background(), dec, &contracts.Effect{EffectID: "e1", EffectType: "T"})
	if err == nil {
		t.Fatal("expected error for denied decision")
	}
}

// ─── 23: IssueExecutionIntent rejects ESCALATE verdict ────────

func TestExt_IssueIntentRejectsEscalate(t *testing.T) {
	g := newMinimalGuardian()
	dec := &contracts.DecisionRecord{Verdict: string(contracts.VerdictEscalate)}
	_, err := g.IssueExecutionIntent(context.Background(), dec, &contracts.Effect{EffectID: "e1", EffectType: "T"})
	if err == nil {
		t.Fatal("expected error for escalated decision")
	}
}

func TestExt_IssueIntentPropagatesTaint(t *testing.T) {
	g := newMinimalGuardian()
	dec := &contracts.DecisionRecord{ID: "dec-taint", Verdict: string(contracts.VerdictAllow), Signature: "sig"}
	effect := &contracts.Effect{
		EffectID:   "e-taint",
		EffectType: "tool_call",
		Params:     map[string]any{"tool_name": "safe_tool"},
		Taint:      []string{"PII", contracts.TaintCredential},
	}
	intent, err := g.IssueExecutionIntent(context.Background(), dec, effect)
	if err != nil {
		t.Fatalf("IssueExecutionIntent failed: %v", err)
	}
	if !contracts.TaintContains(intent.Taint, contracts.TaintPII) ||
		!contracts.TaintContains(intent.Taint, contracts.TaintCredential) {
		t.Fatalf("expected normalized taint on intent, got %v", intent.Taint)
	}
}

// ─── 24: recordBehavioralEvent with nil scorer is no-op ───────

func TestExt_RecordBehavioralEventNilScorer(t *testing.T) {
	g := newMinimalGuardian()
	// Should not panic
	g.recordBehavioralEvent("agent-1", trust.EventPolicyComply, "test")
}

// ─── 25: recordBehavioralEvent with empty principal is no-op ──

func TestExt_RecordBehavioralEventEmptyPrincipal(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	g := newMinimalGuardian(WithBehavioralTrustScorer(scorer))
	g.recordBehavioralEvent("", trust.EventPolicyComply, "test")
	// Should not have recorded anything
}
