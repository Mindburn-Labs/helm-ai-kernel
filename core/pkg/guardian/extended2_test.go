package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// ─── mock compliance checker for extended2 tests ────────────

type ext2ComplianceChecker struct {
	compliant           bool
	reason              string
	violatedObligations []string
	returnErr           error
}

func (m *ext2ComplianceChecker) CheckCompliance(_ context.Context, _, _ string, _ map[string]interface{}) (*ComplianceCheckResult, error) {
	if m.returnErr != nil {
		return nil, m.returnErr
	}
	return &ComplianceCheckResult{
		Compliant:           m.compliant,
		Reason:              m.reason,
		ObligationsChecked:  1,
		ViolatedObligations: m.violatedObligations,
	}, nil
}

// ─── 1: Compliance checker ALLOW path ────────────────────────

func TestExt2_ComplianceCheckerAllowPath(t *testing.T) {
	cc := &ext2ComplianceChecker{compliant: true}
	g := newMinimalGuardian(WithComplianceChecker(cc))
	dec, err := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "a", Action: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Verdict == string(contracts.VerdictDeny) && dec.ReasonCode == "COMPLIANCE_VIOLATION" {
		t.Fatal("compliant checker should not produce COMPLIANCE_VIOLATION")
	}
}

// ─── 2: Compliance checker DENY path ─────────────────────────

func TestExt2_ComplianceCheckerDenyPath(t *testing.T) {
	cc := &ext2ComplianceChecker{compliant: false, reason: "GDPR", violatedObligations: []string{"OB-1"}}
	g := newMinimalGuardian(WithComplianceChecker(cc))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "a", Action: "x"})
	if dec.ReasonCode != "COMPLIANCE_VIOLATION" {
		t.Fatalf("expected COMPLIANCE_VIOLATION, got %s", dec.ReasonCode)
	}
}

// ─── 3: Compliance checker error fails closed ────────────────

func TestExt2_ComplianceCheckerErrorFailsClosed(t *testing.T) {
	cc := &ext2ComplianceChecker{returnErr: errorf("db down")}
	g := newMinimalGuardian(WithComplianceChecker(cc))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "a", Action: "x"})
	if dec.Verdict != string(contracts.VerdictDeny) || dec.ReasonCode != "COMPLIANCE_ERROR" {
		t.Fatalf("expected DENY/COMPLIANCE_ERROR, got %s/%s", dec.Verdict, dec.ReasonCode)
	}
}

// ─── 4: Behavioral score recorded on ALLOW path ─────────────

func TestExt2_BehavioralScoreRecordedOnAllow(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	g := newMinimalGuardian(WithBehavioralTrustScorer(scorer))
	g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "agent-1", Action: "x"})
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

// ─── 5: Behavioral score recorded on DENY (compliance) ──────

func TestExt2_BehavioralScoreRecordedOnComplianceDeny(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	cc := &ext2ComplianceChecker{compliant: false, reason: "blocked"}
	g := newMinimalGuardian(WithBehavioralTrustScorer(scorer), WithComplianceChecker(cc))
	g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "agent-2", Action: "x"})
	score := scorer.GetScore("agent-2")
	if score.Score >= 500 {
		t.Fatalf("expected score below 500 after compliance violation, got %d", score.Score)
	}
}

// ─── 6: Privilege tier context injection ─────────────────────

func TestExt2_PrivilegeTierContextInjection(t *testing.T) {
	resolver := NewStaticPrivilegeResolver(TierStandard)
	g := newMinimalGuardian(WithPrivilegeResolver(resolver))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1", Action: "SEND_EMAIL", Resource: "tool",
	})
	if dec.InputContext == nil {
		t.Fatal("expected InputContext to be set")
	}
	tier, ok := dec.InputContext["privilege_tier"].(string)
	if !ok || tier != "STANDARD" {
		t.Fatalf("expected privilege_tier=STANDARD, got %v", dec.InputContext["privilege_tier"])
	}
}

// ─── 7: Privilege tier DENY for insufficient tier ────────────

func TestExt2_PrivilegeTierDenyInsufficient(t *testing.T) {
	resolver := NewStaticPrivilegeResolver(TierRestricted)
	g := newMinimalGuardian(WithPrivilegeResolver(resolver))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1", Action: "INFRA_DESTROY",
	})
	if dec.Verdict != string(contracts.VerdictDeny) || dec.ReasonCode != string(contracts.ReasonInsufficientPrivilege) {
		t.Fatalf("expected DENY/INSUFFICIENT_PRIVILEGE, got %s/%s", dec.Verdict, dec.ReasonCode)
	}
}

// ─── 8: Privilege tier ALLOW for system tier ─────────────────

func TestExt2_PrivilegeTierAllowSystem(t *testing.T) {
	resolver := NewStaticPrivilegeResolver(TierSystem)
	g := newMinimalGuardian(WithPrivilegeResolver(resolver))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1", Action: "INFRA_DESTROY",
	})
	// Should NOT be denied for privilege (may be denied for other reasons like no policy)
	if dec.ReasonCode == string(contracts.ReasonInsufficientPrivilege) {
		t.Fatal("TierSystem should not be denied for INFRA_DESTROY on privilege grounds")
	}
}

// ─── 9: Freeze + kill switch — freeze takes priority ─────────

func TestExt2_FreezeAndKillSwitchBothActive(t *testing.T) {
	fc := kernel.NewFreezeController()
	fc.Freeze("admin")
	ks := kernel.NewAgentKillSwitch()
	ks.Kill("agent-1", "admin", "bad")
	g := newMinimalGuardian(WithFreezeController(fc), WithAgentKillSwitch(ks))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "agent-1", Action: "x"})
	// Gate 0 (freeze) fires before gate 0.5 (kill switch)
	if dec.ReasonCode != string(contracts.ReasonSystemFrozen) {
		t.Fatalf("expected SYSTEM_FROZEN (freeze takes precedence), got %s", dec.ReasonCode)
	}
}

// ─── 10: Kill switch + context guard — kill switch first ─────

func TestExt2_KillSwitchBeforeContextGuard(t *testing.T) {
	ks := kernel.NewAgentKillSwitch()
	ks.Kill("agent-1", "admin", "test")
	cg := kernel.NewContextGuardWithFingerprint("mismatch-fp")
	g := newMinimalGuardian(WithAgentKillSwitch(ks), WithContextGuard(cg))
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "agent-1", Action: "x"})
	if dec.ReasonCode != string(contracts.ReasonAgentKilled) {
		t.Fatalf("expected AGENT_KILLED before CONTEXT_MISMATCH, got %s", dec.ReasonCode)
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

// ─── 13: ComplianceChecker nil safety — no panic ─────────────

func TestExt2_ComplianceCheckerNilSafety(t *testing.T) {
	g := newMinimalGuardian() // no compliance checker set
	dec, err := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "a", Action: "x"})
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
	dec, _ := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "agent-1", Action: "x"})
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

// ─── 15: EffectiveTier downgrade under HOSTILE trust ─────────

func TestExt2_EffectiveTierHostileDowngrade(t *testing.T) {
	got := EffectiveTier(TierSystem, trust.TierHostile)
	if got != TierRestricted {
		t.Fatalf("expected TierRestricted under HOSTILE, got %s", got)
	}
}

// ─── 16: EffectiveTier cap under SUSPECT trust ──────────────

func TestExt2_EffectiveTierSuspectCap(t *testing.T) {
	got := EffectiveTier(TierElevated, trust.TierSuspect)
	if got != TierStandard {
		t.Fatalf("expected TierStandard cap under SUSPECT, got %s", got)
	}
}

// ─── 17: EffectiveTier no change under TRUSTED ──────────────

func TestExt2_EffectiveTierNoChangeUnderTrusted(t *testing.T) {
	got := EffectiveTier(TierElevated, trust.TierTrusted)
	if got != TierElevated {
		t.Fatalf("expected TierElevated unchanged, got %s", got)
	}
}

// ─── 18: RequiredTierForEffect unknown defaults to Standard ─

func TestExt2_RequiredTierUnknownDefaultsStandard(t *testing.T) {
	tier := RequiredTierForEffect("TOTALLY_UNKNOWN_EFFECT")
	if tier != TierStandard {
		t.Fatalf("expected TierStandard for unknown effect, got %s", tier)
	}
}

// ─── 19: RequiredTierForEffect INFRA_DESTROY is System ──────

func TestExt2_RequiredTierInfraDestroyIsSystem(t *testing.T) {
	tier := RequiredTierForEffect("INFRA_DESTROY")
	if tier != TierSystem {
		t.Fatalf("expected TierSystem, got %s", tier)
	}
}

// ─── 20: StaticPrivilegeResolver default tier ────────────────

func TestExt2_StaticPrivilegeResolverDefault(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierElevated)
	tier, err := r.ResolveTier(context.Background(), "unknown-agent")
	if err != nil || tier != TierElevated {
		t.Fatalf("expected TierElevated default, got %s (err=%v)", tier, err)
	}
}

// ─── 21: StaticPrivilegeResolver override per principal ──────

func TestExt2_StaticPrivilegeResolverOverride(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierStandard)
	r.SetTier("admin-agent", TierSystem)
	tier, _ := r.ResolveTier(context.Background(), "admin-agent")
	if tier != TierSystem {
		t.Fatalf("expected TierSystem override, got %s", tier)
	}
}

// ─── 22: AuditLog chain verification on append ──────────────

func TestExt2_AuditLogChainVerificationAfterAppend(t *testing.T) {
	log := NewAuditLog()
	log.Append("actor", "action", "target", "detail")
	log.Append("actor2", "action2", "target2", "detail2")
	ok, err := log.VerifyChain()
	if err != nil || !ok {
		t.Fatalf("chain verification failed: ok=%v err=%v", ok, err)
	}
}

// ─── 23: AuditLog tamper detection ──────────────────────────

func TestExt2_AuditLogTamperDetection(t *testing.T) {
	log := NewAuditLog()
	log.Append("a", "b", "c", "d")
	log.Append("e", "f", "g", "h")
	// Tamper with first entry's hash
	log.Entries[0].Hash = "tampered"
	ok, _ := log.VerifyChain()
	if ok {
		t.Fatal("expected chain verification to fail after tampering")
	}
}

// ─── 24: PrivilegeTier String representations ────────────────

func TestExt2_PrivilegeTierStringRepresentations(t *testing.T) {
	cases := map[PrivilegeTier]string{
		TierRestricted: "RESTRICTED",
		TierStandard:   "STANDARD",
		TierElevated:   "ELEVATED",
		TierSystem:     "SYSTEM",
	}
	for tier, want := range cases {
		if got := tier.String(); got != want {
			t.Errorf("tier %d: expected %s, got %s", tier, want, got)
		}
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
