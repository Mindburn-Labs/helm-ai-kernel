package governance

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ─── 1: PolicyEngine load and list ───────────────────────────────

func TestExt2_PolicyEngineLoadAndList(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatal(err)
	}
	if err := pe.LoadPolicy("p1", `action == "read"`); err != nil {
		t.Fatal(err)
	}
	defs := pe.ListDefinitions()
	if defs["p1"] != `action == "read"` {
		t.Fatalf("expected policy source, got %q", defs["p1"])
	}
}

// ─── 2: PolicyEngine evaluate allow ──────────────────────────────

func TestExt2_PolicyEngineEvaluateAllow(t *testing.T) {
	pe, _ := NewPolicyEngine()
	pe.LoadPolicy("p1", `action == "read"`)
	req := contracts.AccessRequest{Action: "read", PrincipalID: "u1", ResourceID: "r1", Context: map[string]interface{}{}}
	d, err := pe.Evaluate(context.Background(), "p1", req)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s", d.Verdict)
	}
}

// ─── 3: PolicyEngine evaluate deny ───────────────────────────────

func TestExt2_PolicyEngineEvaluateDeny(t *testing.T) {
	pe, _ := NewPolicyEngine()
	pe.LoadPolicy("p1", `action == "read"`)
	req := contracts.AccessRequest{Action: "write", PrincipalID: "u1", ResourceID: "r1", Context: map[string]interface{}{}}
	d, _ := pe.Evaluate(context.Background(), "p1", req)
	if d.Verdict != "DENY" {
		t.Fatalf("expected DENY, got %s", d.Verdict)
	}
}

// ─── 4: PolicyEngine missing policy defaults deny ────────────────

func TestExt2_PolicyEngineMissingPolicyDeny(t *testing.T) {
	pe, _ := NewPolicyEngine()
	req := contracts.AccessRequest{Action: "read", PrincipalID: "u1", ResourceID: "r1", Context: map[string]interface{}{}}
	d, _ := pe.Evaluate(context.Background(), "nonexistent", req)
	if d.Verdict != "DENY" {
		t.Fatalf("missing policy should DENY, got %s", d.Verdict)
	}
}

// ─── 5: PolicyEngine no policy ID defaults deny ─────────────────

func TestExt2_PolicyEngineNoPolicyIDDeny(t *testing.T) {
	pe, _ := NewPolicyEngine()
	req := contracts.AccessRequest{Action: "read", PrincipalID: "u1", ResourceID: "r1", Context: map[string]interface{}{}}
	d, _ := pe.Evaluate(context.Background(), "", req)
	if d.Verdict != "DENY" {
		t.Fatalf("empty policyID should DENY, got %s", d.Verdict)
	}
}

// ─── 6: PolicyEngine compile error rejected ──────────────────────

func TestExt2_PolicyEngineCompileError(t *testing.T) {
	pe, _ := NewPolicyEngine()
	err := pe.LoadPolicy("bad", `!!!invalid-cel`)
	if err == nil {
		t.Fatal("expected compile error for invalid CEL")
	}
}

// ─── 7: DelegationRevocationList revoke and check ────────────────

func TestExt2_RevocationListRevokeAndCheck(t *testing.T) {
	drl := NewDelegationRevocationList()
	drl.Revoke("d1", "admin", "compromised")
	if !drl.IsRevoked("d1") {
		t.Fatal("d1 should be revoked")
	}
}

// ─── 8: DelegationRevocationList double revoke error ─────────────

func TestExt2_RevocationListDoubleRevokeError(t *testing.T) {
	drl := NewDelegationRevocationList()
	drl.Revoke("d1", "admin", "reason")
	err := drl.Revoke("d1", "admin", "again")
	if err == nil {
		t.Fatal("expected error for double revoke")
	}
}

// ─── 9: PDPAttestation mark suspect ──────────────────────────────

func TestExt2_PDPAttestationMarkSuspect(t *testing.T) {
	att := NewPDPAttestation("pdp-1", time.Hour)
	att.MarkSuspect()
	if att.Status != PDPAttestationSuspect {
		t.Fatalf("expected SUSPECT, got %s", att.Status)
	}
}

// ─── 10: CompromiseDetector fail-closed for suspect PDP ──────────

func TestExt2_CompromiseDetectorFailClosedSuspect(t *testing.T) {
	cd := NewCompromiseDetector()
	att := NewPDPAttestation("pdp-1", time.Hour)
	cd.RegisterAttestation(att)
	cd.ReportAnomaly("pdp-1", AnomalyTypeTimingAnomaly, "latency spike", 6)
	if !cd.ShouldFailClosed("pdp-1") {
		t.Fatal("suspect PDP should fail closed")
	}
}

// ─── 11: CompromiseDetector below threshold stays valid ──────────

func TestExt2_CompromiseDetectorBelowThreshold(t *testing.T) {
	cd := NewCompromiseDetector()
	att := NewPDPAttestation("pdp-1", time.Hour)
	cd.RegisterAttestation(att)
	cd.ReportAnomaly("pdp-1", AnomalyTypeTimingAnomaly, "minor", 2)
	if cd.ShouldFailClosed("pdp-1") {
		t.Fatal("below-threshold anomaly should not trigger fail-closed")
	}
}

// ─── 12: CompromiseDetector unknown PDP returns expired ──────────

func TestExt2_CompromiseDetectorUnknownPDP(t *testing.T) {
	cd := NewCompromiseDetector()
	status := cd.GetPDPStatus("unknown")
	if status != PDPAttestationExpired {
		t.Fatalf("unknown PDP should return EXPIRED, got %s", status)
	}
}

// ─── 13: Compensation escalate on max attempts ──────────────────

func TestExt2_CompensationEscalateOnMax(t *testing.T) {
	cs := NewCompensationState("tx1", "op1", CompensationPolicyEscalate)
	cs.RecordAttempt(false, "err1")
	cs.RecordAttempt(false, "err2")
	outcome := cs.RecordAttempt(false, "err3")
	if outcome != CompensationOutcomeEscalate {
		t.Fatalf("expected ESCALATE, got %s", outcome)
	}
}

// ─── 14: Compensation success on first attempt ──────────────────

func TestExt2_CompensationSuccessFirst(t *testing.T) {
	cs := NewCompensationState("tx1", "op1", CompensationPolicyRetry)
	outcome := cs.RecordAttempt(true, "")
	if outcome != CompensationOutcomeSuccess {
		t.Fatalf("expected SUCCESS, got %s", outcome)
	}
}

// ─── 15: Compensation fallback policy ────────────────────────────

func TestExt2_CompensationFallbackPolicy(t *testing.T) {
	cs := NewCompensationState("tx1", "op1", CompensationPolicyFallback)
	for i := 0; i < MaxCompensationAttempts; i++ {
		cs.RecordAttempt(false, "err")
	}
	if !cs.FallbackExecuted {
		t.Fatal("fallback should have been executed")
	}
}

// ─── 16: Compensation NeedsIntervention ──────────────────────────

func TestExt2_CompensationNeedsIntervention(t *testing.T) {
	cs := NewCompensationState("tx1", "op1", CompensationPolicyManual)
	for i := 0; i < MaxCompensationAttempts; i++ {
		cs.RecordAttempt(false, "err")
	}
	if !cs.NeedsIntervention() {
		t.Fatal("manual policy at max attempts should need intervention")
	}
}

// ─── 17: Arbitrate STRICTEST_WINS escalate trumps allow ─────────

func TestExt2_ArbitrateStrictestEscalateOverAllow(t *testing.T) {
	inputs := []ArbitrationInput{
		{RuleID: "r1", Decision: "ALLOW", Priority: 1},
		{RuleID: "r2", Decision: "ESCALATE", Priority: 1},
	}
	result := Arbitrate(inputs, StrategyStrictest)
	if result.Resolution != "ESCALATE" {
		t.Fatalf("expected ESCALATE, got %s", result.Resolution)
	}
}

// ─── 18: Arbitrate PRIORITY_ORDERED highest priority wins ────────

func TestExt2_ArbitratePriorityOrdered(t *testing.T) {
	inputs := []ArbitrationInput{
		{RuleID: "r1", Decision: "DENY", Priority: 1},
		{RuleID: "r2", Decision: "ALLOW", Priority: 10},
	}
	result := Arbitrate(inputs, StrategyPriority)
	if result.Resolution != "ALLOW" {
		t.Fatalf("expected ALLOW (higher priority), got %s", result.Resolution)
	}
}

// ─── 19: Arbitrate MOST_SPECIFIC agent beats global ──────────────

func TestExt2_ArbitrateMostSpecificAgentWins(t *testing.T) {
	inputs := []ArbitrationInput{
		{RuleID: "r1", Decision: "DENY", Scope: "GLOBAL"},
		{RuleID: "r2", Decision: "ALLOW", Scope: "AGENT"},
	}
	result := Arbitrate(inputs, StrategySpecific)
	if result.Resolution != "ALLOW" {
		t.Fatalf("AGENT scope should beat GLOBAL, got %s", result.Resolution)
	}
}

// ─── 20: Arbitrate single input returns nil ──────────────────────

func TestExt2_ArbitrateSingleInputNil(t *testing.T) {
	result := Arbitrate([]ArbitrationInput{{RuleID: "r1", Decision: "ALLOW"}}, StrategyPriority)
	if result != nil {
		t.Fatal("single input should return nil")
	}
}

// ─── 21: EvolutionGovernance C0 auto-approve ─────────────────────

func TestExt2_SelfModC0AutoApprove(t *testing.T) {
	eg := NewEvolutionGovernance()
	ok, reason := eg.EvaluateChange(context.Background(), ChangeClassC0, true)
	if !ok || reason != "APPROVED_AUTO" {
		t.Fatalf("C0 with pass should auto-approve, got ok=%v reason=%s", ok, reason)
	}
}

// ─── 22: EvolutionGovernance C1 reject on test failure ───────────

func TestExt2_SelfModC1RejectTestFail(t *testing.T) {
	eg := NewEvolutionGovernance()
	ok, _ := eg.EvaluateChange(context.Background(), ChangeClassC1, false)
	if ok {
		t.Fatal("C1 with test failure should reject")
	}
}

// ─── 23: EvolutionGovernance C2 requires verification ────────────

func TestExt2_SelfModC2Verified(t *testing.T) {
	eg := NewEvolutionGovernance()
	ok, reason := eg.EvaluateChange(context.Background(), ChangeClassC2, true)
	if !ok || reason != "APPROVED_VERIFIED" {
		t.Fatalf("C2 with pass should be APPROVED_VERIFIED, got ok=%v reason=%s", ok, reason)
	}
}

// ─── 24: EvolutionGovernance C3 always blocked ───────────────────

func TestExt2_SelfModC3AlwaysBlocked(t *testing.T) {
	eg := NewEvolutionGovernance()
	ok, reason := eg.EvaluateChange(context.Background(), ChangeClassC3, true)
	if ok {
		t.Fatal("C3 should always be blocked")
	}
	if reason != "BLOCKED_REQUIRES_HUMAN_APPROVAL" {
		t.Fatalf("expected BLOCKED_REQUIRES_HUMAN_APPROVAL, got %s", reason)
	}
}

// ─── 25: Canary default config ───────────────────────────────────

func TestExt2_CanaryDefaultConfig(t *testing.T) {
	if DefaultCanary.Steps != 3 || DefaultCanary.StepDurationSec != 300 {
		t.Fatalf("unexpected default canary: steps=%d dur=%d", DefaultCanary.Steps, DefaultCanary.StepDurationSec)
	}
}

// ─── 26: Canary fast config ─────────────────────────────────────

func TestExt2_CanaryFastConfig(t *testing.T) {
	if FastCanary.Steps != 1 || FastCanary.StepDurationSec != 30 {
		t.Fatalf("unexpected fast canary: steps=%d dur=%d", FastCanary.Steps, FastCanary.StepDurationSec)
	}
}

// ─── 27: Data classifier detects PII email ───────────────────────

func TestExt2_ClassifierDetectsEmail(t *testing.T) {
	c := NewClassifier()
	class := c.Classify("contact me at user@example.com")
	if class != DataClassConfidential {
		t.Fatalf("expected CONFIDENTIAL for email, got %s", class)
	}
}

// ─── 28: Data classifier detects private key ─────────────────────

func TestExt2_ClassifierDetectsPrivateKey(t *testing.T) {
	c := NewClassifier()
	class := c.Classify("-----BEGIN PRIVATE KEY-----")
	if class != DataClassRestricted {
		t.Fatalf("expected RESTRICTED for private key, got %s", class)
	}
}

// ─── 29: Data classifier defaults to internal ────────────────────

func TestExt2_ClassifierDefaultsInternal(t *testing.T) {
	c := NewClassifier()
	class := c.Classify("general business notes")
	if class != DataClassInternal {
		t.Fatalf("expected INTERNAL, got %s", class)
	}
}

// ─── 30: CEL PDP fail-closed on cancelled context ────────────────

func TestExt2_CELPDPFailClosedCancelledContext(t *testing.T) {
	pdp, err := NewCELPolicyDecisionPoint("hash-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, _ := pdp.Evaluate(ctx, PDPRequest{RequestID: "req-1"})
	if resp.Decision != DecisionDeny {
		t.Fatalf("cancelled context should DENY, got %s", resp.Decision)
	}
}
