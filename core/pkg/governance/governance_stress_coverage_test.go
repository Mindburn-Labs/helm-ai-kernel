package governance

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ── Jurisdiction with 100 rules ─────────────────────────────────────────

func TestStress_Jurisdiction100Rules(t *testing.T) {
	resolver := NewJurisdictionResolver()
	for i := range 100 {
		resolver.AddRule(JurisdictionRule{
			RuleID:      fmt.Sprintf("rule-%d", i),
			LegalRegime: fmt.Sprintf("regime-%d", i%5),
			Region:      fmt.Sprintf("region-%d", i%10),
			Requirement: fmt.Sprintf("req-%d", i),
			Priority:    i,
		})
	}
	ctx, err := resolver.Resolve("entity-1", "cp-1", "ds-1", "region-0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ctx.ContextID == "" {
		t.Fatal("context ID empty")
	}
}

func TestStress_JurisdictionConflictDetection(t *testing.T) {
	resolver := NewJurisdictionResolver()
	resolver.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "eu", Priority: 1})
	resolver.AddRule(JurisdictionRule{RuleID: "r2", LegalRegime: "US/CCPA", Region: "eu", Priority: 1})
	ctx, err := resolver.Resolve("e1", "", "", "eu")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(ctx.Conflicts) == 0 {
		t.Fatal("should detect conflict between EU/GDPR and US/CCPA")
	}
}

func TestStress_JurisdictionMissingRegion(t *testing.T) {
	resolver := NewJurisdictionResolver()
	_, err := resolver.Resolve("e1", "", "", "")
	if err == nil {
		t.Fatal("empty region should fail")
	}
}

// ── Liveness with 50 probes ─────────────────────────────────────────────

func TestStress_Liveness50Probes(t *testing.T) {
	for i := range 50 {
		bs := NewBlockingState(fmt.Sprintf("bs-%d", i), BlockingStateApproval, 1*time.Hour)
		if bs.State != LivenessStatePending {
			t.Fatalf("probe %d: expected PENDING, got %s", i, bs.State)
		}
		if bs.IsExpired() {
			t.Fatalf("probe %d: should not be expired", i)
		}
	}
}

func TestStress_LivenessResolve(t *testing.T) {
	bs := NewBlockingState("bs-resolve", BlockingStateApproval, 1*time.Hour)
	bs.Resolve()
	if bs.State != LivenessStateActive {
		t.Fatalf("expected ACTIVE, got %s", bs.State)
	}
}

func TestStress_LivenessCancel(t *testing.T) {
	bs := NewBlockingState("bs-cancel", BlockingStateObligation, 1*time.Hour)
	bs.Cancel()
	if bs.State != LivenessStateCanceled {
		t.Fatalf("expected CANCELED, got %s", bs.State)
	}
}

func TestStress_LivenessExpire(t *testing.T) {
	bs := NewBlockingState("bs-expire", BlockingStateLease, 1*time.Nanosecond)
	time.Sleep(2 * time.Millisecond)
	if !bs.IsExpired() {
		t.Fatal("should be expired")
	}
}

func TestStress_LivenessTimeRemaining(t *testing.T) {
	bs := NewBlockingState("bs-tr", BlockingStateResource, 1*time.Hour)
	if bs.TimeRemaining() < 59*time.Minute {
		t.Fatal("time remaining should be close to 1h")
	}
}

// ── Plan Commit with 20 concurrent submitters ───────────────────────────

func TestStress_PlanCommit20Concurrent(t *testing.T) {
	pc := NewPlanCommitController()
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			plan := &ExecutionPlan{
				PlanID: fmt.Sprintf("plan-%d", idx), EffectType: "test",
				Principal: "admin", Description: "stress test",
			}
			_, err := pc.SubmitPlan(plan)
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	if len(errs) > 0 {
		t.Fatalf("got %d submit errors", len(errs))
	}
}

func TestStress_PlanCommitDuplicate(t *testing.T) {
	pc := NewPlanCommitController()
	plan := &ExecutionPlan{PlanID: "dup", EffectType: "test", Principal: "admin"}
	_, _ = pc.SubmitPlan(plan)
	_, err := pc.SubmitPlan(plan)
	if err == nil {
		t.Fatal("duplicate plan should fail")
	}
}

func TestStress_PlanCommitNilPlan(t *testing.T) {
	pc := NewPlanCommitController()
	_, err := pc.SubmitPlan(nil)
	if err == nil {
		t.Fatal("nil plan should fail")
	}
}

// ── Swarm PDP ───────────────────────────────────────────────────────────

func TestStress_SwarmPDPDefaultConfig(t *testing.T) {
	cfg := DefaultSwarmPDPConfig()
	if cfg.MaxParallelPDPs != 16 {
		t.Fatalf("expected 16, got %d", cfg.MaxParallelPDPs)
	}
	if !cfg.StrictMerge {
		t.Fatal("strict merge should be true by default")
	}
}

func TestStress_SwarmPDPMetric(t *testing.T) {
	m := NewSwarmPDPMetric()
	for range 10 {
		m.RecordBatch(5, []int{3}, 1)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.TotalBatches != 10 {
		t.Fatalf("expected 10 batches, got %d", m.TotalBatches)
	}
}

// ── Risk Envelope with 100 actions ──────────────────────────────────────

func TestStress_RiskEnvelope100Actions(t *testing.T) {
	ra := NewAggregateRiskAccounting(1*time.Hour, 1000.0)
	for i := range 100 {
		ra.RegisterEnvelope(&RiskEnvelope{
			EnvelopeID: fmt.Sprintf("env-%d", i), ActionType: fmt.Sprintf("action-%d", i),
			MaxRisk: 10.0, Weight: 1.0, Level: RiskLow,
		})
	}
	for i := range 100 {
		err := ra.CheckAndRecord(fmt.Sprintf("action-%d", i), 5.0)
		if err != nil {
			t.Fatalf("action-%d: %v", i, err)
		}
	}
}

func TestStress_RiskEnvelopeExceedsMax(t *testing.T) {
	ra := NewAggregateRiskAccounting(1*time.Hour, 100.0)
	ra.RegisterEnvelope(&RiskEnvelope{EnvelopeID: "e1", ActionType: "a1", MaxRisk: 5.0, Weight: 1.0})
	err := ra.CheckAndRecord("a1", 10.0)
	if err == nil {
		t.Fatal("should fail: risk exceeds envelope max")
	}
}

func TestStress_RiskEnvelopeAggregateExceeded(t *testing.T) {
	ra := NewAggregateRiskAccounting(1*time.Hour, 10.0)
	ra.RegisterEnvelope(&RiskEnvelope{EnvelopeID: "e1", ActionType: "a1", MaxRisk: 100.0, Weight: 1.0})
	for range 10 {
		_ = ra.CheckAndRecord("a1", 1.0)
	}
	err := ra.CheckAndRecord("a1", 1.0)
	if err == nil {
		t.Fatal("should fail: aggregate exceeded")
	}
}

func TestStress_RiskEnvelopeCurrentAggregate(t *testing.T) {
	ra := NewAggregateRiskAccounting(1*time.Hour, 1000.0)
	ra.RegisterEnvelope(&RiskEnvelope{EnvelopeID: "e1", ActionType: "a1", MaxRisk: 100.0, Weight: 2.0})
	_ = ra.CheckAndRecord("a1", 5.0)
	agg := ra.CurrentAggregate()
	if agg < 9.9 || agg > 10.1 { // 5.0 * 2.0 = 10.0
		t.Fatalf("expected ~10.0, got %.2f", agg)
	}
}

// ── Policy Engine with 50 policies ──────────────────────────────────────

func TestStress_PolicyEngine50Policies(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	for i := range 50 {
		source := fmt.Sprintf(`action == "read-%d"`, i)
		if err := pe.LoadPolicy(fmt.Sprintf("p-%d", i), source); err != nil {
			t.Fatalf("load policy %d: %v", i, err)
		}
	}
	defs := pe.ListDefinitions()
	if len(defs) != 50 {
		t.Fatalf("expected 50 definitions, got %d", len(defs))
	}
}

func TestStress_PolicyEngineEvaluate(t *testing.T) {
	pe, _ := NewPolicyEngine()
	_ = pe.LoadPolicy("allow-read", `action == "read"`)
	decision, err := pe.Evaluate(context.Background(), "allow-read", contracts.AccessRequest{
		PrincipalID: "user-1", Action: "read", ResourceID: "doc-1",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision == nil {
		t.Fatal("decision should not be nil")
	}
}

func TestStress_PolicyEngineInvalidCEL(t *testing.T) {
	pe, _ := NewPolicyEngine()
	err := pe.LoadPolicy("bad", "!!!invalid CEL!!!")
	if err == nil {
		t.Fatal("invalid CEL should fail compilation")
	}
}

// ── Security: delegation revocation ─────────────────────────────────────

func TestStress_DelegationRevocation(t *testing.T) {
	drl := NewDelegationRevocationList()
	for i := range 20 {
		err := drl.Revoke(fmt.Sprintf("del-%d", i), "admin", "test")
		if err != nil {
			t.Fatalf("revoke %d: %v", i, err)
		}
	}
	for i := range 20 {
		if !drl.IsRevoked(fmt.Sprintf("del-%d", i)) {
			t.Fatalf("del-%d should be revoked", i)
		}
	}
}

func TestStress_DelegationDoubleRevoke(t *testing.T) {
	drl := NewDelegationRevocationList()
	_ = drl.Revoke("del-1", "admin", "reason")
	err := drl.Revoke("del-1", "admin", "reason2")
	if err == nil {
		t.Fatal("double revoke should fail")
	}
}

func TestStress_DelegationGetEntry(t *testing.T) {
	drl := NewDelegationRevocationList()
	_ = drl.Revoke("del-x", "admin", "test")
	entry, ok := drl.GetEntry("del-x")
	if !ok || entry.RevokedBy != "admin" {
		t.Fatal("entry mismatch")
	}
}

// ── Compensation state ──────────────────────────────────────────────────

func TestStress_CompensationStateRetry(t *testing.T) {
	cs := NewCompensationState("tx-1", "op-1", CompensationPolicyRetry)
	outcome := cs.RecordAttempt(false, "fail")
	if outcome != CompensationOutcomeRetry {
		t.Fatalf("expected RETRY, got %v", outcome)
	}
}

func TestStress_CompensationStateMaxAttempts(t *testing.T) {
	cs := NewCompensationState("tx-2", "op-2", CompensationPolicyEscalate)
	for range MaxCompensationAttempts {
		cs.RecordAttempt(false, "fail")
	}
	if cs.AttemptCount != MaxCompensationAttempts {
		t.Fatalf("expected %d attempts, got %d", MaxCompensationAttempts, cs.AttemptCount)
	}
}

func TestStress_CompensationStateSuccess(t *testing.T) {
	cs := NewCompensationState("tx-3", "op-3", CompensationPolicyRetry)
	outcome := cs.RecordAttempt(true, "")
	if outcome != CompensationOutcomeSuccess {
		t.Fatalf("expected SUCCESS, got %v", outcome)
	}
}

// ── Risk level constants ────────────────────────────────────────────────

func TestStress_RiskLevelConstants(t *testing.T) {
	levels := map[RiskLevel]string{RiskNone: "NONE", RiskLow: "LOW", RiskMedium: "MEDIUM", RiskHigh: "HIGH", RiskCritical: "CRITICAL"}
	for level, expected := range levels {
		if string(level) != expected {
			t.Fatalf("expected %s, got %s", expected, level)
		}
	}
}

// ── Liveness state types ────────────────────────────────────────────────

func TestStress_BlockingStateTypes(t *testing.T) {
	types := []BlockingStateType{BlockingStateApproval, BlockingStateObligation, BlockingStateLease, BlockingStateResource}
	for _, st := range types {
		bs := NewBlockingState("id", st, time.Hour)
		if bs.StateType != st {
			t.Fatalf("expected %s, got %s", st, bs.StateType)
		}
	}
}

func TestStress_SequencerLeaseDefault(t *testing.T) {
	bs := NewSequencerLease("lease-1", 0)
	if bs.Timeout != DefaultLeaseTimeout {
		t.Fatalf("expected %v, got %v", DefaultLeaseTimeout, bs.Timeout)
	}
}

func TestStress_ApprovalStateDefault(t *testing.T) {
	bs := NewApprovalState("a-1", 0)
	if bs.Timeout != DefaultApprovalTimeout {
		t.Fatalf("expected %v, got %v", DefaultApprovalTimeout, bs.Timeout)
	}
}

func TestStress_ObligationStateDefault(t *testing.T) {
	bs := NewObligationState("o-1", 0)
	if bs.Timeout != DefaultObligationTimeout {
		t.Fatalf("expected %v, got %v", DefaultObligationTimeout, bs.Timeout)
	}
}

func TestStress_PlanStatusConstants(t *testing.T) {
	statuses := []PlanStatus{PlanStatusPending, PlanStatusApproved, PlanStatusRejected, PlanStatusTimeout, PlanStatusAborted}
	if len(statuses) != 5 {
		t.Fatal("expected 5 plan statuses")
	}
}

func TestStress_LivenessStateConstants(t *testing.T) {
	states := []LivenessState{LivenessStateActive, LivenessStatePending, LivenessStateExpired, LivenessStateCanceled}
	if len(states) != 4 {
		t.Fatal("expected 4 liveness states")
	}
}

func TestStress_JurisdictionNoRulesForRegion(t *testing.T) {
	resolver := NewJurisdictionResolver()
	resolver.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU", Region: "eu"})
	_, err := resolver.Resolve("e1", "", "", "us")
	if err == nil {
		t.Fatal("should fail for region with no rules")
	}
}

func TestStress_CompensationPolicyConstants(t *testing.T) {
	policies := []CompensationFailurePolicy{CompensationPolicyRetry, CompensationPolicyEscalate, CompensationPolicyManual, CompensationPolicyFallback}
	if len(policies) != 4 {
		t.Fatal("expected 4 compensation policies")
	}
}

func TestStress_SwarmPDPDomainDecomposition(t *testing.T) {
	cfg := DefaultSwarmPDPConfig()
	if !cfg.DomainDecomposition {
		t.Fatal("domain decomposition should be enabled by default")
	}
}

func TestStress_SwarmPDPEnableMetrics(t *testing.T) {
	cfg := DefaultSwarmPDPConfig()
	if !cfg.EnableMetrics {
		t.Fatal("metrics should be enabled by default")
	}
}

func TestStress_RiskEnvelopeWithClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ra := NewAggregateRiskAccounting(1*time.Hour, 1000.0).WithClock(func() time.Time { return fixed })
	ra.RegisterEnvelope(&RiskEnvelope{EnvelopeID: "e1", ActionType: "a1", MaxRisk: 100.0, Weight: 1.0})
	_ = ra.CheckAndRecord("a1", 1.0)
	if ra.CurrentAggregate() != 1.0 {
		t.Fatal("aggregate should be 1.0")
	}
}

func TestStress_PlanCommitEmptyPlanID(t *testing.T) {
	pc := NewPlanCommitController()
	_, err := pc.SubmitPlan(&ExecutionPlan{})
	if err == nil {
		t.Fatal("empty plan ID should fail")
	}
}

func TestStress_DelegationRevocationListVersion(t *testing.T) {
	drl := NewDelegationRevocationList()
	if drl.Version != "1.0.0" {
		t.Fatalf("expected 1.0.0, got %s", drl.Version)
	}
}
