package governance

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── CEL Deterministic Validator Tests ────────────────────────────

func TestDeepCELDPValidatorBannedFunctions(t *testing.T) {
	v := NewCELDPValidator()
	banned := []string{
		"now()", "timestamp(x)", "duration(x)", "random()", "uuid()",
		"getDate()", "getFullYear()", "getHours()", "getMinutes()",
		"getMonth()", "getSeconds()", "getMilliseconds()", "getDayOfMonth()",
		"getDayOfWeek()", "getDayOfYear()", "getTimezoneOffset()", "matches(x)",
	}
	for _, expr := range banned {
		issues := v.ValidateExpression(expr)
		if len(issues) == 0 {
			t.Fatalf("expected issues for banned expression %q", expr)
		}
	}
}

func TestDeepCELDPValidatorAllowedFunctions(t *testing.T) {
	v := NewCELDPValidator()
	allowed := []string{
		`x.contains("foo")`, `x.startsWith("bar")`, `x.endsWith("baz")`,
		`x + y`, `x == true`, `x > 10`,
	}
	for _, expr := range allowed {
		issues := v.ValidateExpression(expr)
		if len(issues) != 0 {
			t.Fatalf("unexpected issues for allowed expression %q: %v", expr, issues)
		}
	}
}

func TestDeepCELDPValidatorBannedTypes(t *testing.T) {
	v := NewCELDPValidator()
	issues := v.ValidateExpression("double(x)")
	hasBannedType := false
	for _, i := range issues {
		if i.Type == "banned_type" {
			hasBannedType = true
		}
	}
	if !hasBannedType {
		t.Fatal("expected banned_type issue for double")
	}
}

func TestDeepCELDPValidatorDynamicOps(t *testing.T) {
	v := NewCELDPValidator()
	for _, expr := range []string{"type(x)", "dyn(y)"} {
		issues := v.ValidateExpression(expr)
		hasND := false
		for _, i := range issues {
			if i.Type == "nondeterministic" {
				hasND = true
			}
		}
		if !hasND {
			t.Fatalf("expected nondeterministic issue for %q", expr)
		}
	}
}

func TestDeepCELDPValidateAndAnalyze(t *testing.T) {
	v := NewCELDPValidator()
	info := v.ValidateAndAnalyze("x + y > 10")
	if !info.Valid {
		t.Fatal("simple arithmetic should be valid")
	}
	if info.ProfileID != CELDPProfileID {
		t.Fatal("profile ID mismatch")
	}
}

func TestDeepCELDPHashErrorMessageDeterministic(t *testing.T) {
	h1 := HashErrorMessage("Division by zero")
	h2 := HashErrorMessage("division  by  zero")
	if h1 != h2 {
		t.Fatal("normalized messages should produce same hash")
	}
}

func TestDeepCELDPHashErrorMessageDifferent(t *testing.T) {
	h1 := HashErrorMessage("error A")
	h2 := HashErrorMessage("error B")
	if h1 == h2 {
		t.Fatal("different messages should produce different hashes")
	}
}

func TestDeepCELDPComputeTraceHashEmpty(t *testing.T) {
	if ComputeTraceHash(nil) != "" {
		t.Fatal("empty trace should produce empty hash")
	}
}

func TestDeepCELDPComputeTraceHashDeterministic(t *testing.T) {
	entries := []CELDPTraceEntry{
		{Step: 1, Expression: "x > 0", ResultHash: "abc"},
		{Step: 2, Expression: "y < 10", ResultHash: "def"},
	}
	h1 := ComputeTraceHash(entries)
	h2 := ComputeTraceHash(entries)
	if h1 != h2 || h1 == "" {
		t.Fatal("same trace should produce identical non-empty hash")
	}
}

func TestDeepCELDPNewError(t *testing.T) {
	err := NewCELDPError(CELDPErrorDivZero, "division by zero", &CELDPSpan{Start: 0, End: 5})
	if err.Code != CELDPErrorDivZero || err.Span == nil {
		t.Fatal("error construction failed")
	}
}

// ── Jurisdiction Tests ───────────────────────────────────────────

func TestDeepJurisdictionResolveBasic(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "eu-west-1", Priority: 1})
	ctx, err := r.Resolve("entity-1", "cp-1", "ds-1", "eu-west-1")
	if err != nil || ctx.LegalRegime != "EU/GDPR" {
		t.Fatalf("expected EU/GDPR, got %v, err=%v", ctx, err)
	}
}

func TestDeepJurisdictionResolveWildcard(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "GLOBAL", Region: "*", Priority: 0})
	ctx, err := r.Resolve("entity-1", "", "", "us-east-1")
	if err != nil || ctx.LegalRegime != "GLOBAL" {
		t.Fatal("wildcard rule should match any region")
	}
}

func TestDeepJurisdictionResolveConflict(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "eu-west-1", Priority: 1})
	r.AddRule(JurisdictionRule{RuleID: "r2", LegalRegime: "UK/FCA", Region: "eu-west-1", Priority: 1})
	ctx, err := r.Resolve("e", "cp", "ds", "eu-west-1")
	if err != nil {
		t.Fatal(err)
	}
	if ctx.LegalRegime != "" {
		t.Fatal("equal-priority conflicts should leave regime empty for escalation")
	}
	if len(ctx.Conflicts) == 0 {
		t.Fatal("conflicts should be recorded")
	}
}

func TestDeepJurisdictionResolveNoRules(t *testing.T) {
	r := NewJurisdictionResolver()
	_, err := r.Resolve("e", "", "", "unknown-region")
	if err == nil {
		t.Fatal("should error when no rules match")
	}
}

func TestDeepJurisdictionResolveEmptyEntity(t *testing.T) {
	r := NewJurisdictionResolver()
	_, err := r.Resolve("", "", "", "region")
	if err == nil {
		t.Fatal("should error on empty entity")
	}
}

func TestDeepJurisdictionPriorityWins(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "low", LegalRegime: "LOW_REGIME", Region: "r1", Priority: 0})
	r.AddRule(JurisdictionRule{RuleID: "high", LegalRegime: "HIGH_REGIME", Region: "r1", Priority: 10})
	ctx, _ := r.Resolve("e", "", "", "r1")
	if ctx.LegalRegime != "HIGH_REGIME" {
		t.Fatal("higher priority rule should win")
	}
}

// ── PlanCommit Tests ─────────────────────────────────────────────

func TestDeepPlanCommitSubmitAndApprove(t *testing.T) {
	pc := NewPlanCommitController()
	ref, err := pc.SubmitPlan(&ExecutionPlan{PlanID: "p1", EffectType: "test"})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		pc.Approve("p1", "approver-1")
	}()
	decision, err := pc.WaitForApproval(*ref, 1*time.Second)
	if err != nil || decision.Status != PlanStatusApproved {
		t.Fatal("approval should succeed")
	}
}

func TestDeepPlanCommitReject(t *testing.T) {
	pc := NewPlanCommitController()
	ref, _ := pc.SubmitPlan(&ExecutionPlan{PlanID: "p1"})
	go func() {
		time.Sleep(10 * time.Millisecond)
		pc.Reject("p1", "reviewer", "too risky")
	}()
	decision, _ := pc.WaitForApproval(*ref, 1*time.Second)
	if decision.Status != PlanStatusRejected {
		t.Fatal("rejection should be recorded")
	}
}

func TestDeepPlanCommitTimeout(t *testing.T) {
	pc := NewPlanCommitController()
	ch := make(chan time.Time, 1)
	pc.WithAfter(func(d time.Duration) <-chan time.Time {
		go func() { ch <- time.Now() }()
		return ch
	})
	ref, _ := pc.SubmitPlan(&ExecutionPlan{PlanID: "p1"})
	decision, _ := pc.WaitForApproval(*ref, 10*time.Millisecond)
	if decision.Status != PlanStatusTimeout {
		t.Fatal("should timeout")
	}
}

func TestDeepPlanCommitAbort(t *testing.T) {
	pc := NewPlanCommitController()
	ref, _ := pc.SubmitPlan(&ExecutionPlan{PlanID: "p1"})
	go func() {
		time.Sleep(10 * time.Millisecond)
		pc.Abort("p1")
	}()
	decision, _ := pc.WaitForApproval(*ref, 1*time.Second)
	if decision.Status != PlanStatusAborted {
		t.Fatal("abort should be recorded")
	}
}

func TestDeepPlanCommitNilPlan(t *testing.T) {
	pc := NewPlanCommitController()
	_, err := pc.SubmitPlan(nil)
	if err == nil {
		t.Fatal("nil plan should error")
	}
}

func TestDeepPlanCommitEmptyPlanID(t *testing.T) {
	pc := NewPlanCommitController()
	_, err := pc.SubmitPlan(&ExecutionPlan{})
	if err == nil {
		t.Fatal("empty PlanID should error")
	}
}

func TestDeepPlanCommitDuplicate(t *testing.T) {
	pc := NewPlanCommitController()
	pc.SubmitPlan(&ExecutionPlan{PlanID: "p1"})
	_, err := pc.SubmitPlan(&ExecutionPlan{PlanID: "p1"})
	if err == nil {
		t.Fatal("duplicate plan should error")
	}
}

func TestDeepPlanCommitPendingCount(t *testing.T) {
	pc := NewPlanCommitController()
	pc.SubmitPlan(&ExecutionPlan{PlanID: "p1"})
	pc.SubmitPlan(&ExecutionPlan{PlanID: "p2"})
	if pc.PendingCount() != 2 {
		t.Fatal("should have 2 pending")
	}
}

// ── SwarmPDP Tests ───────────────────────────────────────────────

type mockPDP struct {
	version string
}

func (m *mockPDP) Evaluate(_ context.Context, req PDPRequest) (*PDPResponse, error) {
	return &PDPResponse{Decision: DecisionAllow, DecisionID: req.RequestID, PolicyVersion: m.version}, nil
}
func (m *mockPDP) PolicyVersion() string { return m.version }

func TestDeepSwarmPDPSingleRequest(t *testing.T) {
	base := &mockPDP{version: "v1"}
	swarm := NewSwarmPDP(base, nil)
	resp, err := swarm.Evaluate(context.Background(), PDPRequest{RequestID: "r1"})
	if err != nil || resp.Decision != DecisionAllow {
		t.Fatal("single request should delegate to base PDP")
	}
}

func TestDeepSwarmPDPBatchEmpty(t *testing.T) {
	swarm := NewSwarmPDP(&mockPDP{version: "v1"}, nil)
	result, err := swarm.EvaluateBatch(context.Background(), nil)
	if err != nil || len(result.Responses) != 0 {
		t.Fatal("empty batch should succeed")
	}
}

func TestDeepSwarmPDPMergeDecisionsDenyWins(t *testing.T) {
	swarm := NewSwarmPDP(&mockPDP{version: "v1"}, DefaultSwarmPDPConfig())
	result := swarm.MergeDecisions([]Decision{DecisionAllow, DecisionDeny, DecisionAllow})
	if result != DecisionDeny {
		t.Fatal("strict merge: any DENY should win")
	}
}

func TestDeepSwarmPDPMergeDecisionsAllAllow(t *testing.T) {
	swarm := NewSwarmPDP(&mockPDP{version: "v1"}, DefaultSwarmPDPConfig())
	result := swarm.MergeDecisions([]Decision{DecisionAllow, DecisionAllow})
	if result != DecisionAllow {
		t.Fatal("all ALLOW should yield ALLOW")
	}
}

func TestDeepSwarmPDPMergeDecisionsRequireApproval(t *testing.T) {
	swarm := NewSwarmPDP(&mockPDP{version: "v1"}, DefaultSwarmPDPConfig())
	result := swarm.MergeDecisions([]Decision{DecisionAllow, DecisionRequireApproval})
	if result != DecisionRequireApproval {
		t.Fatal("REQUIRE_APPROVAL should take precedence over ALLOW")
	}
}

func TestDeepSwarmPDPMergeDecisionsEmpty(t *testing.T) {
	swarm := NewSwarmPDP(&mockPDP{version: "v1"}, DefaultSwarmPDPConfig())
	result := swarm.MergeDecisions(nil)
	if result != DecisionDeny {
		t.Fatal("empty decisions should default to DENY")
	}
}

func TestDeepSwarmPDPHash(t *testing.T) {
	swarm := NewSwarmPDP(&mockPDP{version: "v1"}, DefaultSwarmPDPConfig())
	h1 := swarm.Hash()
	h2 := swarm.Hash()
	if h1 != h2 || h1 == "" {
		t.Fatal("hash should be deterministic and non-empty")
	}
}

// ── Liveness Tests ───────────────────────────────────────────────

func TestDeepBlockingStateExpiry(t *testing.T) {
	bs := NewBlockingState("s1", BlockingStateApproval, 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if !bs.IsExpired() {
		t.Fatal("should be expired after timeout")
	}
}

func TestDeepBlockingStateResolve(t *testing.T) {
	bs := NewBlockingState("s1", BlockingStateApproval, 1*time.Hour)
	bs.Resolve()
	if bs.State != LivenessStateActive {
		t.Fatal("resolved state should be ACTIVE")
	}
}

func TestDeepBlockingStateCancel(t *testing.T) {
	bs := NewBlockingState("s1", BlockingStateApproval, 1*time.Hour)
	bs.Cancel()
	if bs.State != LivenessStateCanceled {
		t.Fatal("canceled state should be CANCELED")
	}
}

func TestDeepBlockingStateExtendNonPending(t *testing.T) {
	bs := NewBlockingState("s1", BlockingStateApproval, 1*time.Hour)
	bs.Resolve()
	err := bs.Extend(1 * time.Hour)
	if err == nil {
		t.Fatal("extending non-pending should error")
	}
}

func TestDeepLivenessManagerRegisterAndResolve(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	bs := NewBlockingState("s1", BlockingStateApproval, 1*time.Hour)
	lm.Register(bs)
	if err := lm.Resolve("s1"); err != nil {
		t.Fatal(err)
	}
}

func TestDeepLivenessManagerDuplicateRegister(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	bs := NewBlockingState("s1", BlockingStateApproval, 1*time.Hour)
	lm.Register(bs)
	err := lm.Register(bs)
	if err == nil {
		t.Fatal("duplicate register should error")
	}
}

func TestDeepLivenessManagerConcurrentAccess(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			bs := NewBlockingState(fmt.Sprintf("s-%d", idx), BlockingStateApproval, 1*time.Hour)
			lm.Register(bs)
			lm.ActiveCount()
		}(i)
	}
	wg.Wait()
	if lm.ActiveCount() != 50 {
		t.Fatalf("expected 50 active, got %d", lm.ActiveCount())
	}
}
