package governance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ── Jurisdiction Resolution ─────────────────────────────────────

func TestJurisdictionResolve_SingleRule(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "eu-west-1", Priority: 1})
	ctx, err := r.Resolve("acme", "", "", "eu-west-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.LegalRegime != "EU/GDPR" {
		t.Errorf("expected EU/GDPR, got %s", ctx.LegalRegime)
	}
}

func TestJurisdictionResolve_RequiresEntityAndRegion(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "US/CCPA", Region: "us-east-1", Priority: 1})
	_, err := r.Resolve("", "", "", "us-east-1")
	if err == nil {
		t.Fatal("expected error for empty entity")
	}
}

func TestJurisdictionResolve_NoMatchingRegion(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "eu-west-1", Priority: 1})
	_, err := r.Resolve("acme", "", "", "ap-south-1")
	if err == nil {
		t.Fatal("expected error for unmatched region")
	}
}

func TestJurisdictionResolve_WildcardRule(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "GLOBAL", Region: "*", Priority: 1})
	ctx, err := r.Resolve("acme", "", "", "any-region")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.LegalRegime != "GLOBAL" {
		t.Errorf("expected GLOBAL, got %s", ctx.LegalRegime)
	}
}

func TestJurisdictionResolve_ConflictEscalation(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "eu-west-1", Priority: 5})
	r.AddRule(JurisdictionRule{RuleID: "r2", LegalRegime: "UK/FCA", Region: "eu-west-1", Priority: 5})
	ctx, err := r.Resolve("acme", "", "", "eu-west-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.LegalRegime != "" {
		t.Errorf("equal-priority conflict should leave regime empty, got %q", ctx.LegalRegime)
	}
	if len(ctx.Conflicts) == 0 {
		t.Fatal("expected at least one conflict")
	}
}

func TestJurisdictionResolve_HigherPriorityWins(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "eu-west-1", Priority: 1})
	r.AddRule(JurisdictionRule{RuleID: "r2", LegalRegime: "UK/FCA", Region: "eu-west-1", Priority: 10})
	ctx, err := r.Resolve("acme", "", "", "eu-west-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.LegalRegime != "UK/FCA" {
		t.Errorf("expected UK/FCA (higher priority), got %s", ctx.LegalRegime)
	}
}

func TestJurisdictionResolve_ContentHashNonEmpty(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "US/CCPA", Region: "us-east-1", Priority: 1})
	ctx, _ := r.Resolve("acme", "", "", "us-east-1")
	if !strings.HasPrefix(ctx.ContentHash, "sha256:") {
		t.Errorf("content hash should start with sha256:, got %s", ctx.ContentHash)
	}
}

// ── Liveness Probes ─────────────────────────────────────────────

func TestLivenessManager_RegisterAndGet(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	bs := NewBlockingState("bs-1", BlockingStateApproval, time.Hour)
	if err := lm.Register(bs); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	got, err := lm.Get("bs-1")
	if err != nil || got.StateID != "bs-1" {
		t.Fatalf("get failed: err=%v, got=%v", err, got)
	}
}

func TestLivenessManager_DuplicateRegisterFails(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	bs := NewBlockingState("bs-1", BlockingStateApproval, time.Hour)
	_ = lm.Register(bs)
	if err := lm.Register(bs); err == nil {
		t.Fatal("expected error on duplicate register")
	}
}

func TestLivenessManager_ResolveState(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	bs := NewBlockingState("bs-2", BlockingStateApproval, time.Hour)
	_ = lm.Register(bs)
	if err := lm.Resolve("bs-2"); err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	got, _ := lm.Get("bs-2")
	if got.State != LivenessStateActive {
		t.Errorf("expected ACTIVE, got %s", got.State)
	}
}

func TestLivenessManager_CancelState(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	bs := NewBlockingState("bs-3", BlockingStateApproval, time.Hour)
	_ = lm.Register(bs)
	_ = lm.Cancel("bs-3")
	got, _ := lm.Get("bs-3")
	if got.State != LivenessStateCanceled {
		t.Errorf("expected CANCELED, got %s", got.State)
	}
}

func TestBlockingState_DefaultApprovalTimeout(t *testing.T) {
	bs := NewApprovalState("a1", 0)
	if bs.Timeout != DefaultApprovalTimeout {
		t.Errorf("expected %v, got %v", DefaultApprovalTimeout, bs.Timeout)
	}
}

func TestBlockingState_ExtendFailsWhenNotPending(t *testing.T) {
	bs := NewBlockingState("bs-4", BlockingStateApproval, time.Hour)
	bs.Resolve()
	if err := bs.Extend(time.Hour); err == nil {
		t.Fatal("expected error extending resolved state")
	}
}

func TestLivenessManager_ActiveCount(t *testing.T) {
	lm := NewLivenessManager()
	defer lm.Shutdown()
	_ = lm.Register(NewBlockingState("a", BlockingStateApproval, time.Hour))
	_ = lm.Register(NewBlockingState("b", BlockingStateApproval, time.Hour))
	if lm.ActiveCount() != 2 {
		t.Errorf("expected 2 active, got %d", lm.ActiveCount())
	}
}

// ── Plan Commit Workflow ────────────────────────────────────────

func TestPlanCommit_SubmitAndApprove(t *testing.T) {
	pc := NewPlanCommitController()
	plan := &ExecutionPlan{PlanID: "p1", EffectType: "deploy", Principal: "alice"}
	ref, err := pc.SubmitPlan(plan)
	if err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	go func() { _ = pc.Approve("p1", "bob") }()
	dec, err := pc.WaitForApproval(*ref, 5*time.Second)
	if err != nil || dec.Status != PlanStatusApproved {
		t.Fatalf("expected APPROVED, got %v (err=%v)", dec, err)
	}
}

func TestPlanCommit_SubmitAndReject(t *testing.T) {
	pc := NewPlanCommitController()
	plan := &ExecutionPlan{PlanID: "p2", EffectType: "deploy", Principal: "alice"}
	ref, _ := pc.SubmitPlan(plan)
	go func() { _ = pc.Reject("p2", "bob", "too risky") }()
	dec, _ := pc.WaitForApproval(*ref, 5*time.Second)
	if dec.Status != PlanStatusRejected {
		t.Errorf("expected REJECTED, got %s", dec.Status)
	}
}

func TestPlanCommit_NilPlanFails(t *testing.T) {
	pc := NewPlanCommitController()
	_, err := pc.SubmitPlan(nil)
	if err == nil {
		t.Fatal("expected error for nil plan")
	}
}

func TestPlanCommit_EmptyPlanIDFails(t *testing.T) {
	pc := NewPlanCommitController()
	_, err := pc.SubmitPlan(&ExecutionPlan{})
	if err == nil {
		t.Fatal("expected error for empty PlanID")
	}
}

func TestPlanCommit_DuplicateSubmitFails(t *testing.T) {
	pc := NewPlanCommitController()
	plan := &ExecutionPlan{PlanID: "dup", EffectType: "deploy", Principal: "alice"}
	_, _ = pc.SubmitPlan(plan)
	_, err := pc.SubmitPlan(plan)
	if err == nil {
		t.Fatal("expected error on duplicate submit")
	}
}

func TestPlanCommit_Timeout(t *testing.T) {
	ch := make(chan time.Time, 1)
	ch <- time.Now()
	pc := NewPlanCommitController().WithAfter(func(d time.Duration) <-chan time.Time {
		return ch
	})
	plan := &ExecutionPlan{PlanID: "t1", EffectType: "deploy", Principal: "alice"}
	ref, _ := pc.SubmitPlan(plan)
	dec, _ := pc.WaitForApproval(*ref, time.Millisecond)
	if dec.Status != PlanStatusTimeout {
		t.Errorf("expected TIMEOUT, got %s", dec.Status)
	}
}

func TestPlanCommit_PendingCount(t *testing.T) {
	pc := NewPlanCommitController()
	pc.SubmitPlan(&ExecutionPlan{PlanID: "c1", EffectType: "x", Principal: "a"})
	pc.SubmitPlan(&ExecutionPlan{PlanID: "c2", EffectType: "x", Principal: "a"})
	if pc.PendingCount() != 2 {
		t.Errorf("expected 2 pending, got %d", pc.PendingCount())
	}
}

func TestPlanCommit_AbortPlan(t *testing.T) {
	pc := NewPlanCommitController()
	plan := &ExecutionPlan{PlanID: "ab1", EffectType: "deploy", Principal: "alice"}
	ref, _ := pc.SubmitPlan(plan)
	go func() { _ = pc.Abort("ab1") }()
	dec, _ := pc.WaitForApproval(*ref, 5*time.Second)
	if dec.Status != PlanStatusAborted {
		t.Errorf("expected ABORTED, got %s", dec.Status)
	}
}

// ── Keyring Operations ──────────────────────────────────────────

func TestKeyring_SignAndVerify(t *testing.T) {
	kp, _ := NewMemoryKeyProvider()
	kr := NewKeyring(kp)
	sig, err := kr.Sign(map[string]string{"hello": "world"})
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}
}

func TestKeyring_NilProviderFallback(t *testing.T) {
	kr := NewKeyring(nil)
	if kr.PublicKey() == nil {
		t.Fatal("nil provider should fall back to in-memory key")
	}
}

func TestKeyring_DeriveForTenant(t *testing.T) {
	kp, _ := NewMemoryKeyProvider()
	kr := NewKeyring(kp)
	derived, err := kr.DeriveForTenant("tenant-a")
	if err != nil {
		t.Fatalf("derivation failed: %v", err)
	}
	if string(derived.PublicKey()) == string(kr.PublicKey()) {
		t.Error("derived key should differ from master key")
	}
}

func TestKeyring_DeriveEmptyTenantFails(t *testing.T) {
	kp, _ := NewMemoryKeyProvider()
	kr := NewKeyring(kp)
	_, err := kr.DeriveForTenant("")
	if err == nil {
		t.Fatal("expected error for empty tenantID")
	}
}

func TestKeyring_DeterministicDerivation(t *testing.T) {
	kp, _ := NewMemoryKeyProvider()
	kr := NewKeyring(kp)
	d1, _ := kr.DeriveForTenant("tenant-x")
	d2, _ := kr.DeriveForTenant("tenant-x")
	if string(d1.PublicKey()) != string(d2.PublicKey()) {
		t.Error("same tenant should yield same derived key")
	}
}

// ── Swarm PDP ───────────────────────────────────────────────────

func TestSwarmPDP_MergeDecisions_DenyWins(t *testing.T) {
	pdp := newTestSwarmPDP(true)
	result := pdp.MergeDecisions([]Decision{DecisionAllow, DecisionDeny, DecisionAllow})
	if result != DecisionDeny {
		t.Errorf("expected DENY (strict merge), got %s", result)
	}
}

func TestSwarmPDP_MergeDecisions_EmptyDenies(t *testing.T) {
	pdp := newTestSwarmPDP(true)
	result := pdp.MergeDecisions([]Decision{})
	if result != DecisionDeny {
		t.Errorf("expected DENY for empty decisions, got %s", result)
	}
}

func TestSwarmPDP_MergeDecisions_RequireApprovalOverAllow(t *testing.T) {
	pdp := newTestSwarmPDP(true)
	result := pdp.MergeDecisions([]Decision{DecisionAllow, DecisionRequireApproval})
	if result != DecisionRequireApproval {
		t.Errorf("expected REQUIRE_APPROVAL, got %s", result)
	}
}

func TestSwarmPDP_MergeDecisions_PriorityMode(t *testing.T) {
	pdp := newTestSwarmPDP(false) // non-strict
	result := pdp.MergeDecisions([]Decision{DecisionAllow, DecisionRequireEvidence})
	if result != DecisionRequireEvidence {
		t.Errorf("expected REQUIRE_EVIDENCE in priority mode, got %s", result)
	}
}

func TestSwarmPDP_BatchEmpty(t *testing.T) {
	pdp := newTestSwarmPDP(true)
	result, err := pdp.EvaluateBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Responses) != 0 {
		t.Errorf("expected 0 responses, got %d", len(result.Responses))
	}
}

func TestSwarmPDP_ClassifyDomain(t *testing.T) {
	if classifyDomain("trade") != DomainRisk {
		t.Error("trade should classify as risk")
	}
	if classifyDomain("log") != DomainAudit {
		t.Error("log should classify as audit")
	}
	if classifyDomain("unknown") != DomainGeneral {
		t.Error("unknown should classify as general")
	}
}

// ── Risk Envelope ───────────────────────────────────────────────

func TestRiskEnvelope_WithinLimits(t *testing.T) {
	ra := NewAggregateRiskAccounting(time.Hour, 100.0)
	ra.RegisterEnvelope(&RiskEnvelope{ActionType: "trade", MaxRisk: 50, Weight: 1.0})
	if err := ra.CheckAndRecord("trade", 30); err != nil {
		t.Fatalf("should allow within limits: %v", err)
	}
}

func TestRiskEnvelope_ExceedsPerActionMax(t *testing.T) {
	ra := NewAggregateRiskAccounting(time.Hour, 100.0)
	ra.RegisterEnvelope(&RiskEnvelope{ActionType: "trade", MaxRisk: 10, Weight: 1.0})
	if err := ra.CheckAndRecord("trade", 20); err == nil {
		t.Fatal("expected error exceeding per-action max")
	}
}

func TestRiskEnvelope_ExceedsAggregateMax(t *testing.T) {
	ra := NewAggregateRiskAccounting(time.Hour, 50.0)
	ra.RegisterEnvelope(&RiskEnvelope{ActionType: "trade", MaxRisk: 100, Weight: 1.0})
	_ = ra.CheckAndRecord("trade", 30)
	if err := ra.CheckAndRecord("trade", 25); err == nil {
		t.Fatal("expected error exceeding aggregate max")
	}
}

func TestRiskEnvelope_CurrentAggregate(t *testing.T) {
	ra := NewAggregateRiskAccounting(time.Hour, 100.0)
	ra.RegisterEnvelope(&RiskEnvelope{ActionType: "trade", MaxRisk: 100, Weight: 2.0})
	_ = ra.CheckAndRecord("trade", 10)
	agg := ra.CurrentAggregate()
	if agg != 20.0 { // 10 * weight 2.0
		t.Errorf("expected aggregate 20, got %.2f", agg)
	}
}

func TestRiskEnvelope_SnapshotDeterministic(t *testing.T) {
	ra := NewAggregateRiskAccounting(time.Hour, 100.0)
	s1 := ra.Snapshot()
	s2 := ra.Snapshot()
	if s1 != s2 {
		t.Error("snapshot should be deterministic")
	}
}

// ── Denial Handling ─────────────────────────────────────────────

func TestDenialLedger_DenyCreatesReceipt(t *testing.T) {
	l := NewDenialLedger()
	receipt := l.Deny("alice", "deploy", DenialPolicy, "not allowed")
	if receipt.ReceiptID == "" || receipt.Principal != "alice" {
		t.Fatalf("receipt malformed: %+v", receipt)
	}
}

func TestDenialLedger_ContentHashPresent(t *testing.T) {
	l := NewDenialLedger()
	receipt := l.Deny("alice", "deploy", DenialPolicy, "reason")
	if !strings.HasPrefix(receipt.ContentHash, "sha256:") {
		t.Error("content hash should be sha256-prefixed")
	}
}

func TestDenialLedger_GetByID(t *testing.T) {
	l := NewDenialLedger()
	receipt := l.Deny("alice", "deploy", DenialPolicy, "test")
	got, err := l.Get(receipt.ReceiptID)
	if err != nil || got.Principal != "alice" {
		t.Fatalf("get failed: err=%v", err)
	}
}

func TestDenialLedger_GetMissing(t *testing.T) {
	l := NewDenialLedger()
	_, err := l.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing receipt")
	}
}

func TestDenialLedger_QueryByReason(t *testing.T) {
	l := NewDenialLedger()
	l.Deny("alice", "deploy", DenialPolicy, "a")
	l.Deny("bob", "scale", DenialBudget, "b")
	l.Deny("carol", "transfer", DenialPolicy, "c")
	results := l.QueryByReason(DenialPolicy)
	if len(results) != 2 {
		t.Errorf("expected 2 policy denials, got %d", len(results))
	}
}

func TestDenialLedger_QueryByPrincipal(t *testing.T) {
	l := NewDenialLedger()
	l.Deny("alice", "deploy", DenialPolicy, "a")
	l.Deny("alice", "scale", DenialBudget, "b")
	results := l.QueryByPrincipal("alice")
	if len(results) != 2 {
		t.Errorf("expected 2 denials for alice, got %d", len(results))
	}
}

func TestDenialLedger_DenyWithContext(t *testing.T) {
	l := NewDenialLedger()
	receipt := l.DenyWithContext("alice", "t1", "deploy", "run-1", DenialPolicy, "detail", "pol-1", "env-1")
	if receipt.TenantID != "t1" || receipt.RunID != "run-1" {
		t.Errorf("context fields missing: %+v", receipt)
	}
}

// ── Firewall Governance (ConnectorManifest / Edge) ──────────────

func TestConnectorManifest_AllowValidEgress(t *testing.T) {
	m := NewConnectorManifest()
	ok, err := m.CanEgress("email", DataClassConfidential)
	if !ok || err != nil {
		t.Fatalf("expected allowed: ok=%v err=%v", ok, err)
	}
}

func TestConnectorManifest_DenyEgressAboveMax(t *testing.T) {
	m := NewConnectorManifest()
	ok, err := m.CanEgress("slack", DataClassConfidential) // slack max = Internal
	if ok {
		t.Fatal("expected deny for confidential data to slack")
	}
	if err == nil {
		t.Fatal("expected error message")
	}
}

func TestConnectorManifest_UnknownConnector(t *testing.T) {
	m := NewConnectorManifest()
	_, err := m.CanEgress("unknown-connector", DataClassPublic)
	if err == nil {
		t.Fatal("expected error for unknown connector")
	}
}

func TestEdgeAssistant_FallbackDenyAll(t *testing.T) {
	ea := &EdgeAssistant{
		Config:   EdgeConfig{Mode: EdgeFallback},
		Fallback: FallbackPolicy{Strategy: FallbackDenyAll},
	}
	if ea.ShouldAllow("deploy", "LOW") {
		t.Error("DENY_ALL should deny everything")
	}
}

func TestEdgeAssistant_RingFenceAllowsLow(t *testing.T) {
	ea := &EdgeAssistant{
		Config: EdgeConfig{Mode: EdgeFallback},
		Fallback: FallbackPolicy{
			Strategy:   FallbackRingFence,
			AllowRules: []FallbackRule{{EffectType: "log", MaxRisk: "MEDIUM"}},
		},
	}
	if !ea.ShouldAllow("log", "LOW") {
		t.Error("ring fence should allow LOW log")
	}
	if ea.ShouldAllow("deploy", "HIGH") {
		t.Error("ring fence should deny HIGH deploy")
	}
}

// ── CEL Deterministic Evaluation ────────────────────────────────

func TestCELDP_BannedFunctionDetected(t *testing.T) {
	v := NewCELDPValidator()
	issues := v.ValidateExpression(`now() > 100`)
	if len(issues) == 0 {
		t.Fatal("expected banned function issue for now()")
	}
}

func TestCELDP_CleanExpressionPasses(t *testing.T) {
	v := NewCELDPValidator()
	issues := v.ValidateExpression(`x + y == 10`)
	if len(issues) != 0 {
		t.Errorf("expected no issues, got %d", len(issues))
	}
}

func TestCELDP_BannedTypeDetected(t *testing.T) {
	v := NewCELDPValidator()
	issues := v.ValidateExpression(`double(x) > 1`)
	found := false
	for _, iss := range issues {
		if iss.Type == "banned_type" {
			found = true
		}
	}
	if !found {
		t.Error("expected banned_type issue for double")
	}
}

func TestCELDP_DynamicOpDetected(t *testing.T) {
	v := NewCELDPValidator()
	issues := v.ValidateExpression(`type(x) == "int"`)
	found := false
	for _, iss := range issues {
		if iss.Type == "nondeterministic" {
			found = true
		}
	}
	if !found {
		t.Error("expected nondeterministic issue for type()")
	}
}

func TestCELDP_HashErrorMessageDeterministic(t *testing.T) {
	h1 := HashErrorMessage("  Some Error  ")
	h2 := HashErrorMessage("some error")
	if h1 != h2 {
		t.Error("normalized messages should hash identically")
	}
}

func TestCELDP_ComputeTraceHashEmpty(t *testing.T) {
	hash := ComputeTraceHash(nil)
	if hash != "" {
		t.Error("empty trace should produce empty hash")
	}
}

func TestCELDP_ValidateAndAnalyze(t *testing.T) {
	v := NewCELDPValidator()
	info := v.ValidateAndAnalyze(`x > 5`)
	if !info.Valid {
		t.Error("simple comparison should be valid")
	}
	if info.ProfileID != CELDPProfileID {
		t.Errorf("expected profile %s, got %s", CELDPProfileID, info.ProfileID)
	}
}

// ── Policy Engine ───────────────────────────────────────────────

func TestPolicyEngine_LoadAndEvaluateAllow(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("engine creation failed: %v", err)
	}
	if err := pe.LoadPolicy("p1", `action == "read"`); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	req := contracts.AccessRequest{PrincipalID: "alice", Action: "read", ResourceID: "doc", Context: map[string]interface{}{}}
	dec, err := pe.Evaluate(context.Background(), "p1", req)
	if err != nil || dec.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s (err=%v)", dec.Verdict, err)
	}
}

func TestPolicyEngine_LoadAndEvaluateDeny(t *testing.T) {
	pe, _ := NewPolicyEngine()
	_ = pe.LoadPolicy("p1", `action == "write"`)
	req := contracts.AccessRequest{PrincipalID: "alice", Action: "read", ResourceID: "doc", Context: map[string]interface{}{}}
	dec, _ := pe.Evaluate(context.Background(), "p1", req)
	if dec.Verdict != "DENY" {
		t.Errorf("expected DENY, got %s", dec.Verdict)
	}
}

func TestPolicyEngine_MissingPolicyDenies(t *testing.T) {
	pe, _ := NewPolicyEngine()
	req := contracts.AccessRequest{PrincipalID: "alice", Action: "read", ResourceID: "doc", Context: map[string]interface{}{}}
	dec, _ := pe.Evaluate(context.Background(), "nonexistent", req)
	if dec.Verdict != "DENY" {
		t.Errorf("missing policy should deny, got %s", dec.Verdict)
	}
}

func TestPolicyEngine_NoPolicyIDDenies(t *testing.T) {
	pe, _ := NewPolicyEngine()
	req := contracts.AccessRequest{PrincipalID: "alice", Action: "read", ResourceID: "doc", Context: map[string]interface{}{}}
	dec, _ := pe.Evaluate(context.Background(), "", req)
	if dec.Verdict != "DENY" {
		t.Errorf("empty policy ID should deny, got %s", dec.Verdict)
	}
}

func TestPolicyEngine_InvalidCELFails(t *testing.T) {
	pe, _ := NewPolicyEngine()
	err := pe.LoadPolicy("bad", "!!!invalid cel")
	if err == nil {
		t.Fatal("expected compilation error")
	}
}

func TestPolicyEngine_ListDefinitions(t *testing.T) {
	pe, _ := NewPolicyEngine()
	_ = pe.LoadPolicy("p1", `action == "read"`)
	defs := pe.ListDefinitions()
	if defs["p1"] != `action == "read"` {
		t.Error("expected loaded definition")
	}
}

// ── Security Checks ─────────────────────────────────────────────

func TestDelegationRevocationList_RevokeAndCheck(t *testing.T) {
	drl := NewDelegationRevocationList()
	_ = drl.Revoke("del-1", "admin", "compromised")
	if !drl.IsRevoked("del-1") {
		t.Error("delegation should be revoked")
	}
	if drl.IsRevoked("del-2") {
		t.Error("del-2 was never revoked")
	}
}

func TestDelegationRevocationList_DoubleRevokeFails(t *testing.T) {
	drl := NewDelegationRevocationList()
	_ = drl.Revoke("del-1", "admin", "reason")
	if err := drl.Revoke("del-1", "admin", "again"); err == nil {
		t.Fatal("expected error on double revoke")
	}
}

func TestCompromiseDetector_HighSeverityMarksSuspect(t *testing.T) {
	cd := NewCompromiseDetector()
	att := NewPDPAttestation("pdp-1", time.Hour)
	cd.RegisterAttestation(att)
	cd.ReportAnomaly("pdp-1", AnomalyTypeTimingAnomaly, "slow", 5) // threshold=5
	if cd.GetPDPStatus("pdp-1") != PDPAttestationSuspect {
		t.Errorf("expected SUSPECT, got %s", cd.GetPDPStatus("pdp-1"))
	}
}

func TestCompromiseDetector_ShouldFailClosed(t *testing.T) {
	cd := NewCompromiseDetector()
	att := NewPDPAttestation("pdp-2", time.Hour)
	cd.RegisterAttestation(att)
	att.Revoke()
	if !cd.ShouldFailClosed("pdp-2") {
		t.Error("revoked PDP should fail closed")
	}
}

func TestCompromiseDetector_UnknownPDPNotTrusted(t *testing.T) {
	cd := NewCompromiseDetector()
	status := cd.GetPDPStatus("unknown-pdp")
	if status != PDPAttestationExpired {
		t.Errorf("unknown PDP should be EXPIRED, got %s", status)
	}
}

func TestCompensationState_SuccessOnFirstAttempt(t *testing.T) {
	cs := NewCompensationState("tx-1", "op-1", CompensationPolicyRetry)
	outcome := cs.RecordAttempt(true, "")
	if outcome != CompensationOutcomeSuccess {
		t.Errorf("expected SUCCESS, got %s", outcome)
	}
}

func TestCompensationState_EscalateAfterMaxRetries(t *testing.T) {
	cs := NewCompensationState("tx-2", "op-2", CompensationPolicyEscalate)
	for i := 0; i < MaxCompensationAttempts; i++ {
		cs.RecordAttempt(false, "fail")
	}
	if !cs.NeedsIntervention() {
		t.Error("should need intervention after max attempts with ESCALATE policy")
	}
}

// ── Data Classification ─────────────────────────────────────────

func TestClassifier_DetectsRestrictedContent(t *testing.T) {
	c := NewClassifier()
	class := c.Classify("root_password=secret123")
	if class != DataClassRestricted {
		t.Errorf("expected RESTRICTED, got %s", class)
	}
}

func TestClassifier_DetectsConfidentialPII(t *testing.T) {
	c := NewClassifier()
	class := c.Classify("contact: user@example.com")
	if class != DataClassConfidential {
		t.Errorf("expected CONFIDENTIAL, got %s", class)
	}
}

// ── Conflict Arbitration ────────────────────────────────────────

func TestArbitrate_StrictestDenyWins(t *testing.T) {
	inputs := []ArbitrationInput{
		{RuleID: "r1", Decision: "ALLOW", Priority: 1},
		{RuleID: "r2", Decision: "DENY", Priority: 1},
	}
	result := Arbitrate(inputs, StrategyStrictest)
	if result.Resolution != "DENY" {
		t.Errorf("expected DENY, got %s", result.Resolution)
	}
}

func TestArbitrate_SingleInputNoConflict(t *testing.T) {
	inputs := []ArbitrationInput{{RuleID: "r1", Decision: "ALLOW", Priority: 1}}
	result := Arbitrate(inputs, StrategyStrictest)
	if result != nil {
		t.Error("single input should not produce a conflict record")
	}
}

// ── Self-Modification Governance ────────────────────────────────

func TestEvolutionGovernance_C0AutoApproved(t *testing.T) {
	eg := NewEvolutionGovernance()
	allowed, reason := eg.EvaluateChange(context.Background(), ChangeClassC0, true)
	if !allowed || reason != "APPROVED_AUTO" {
		t.Errorf("C0 with passing regression should auto-approve: allowed=%v reason=%s", allowed, reason)
	}
}

func TestEvolutionGovernance_C3AlwaysBlocked(t *testing.T) {
	eg := NewEvolutionGovernance()
	allowed, _ := eg.EvaluateChange(context.Background(), ChangeClassC3, true)
	if allowed {
		t.Error("C3 kernel changes should always be blocked for human review")
	}
}

// ── Canary Config ───────────────────────────────────────────────

func TestCanaryDefaults(t *testing.T) {
	if DefaultCanary.Steps != 3 {
		t.Errorf("expected 3 steps, got %d", DefaultCanary.Steps)
	}
	if FastCanary.Steps != 1 {
		t.Errorf("expected 1 step for fast canary, got %d", FastCanary.Steps)
	}
}

// ── PDP Integration ─────────────────────────────────────────────

func TestCELPDP_AllowedEffectType(t *testing.T) {
	pdp, err := NewCELPolicyDecisionPoint("test-policy-v1", nil)
	if err != nil {
		t.Fatalf("PDP creation failed: %v", err)
	}
	req := PDPRequest{
		RequestID: "req-1",
		Effect:    EffectDescriptor{EffectType: "DATA_WRITE"},
		Subject:   SubjectDescriptor{ActorID: "agent-1", ActorType: "agent"},
	}
	resp, err := pdp.Evaluate(context.Background(), req)
	if err != nil || resp.Decision != DecisionAllow {
		t.Errorf("DATA_WRITE should be allowed: decision=%s err=%v", resp.Decision, err)
	}
}

func TestCELPDP_DefaultDenyUnknownEffect(t *testing.T) {
	pdp, _ := NewCELPolicyDecisionPoint("test-policy-v1", nil)
	req := PDPRequest{
		RequestID: "req-2",
		Effect:    EffectDescriptor{EffectType: "UNKNOWN_TYPE"},
		Subject:   SubjectDescriptor{ActorID: "agent-1", ActorType: "agent"},
	}
	resp, _ := pdp.Evaluate(context.Background(), req)
	if resp.Decision != DecisionDeny {
		t.Errorf("unknown effect should be denied, got %s", resp.Decision)
	}
}

func TestCELPDP_HighRiskRequiresApproval(t *testing.T) {
	pdp, _ := NewCELPolicyDecisionPoint("test-policy-v1", nil)
	req := PDPRequest{
		RequestID: "req-3",
		Effect:    EffectDescriptor{EffectType: "FUNDS_TRANSFER"},
		Subject:   SubjectDescriptor{ActorID: "agent-1", ActorType: "agent"},
	}
	resp, _ := pdp.Evaluate(context.Background(), req)
	if resp.Decision != DecisionRequireApproval {
		t.Errorf("FUNDS_TRANSFER should require approval, got %s", resp.Decision)
	}
}

func TestCELPDP_PolicyVersionReturned(t *testing.T) {
	pdp, _ := NewCELPolicyDecisionPoint("v42", nil)
	if pdp.PolicyVersion() != "v42" {
		t.Errorf("expected v42, got %s", pdp.PolicyVersion())
	}
}

// ── helpers ─────────────────────────────────────────────────────

// newTestSwarmPDP creates a SwarmPDP for testing merge behavior.
func newTestSwarmPDP(strict bool) *SwarmPDP {
	basePDP := &stubPDP{version: "test-v1"}
	return NewSwarmPDP(basePDP, &SwarmPDPConfig{
		MaxParallelPDPs:     4,
		StrictMerge:         strict,
		DomainDecomposition: true,
	})
}

// stubPDP is a minimal PDP that always allows, for testing the swarm wrapper.
type stubPDP struct{ version string }

func (s *stubPDP) Evaluate(_ context.Context, _ PDPRequest) (*PDPResponse, error) {
	return &PDPResponse{Decision: DecisionAllow, PolicyVersion: s.version}, nil
}

func (s *stubPDP) PolicyVersion() string { return s.version }
