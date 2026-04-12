package contracts

import (
	"strings"
	"testing"
	"time"
)

// ── Effect Types ──────────────────────────────────────────────

func TestEffectRiskClass_InfraDestroyIsE4(t *testing.T) {
	if got := EffectRiskClass(EffectTypeInfraDestroy); got != "E4" {
		t.Fatalf("EffectRiskClass(INFRA_DESTROY) = %s, want E4", got)
	}
}

func TestEffectRiskClass_UnknownDefaultsE3(t *testing.T) {
	if got := EffectRiskClass("SOME_UNKNOWN_EFFECT"); got != "E3" {
		t.Fatalf("unknown effect should default to E3, got %s", got)
	}
}

func TestEffectRiskClass_ReversibleEffectsAreE1(t *testing.T) {
	for _, et := range []string{EffectTypeSendChatMessage, EffectTypeCreateCalEvent, EffectTypeCreateTask} {
		if got := EffectRiskClass(et); got != "E1" {
			t.Errorf("EffectRiskClass(%s) = %s, want E1", et, got)
		}
	}
}

func TestLookupEffectType_Found(t *testing.T) {
	et := LookupEffectType(EffectTypeExecutePayment)
	if et == nil {
		t.Fatal("expected non-nil EffectType for EXECUTE_PAYMENT")
	}
	if et.Name == "" {
		t.Error("EffectType.Name must not be empty")
	}
}

func TestLookupEffectType_UnknownReturnsNil(t *testing.T) {
	if et := LookupEffectType("NONEXISTENT_TYPE"); et != nil {
		t.Fatal("expected nil for unknown effect type ID")
	}
}

func TestDefaultEffectCatalog_NonEmpty(t *testing.T) {
	cat := DefaultEffectCatalog()
	if len(cat.EffectTypes) == 0 {
		t.Fatal("default catalog must contain effect types")
	}
	if cat.CatalogVersion == "" {
		t.Error("catalog version must be set")
	}
}

func TestEffectRiskClass_FinancialEffectsAreE4(t *testing.T) {
	for _, et := range []string{EffectTypeExecutePayment, EffectTypeRequestPurchase} {
		if got := EffectRiskClass(et); got != "E4" {
			t.Errorf("EffectRiskClass(%s) = %s, want E4", et, got)
		}
	}
}

// ── Compensation Recipes ──────────────────────────────────────

func TestNewCompensationRecipe_HashPrefix(t *testing.T) {
	steps := []CompensationStep{{StepID: "s1", Order: 1, Action: "revert", Target: "db"}}
	r := NewCompensationRecipe("run-1", steps, true)
	if !strings.HasPrefix(r.ContentHash, "sha256:") {
		t.Fatalf("content hash prefix = %s, want sha256:", r.ContentHash)
	}
}

func TestCompensationRecipe_IsComplete(t *testing.T) {
	r := &CompensationRecipe{Steps: []CompensationStep{{StepID: "s1"}}}
	if !r.IsComplete() {
		t.Error("recipe with steps should be complete")
	}
}

func TestCompensationRecipe_EmptyNotComplete(t *testing.T) {
	r := &CompensationRecipe{}
	if r.IsComplete() {
		t.Error("recipe with no steps should not be complete")
	}
}

func TestCompensationRecipe_HasFallbacks_AllPresent(t *testing.T) {
	r := &CompensationRecipe{Steps: []CompensationStep{
		{StepID: "s1", Fallback: "retry"},
		{StepID: "s2", Fallback: "alert"},
	}}
	if !r.HasFallbacks() {
		t.Error("all steps have fallbacks, expected true")
	}
}

func TestCompensationRecipe_HasFallbacks_MissingOne(t *testing.T) {
	r := &CompensationRecipe{Steps: []CompensationStep{
		{StepID: "s1", Fallback: "retry"},
		{StepID: "s2"},
	}}
	if r.HasFallbacks() {
		t.Error("one step missing fallback, expected false")
	}
}

// ── Verdict & Reason Codes ────────────────────────────────────

func TestVerdictAllow_IsTerminal(t *testing.T) {
	if !VerdictAllow.IsTerminal() {
		t.Error("ALLOW must be terminal")
	}
}

func TestVerdictEscalate_NotTerminal(t *testing.T) {
	if VerdictEscalate.IsTerminal() {
		t.Error("ESCALATE must not be terminal")
	}
}

func TestIsCanonicalVerdict_Valid(t *testing.T) {
	if !IsCanonicalVerdict("ALLOW") {
		t.Error("ALLOW must be canonical")
	}
}

func TestIsCanonicalVerdict_Invalid(t *testing.T) {
	if IsCanonicalVerdict("PERMIT") {
		t.Error("PERMIT is not a canonical verdict")
	}
}

func TestIsCanonicalReasonCode_Valid(t *testing.T) {
	if !IsCanonicalReasonCode("BUDGET_EXCEEDED") {
		t.Error("BUDGET_EXCEEDED must be canonical")
	}
}

func TestIsCanonicalReasonCode_Invalid(t *testing.T) {
	if IsCanonicalReasonCode("UNKNOWN_REASON") {
		t.Error("UNKNOWN_REASON is not in the registry")
	}
}

func TestCanonicalVerdicts_CountIsThree(t *testing.T) {
	if n := len(CanonicalVerdicts()); n != 3 {
		t.Fatalf("expected 3 canonical verdicts, got %d", n)
	}
}

func TestCoreReasonCodes_NonEmpty(t *testing.T) {
	codes := CoreReasonCodes()
	if len(codes) < 10 {
		t.Fatalf("expected many reason codes, got %d", len(codes))
	}
}

// ── Decision Request ──────────────────────────────────────────

func TestDecisionRequest_Validate_MinOptions(t *testing.T) {
	dr := &DecisionRequest{
		RequestID: "dr-1",
		Kind:      DecisionKindApproval,
		Title:     "Approve?",
		Options:   []DecisionOption{{ID: "a", Label: "Yes"}},
	}
	if err := dr.Validate(); err == nil {
		t.Error("should reject with < 2 concrete options")
	}
}

func TestDecisionRequest_Validate_Happy(t *testing.T) {
	dr := &DecisionRequest{
		RequestID: "dr-1",
		Kind:      DecisionKindApproval,
		Title:     "Approve action?",
		Options: []DecisionOption{
			{ID: "a", Label: "Yes"},
			{ID: "b", Label: "No"},
		},
	}
	if err := dr.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestDecisionRequest_Resolve_Success(t *testing.T) {
	dr := &DecisionRequest{
		RequestID: "dr-1",
		Status:    DecisionStatusPending,
		Options:   []DecisionOption{{ID: "opt-1", Label: "Go"}},
	}
	if err := dr.Resolve("opt-1", "user-1"); err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dr.Status != DecisionStatusResolved {
		t.Errorf("status = %s, want RESOLVED", dr.Status)
	}
}

func TestDecisionRequest_Resolve_UnknownOption(t *testing.T) {
	dr := &DecisionRequest{
		RequestID: "dr-1",
		Status:    DecisionStatusPending,
		Options:   []DecisionOption{{ID: "opt-1", Label: "Go"}},
	}
	if err := dr.Resolve("bogus", "user-1"); err == nil {
		t.Error("should reject unknown option ID")
	}
}

func TestDecisionRequest_Skip_Allowed(t *testing.T) {
	dr := &DecisionRequest{
		RequestID:   "dr-1",
		Status:      DecisionStatusPending,
		SkipAllowed: true,
	}
	if err := dr.Skip("admin"); err != nil {
		t.Fatalf("skip failed: %v", err)
	}
	if dr.Status != DecisionStatusSkipped {
		t.Errorf("status = %s, want SKIPPED", dr.Status)
	}
}

func TestDecisionRequest_Skip_NotAllowed(t *testing.T) {
	dr := &DecisionRequest{
		RequestID:   "dr-1",
		Status:      DecisionStatusPending,
		SkipAllowed: false,
	}
	if err := dr.Skip("admin"); err == nil {
		t.Error("should reject skip when not allowed")
	}
}

func TestDecisionRequest_IsBlocking_Pending(t *testing.T) {
	dr := &DecisionRequest{Status: DecisionStatusPending}
	if !dr.IsBlocking() {
		t.Error("PENDING decision should be blocking")
	}
}

func TestDecisionRequest_CheckExpiry(t *testing.T) {
	dr := &DecisionRequest{
		Status:    DecisionStatusPending,
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	if !dr.CheckExpiry() {
		t.Error("past-deadline decision should expire")
	}
	if dr.Status != DecisionStatusExpired {
		t.Errorf("status = %s, want EXPIRED", dr.Status)
	}
}

// ── Receipt ───────────────────────────────────────────────────

func TestReceipt_CausalChainFields(t *testing.T) {
	r := Receipt{
		ReceiptID:    "r1",
		PrevHash:     "sha256:abc",
		LamportClock: 42,
	}
	if r.PrevHash == "" {
		t.Error("PrevHash must be set for causal chain")
	}
	if r.LamportClock != 42 {
		t.Error("LamportClock must be 42")
	}
}

func TestReceipt_V5ExecutionPlaneFields(t *testing.T) {
	r := Receipt{
		ReceiptID:      "r1",
		SandboxLeaseID: "lease-1",
		NetworkLogRef:  "log-ref-1",
	}
	if r.SandboxLeaseID != "lease-1" || r.NetworkLogRef != "log-ref-1" {
		t.Error("V5 execution plane fields must be populated")
	}
}

func TestReceipt_ProvenanceFields(t *testing.T) {
	r := Receipt{
		ReceiptID: "r1",
		Provenance: &ReceiptProvenance{
			GeneratedBy: "agent-1",
			Context:     "production",
		},
	}
	if r.Provenance.GeneratedBy != "agent-1" {
		t.Error("expected provenance generated_by = agent-1")
	}
}

// ── Risk Summary ──────────────────────────────────────────────

func TestComputeRiskSummary_FrozenIsCritical(t *testing.T) {
	rs := ComputeRiskSummary(EffectTypeCreateTask, WithFrozen())
	if rs.OverallRisk != "CRITICAL" {
		t.Errorf("frozen system risk = %s, want CRITICAL", rs.OverallRisk)
	}
}

func TestComputeRiskSummary_ContextMismatchIsCritical(t *testing.T) {
	rs := ComputeRiskSummary(EffectTypeCreateTask, WithContextMismatch())
	if rs.OverallRisk != "CRITICAL" {
		t.Errorf("context mismatch risk = %s, want CRITICAL", rs.OverallRisk)
	}
}

func TestComputeRiskSummary_E2WithEgress(t *testing.T) {
	rs := ComputeRiskSummary(EffectTypeCloudComputeBudget, WithEgressRisk())
	if rs.OverallRisk != "HIGH" {
		t.Errorf("E2+egress risk = %s, want HIGH", rs.OverallRisk)
	}
}

func TestComputeRiskSummary_E1IsLow(t *testing.T) {
	rs := ComputeRiskSummary(EffectTypeAgentIdentityIsolation)
	if rs.OverallRisk != "LOW" {
		t.Errorf("E1 risk = %s, want LOW", rs.OverallRisk)
	}
}

// ── Truth Discipline ──────────────────────────────────────────

func TestTruthAnnotation_HasBlockingUnknowns(t *testing.T) {
	ta := &TruthAnnotation{
		Unknowns: []Unknown{{ID: "u1", Impact: UnknownImpactBlocking}},
	}
	if !ta.HasBlockingUnknowns() {
		t.Error("should detect blocking unknown")
	}
}

func TestTruthAnnotation_NoBlockingUnknowns(t *testing.T) {
	ta := &TruthAnnotation{
		Unknowns: []Unknown{{ID: "u1", Impact: UnknownImpactInformational}},
	}
	if ta.HasBlockingUnknowns() {
		t.Error("informational unknown should not be blocking")
	}
}

func TestTruthAnnotation_BlockingUnknownIDs(t *testing.T) {
	ta := &TruthAnnotation{
		Unknowns: []Unknown{
			{ID: "u1", Impact: UnknownImpactBlocking},
			{ID: "u2", Impact: UnknownImpactDegrading},
			{ID: "u3", Impact: UnknownImpactBlocking},
		},
	}
	ids := ta.BlockingUnknownIDs()
	if len(ids) != 2 {
		t.Fatalf("expected 2 blocking IDs, got %d", len(ids))
	}
}

func TestTruthAnnotation_Merge_TakesLowerConfidence(t *testing.T) {
	a := &TruthAnnotation{Confidence: 0.9}
	b := &TruthAnnotation{Confidence: 0.5}
	merged := a.Merge(b)
	if merged.Confidence != 0.5 {
		t.Errorf("merged confidence = %f, want 0.5", merged.Confidence)
	}
}

func TestTruthAnnotation_Merge_CombinesFacts(t *testing.T) {
	a := &TruthAnnotation{FactSet: []FactRef{{FactID: "f1"}}}
	b := &TruthAnnotation{FactSet: []FactRef{{FactID: "f2"}}}
	merged := a.Merge(b)
	if len(merged.FactSet) != 2 {
		t.Fatalf("expected 2 facts, got %d", len(merged.FactSet))
	}
}

func TestTruthAnnotation_Merge_NilOther(t *testing.T) {
	a := &TruthAnnotation{Confidence: 0.8}
	merged := a.Merge(nil)
	if merged.Confidence != 0.8 {
		t.Errorf("merge with nil should preserve original confidence")
	}
}

// ── Reflex ────────────────────────────────────────────────────

func TestEvaluateReflexes_NilReturnsNil(t *testing.T) {
	actions := EvaluateReflexes(nil, DefaultReflexThresholds())
	if actions != nil {
		t.Error("nil state must return nil actions")
	}
}

func TestEvaluateReflexes_BudgetExhaustedFreeze(t *testing.T) {
	state := &GlobalAutonomyState{
		Budget: BudgetSummary{EnvelopeCents: 1000, BurnCents: 1000},
	}
	actions := EvaluateReflexes(state, DefaultReflexThresholds())
	found := false
	for _, a := range actions {
		if a.Kind == ReflexFreeze {
			found = true
		}
	}
	if !found {
		t.Error("exhausted budget should trigger FREEZE reflex")
	}
}

func TestEvaluateReflexes_FailedRunRollback(t *testing.T) {
	state := &GlobalAutonomyState{
		ActiveRuns: []RunSummaryProjection{
			{RunID: "run-1", CurrentStage: RunStageFailed},
		},
	}
	actions := EvaluateReflexes(state, DefaultReflexThresholds())
	found := false
	for _, a := range actions {
		if a.Kind == ReflexRollback && a.TargetRunID == "run-1" {
			found = true
		}
	}
	if !found {
		t.Error("failed run should trigger ROLLBACK reflex")
	}
}

func TestAllReflexKinds_Order(t *testing.T) {
	kinds := AllReflexKinds()
	if kinds[0] != ReflexIsland {
		t.Errorf("first reflex kind should be ISLAND (most severe), got %s", kinds[0])
	}
}

// ── Evidence Pack Attestation ─────────────────────────────────

func TestEvidencePackAttestation_Fields(t *testing.T) {
	att := EvidencePackAttestation{
		PackHash:  "sha256:abc123",
		SignerID:  "kernel-v1",
		Signature: "sig-hex",
	}
	if !strings.HasPrefix(att.PackHash, "sha256:") {
		t.Error("PackHash must start with sha256:")
	}
}

func TestEvidencePack_MinimalConstruction(t *testing.T) {
	pack := EvidencePack{
		PackID:        "ep-1",
		FormatVersion: "1.0.0",
		CreatedAt:     time.Now(),
		Attestation:   EvidencePackAttestation{PackHash: "sha256:000"},
	}
	if pack.PackID == "" || pack.FormatVersion == "" {
		t.Error("pack must have ID and format version")
	}
}

func TestEvidencePack_ThreatScanRef(t *testing.T) {
	ref := &ThreatScanRef{ScanID: "scan-1", MaxSeverity: ThreatSeverityHigh, FindingCount: 3}
	pack := EvidencePack{PackID: "ep-1", ThreatScan: ref}
	if pack.ThreatScan == nil || pack.ThreatScan.FindingCount != 3 {
		t.Error("threat scan ref must be correctly attached")
	}
}

func TestEvidencePackIdentity_DelegationChain(t *testing.T) {
	id := EvidencePackIdentity{
		ActorID:         "agent-1",
		ActorType:       "module",
		DelegationChain: []string{"root", "parent", "self"},
	}
	if len(id.DelegationChain) != 3 {
		t.Errorf("delegation chain length = %d, want 3", len(id.DelegationChain))
	}
}

// ── Posture & Budget ──────────────────────────────────────────

func TestPosture_CanEscalateTo(t *testing.T) {
	if !PostureObserve.CanEscalateTo(PostureTransact) {
		t.Error("OBSERVE should escalate to TRANSACT")
	}
	if PostureSovereign.CanEscalateTo(PostureDraft) {
		t.Error("SOVEREIGN should not escalate down to DRAFT")
	}
}

func TestBudget_Exhausted(t *testing.T) {
	b := &Budget{MaxTokens: 100, ConsumedTokens: 100}
	if !b.Exhausted() {
		t.Error("budget at limit should be exhausted")
	}
}

func TestBudget_RemainingTokens(t *testing.T) {
	b := &Budget{MaxTokens: 1000, ConsumedTokens: 300}
	if got := b.RemainingTokens(); got != 700 {
		t.Errorf("remaining = %d, want 700", got)
	}
}

// ── Risk Taxonomy ─────────────────────────────────────────────

func TestClassifyRisk_Ranges(t *testing.T) {
	cases := []struct {
		score float64
		want  RiskClass
	}{
		{0.0, RiskNone},
		{0.3, RiskLow},
		{0.5, RiskMedium},
		{0.8, RiskHigh},
		{0.95, RiskCritical},
	}
	for _, tc := range cases {
		if got := ClassifyRisk(tc.score); got != tc.want {
			t.Errorf("ClassifyRisk(%f) = %s, want %s", tc.score, got, tc.want)
		}
	}
}

func TestDefaultThresholds_CriticalAutoDeny(t *testing.T) {
	thresholds := DefaultThresholds()
	for _, th := range thresholds {
		if th.Class == RiskCritical && !th.AutoDeny {
			t.Error("CRITICAL threshold must auto-deny")
		}
	}
}

// ── Lanes ─────────────────────────────────────────────────────

func TestAllLanes_Count(t *testing.T) {
	lanes := AllLanes()
	if len(lanes) != 5 {
		t.Fatalf("expected 5 lanes, got %d", len(lanes))
	}
}

func TestLaneState_IsIdle(t *testing.T) {
	ls := &LaneState{ActiveRuns: 0, NextAction: ""}
	if !ls.IsIdle() {
		t.Error("lane with no runs and no next action should be idle")
	}
}

// ── Codec ─────────────────────────────────────────────────────

func TestDecodeDecisionRecord_JSON(t *testing.T) {
	input := `{"id":"d1","verdict":"ALLOW","reason":"ok"}`
	dr, err := DecodeDecisionRecord(input)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dr.ID != "d1" || dr.Verdict != "ALLOW" {
		t.Errorf("decoded = %+v, want id=d1, verdict=ALLOW", dr)
	}
}

func TestEncodeDecisionRecord_Roundtrip(t *testing.T) {
	original := &DecisionRecord{ID: "d2", Verdict: "DENY", Reason: "policy"}
	encoded, err := EncodeDecisionRecord(original)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, err := DecodeDecisionRecord(encoded)
	if err != nil {
		t.Fatalf("decode roundtrip failed: %v", err)
	}
	if decoded.ID != "d2" || decoded.Verdict != "DENY" {
		t.Error("roundtrip mismatch")
	}
}

// ── Default Condensation Policy ───────────────────────────────

func TestDefaultCondensationPolicy_ThreeTiers(t *testing.T) {
	p := DefaultCondensationPolicy()
	if len(p.RetentionPolicy) != 3 {
		t.Fatalf("expected 3 tiers, got %d", len(p.RetentionPolicy))
	}
}

// ── Severity Helpers ──────────────────────────────────────────

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityAtLeast(ThreatSeverityHigh, ThreatSeverityMedium) {
		t.Error("HIGH should be >= MEDIUM")
	}
	if SeverityAtLeast(ThreatSeverityLow, ThreatSeverityCritical) {
		t.Error("LOW should not be >= CRITICAL")
	}
}

func TestMaxSeverityOf(t *testing.T) {
	findings := []ThreatFinding{
		{Severity: ThreatSeverityLow},
		{Severity: ThreatSeverityCritical},
		{Severity: ThreatSeverityMedium},
	}
	if got := MaxSeverityOf(findings); got != ThreatSeverityCritical {
		t.Errorf("max severity = %s, want CRITICAL", got)
	}
}

func TestInputTrustLevel_IsTainted(t *testing.T) {
	if !InputTrustTainted.IsTainted() {
		t.Error("TAINTED must be tainted")
	}
	if InputTrustTrusted.IsTainted() {
		t.Error("TRUSTED must not be tainted")
	}
}
