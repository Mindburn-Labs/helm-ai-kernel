package contracts

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ── CondensationTier constants ──────────────────────────────────────────

func TestStress_RiskTierLow(t *testing.T) {
	if RiskTierLow != "LOW" {
		t.Fatalf("expected LOW, got %s", RiskTierLow)
	}
}

func TestStress_RiskTierMedium(t *testing.T) {
	if RiskTierMedium != "MEDIUM" {
		t.Fatalf("expected MEDIUM, got %s", RiskTierMedium)
	}
}

func TestStress_RiskTierHigh(t *testing.T) {
	if RiskTierHigh != "HIGH" {
		t.Fatalf("expected HIGH, got %s", RiskTierHigh)
	}
}

func TestStress_DefaultCondensationPolicyTierCount(t *testing.T) {
	policy := DefaultCondensationPolicy()
	if len(policy.RetentionPolicy) != 3 {
		t.Fatalf("expected 3 tiers, got %d", len(policy.RetentionPolicy))
	}
}

// ── Lane constants ──────────────────────────────────────────────────────

func TestStress_LaneResearch(t *testing.T) {
	if LaneResearch != "RESEARCH" {
		t.Fatalf("got %s", LaneResearch)
	}
}

func TestStress_LaneBuild(t *testing.T) {
	if LaneBuild != "BUILD" {
		t.Fatalf("got %s", LaneBuild)
	}
}

func TestStress_LaneGTM(t *testing.T) {
	if LaneGTM != "GTM" {
		t.Fatalf("got %s", LaneGTM)
	}
}

func TestStress_LaneOps(t *testing.T) {
	if LaneOps != "OPS" {
		t.Fatalf("got %s", LaneOps)
	}
}

func TestStress_LaneCompliance(t *testing.T) {
	if LaneCompliance != "COMPLIANCE" {
		t.Fatalf("got %s", LaneCompliance)
	}
}

func TestStress_AllLanesCount(t *testing.T) {
	if len(AllLanes()) != 5 {
		t.Fatalf("expected 5 lanes, got %d", len(AllLanes()))
	}
}

// ── InterventionType constants ──────────────────────────────────────────

func TestStress_InterventionNone(t *testing.T) {
	if InterventionNone != "NONE" {
		t.Fatalf("got %s", InterventionNone)
	}
}

func TestStress_InterventionThrottle(t *testing.T) {
	if InterventionThrottle != "THROTTLE" {
		t.Fatalf("got %s", InterventionThrottle)
	}
}

func TestStress_InterventionInterrupt(t *testing.T) {
	if InterventionInterrupt != "INTERRUPT" {
		t.Fatalf("got %s", InterventionInterrupt)
	}
}

func TestStress_InterventionQuarantine(t *testing.T) {
	if InterventionQuarantine != "QUARANTINE" {
		t.Fatalf("got %s", InterventionQuarantine)
	}
}

// ── Verdict constants ───────────────────────────────────────────────────

func TestStress_VerdictAllow(t *testing.T) {
	if VerdictAllow != "ALLOW" {
		t.Fatalf("got %s", VerdictAllow)
	}
}

func TestStress_VerdictDeny(t *testing.T) {
	if VerdictDeny != "DENY" {
		t.Fatalf("got %s", VerdictDeny)
	}
}

func TestStress_VerdictEscalate(t *testing.T) {
	if VerdictEscalate != "ESCALATE" {
		t.Fatalf("got %s", VerdictEscalate)
	}
}

func TestStress_VerdictAllowIsTerminal(t *testing.T) {
	if !VerdictAllow.IsTerminal() {
		t.Fatal("ALLOW should be terminal")
	}
}

func TestStress_VerdictEscalateNotTerminal(t *testing.T) {
	if VerdictEscalate.IsTerminal() {
		t.Fatal("ESCALATE should not be terminal")
	}
}

// ── Receipt 100-deep chain ──────────────────────────────────────────────

func TestStress_Receipt100DeepChain(t *testing.T) {
	var prev string
	for i := range 100 {
		r := Receipt{
			ReceiptID:    fmt.Sprintf("r-%d", i),
			DecisionID:   "d-1",
			PrevHash:     prev,
			LamportClock: uint64(i),
			Timestamp:    time.Now(),
		}
		prev = r.ReceiptID // simulate chain
		if r.PrevHash == "" && i > 0 {
			t.Fatalf("chain broken at %d", i)
		}
	}
}

// ── CompensationRecipe 50 steps ─────────────────────────────────────────

func TestStress_CompensationRecipe50Steps(t *testing.T) {
	steps := make([]CompensationStep, 50)
	for i := range 50 {
		steps[i] = CompensationStep{
			StepID: fmt.Sprintf("s-%d", i), Order: i, Action: "revert",
			Target: fmt.Sprintf("svc-%d", i), Idempotent: true, Fallback: "notify",
		}
	}
	recipe := NewCompensationRecipe("run-50", steps, true)
	if len(recipe.Steps) != 50 {
		t.Fatalf("expected 50, got %d", len(recipe.Steps))
	}
	if !recipe.HasFallbacks() {
		t.Fatal("all steps have fallbacks")
	}
}

// ── DecisionRequest with maximum options ────────────────────────────────

func TestStress_DecisionRequestMaxOptions(t *testing.T) {
	opts := make([]DecisionOption, 7)
	for i := range 7 {
		opts[i] = DecisionOption{ID: fmt.Sprintf("opt-%d", i), Label: fmt.Sprintf("Option %d", i)}
	}
	opts = append(opts, DecisionOption{ID: "skip", Label: "Skip", IsSkip: true})
	opts = append(opts, DecisionOption{ID: "other", Label: "Something else", IsSomethingElse: true})
	dr := DecisionRequest{RequestID: "dr-1", Kind: DecisionKindApproval, Title: "Test", Options: opts, Priority: DecisionPriorityNormal, Status: DecisionStatusPending}
	if err := dr.Validate(); err != nil {
		t.Fatalf("should be valid: %v", err)
	}
}

func TestStress_DecisionRequestTooManyOptions(t *testing.T) {
	opts := make([]DecisionOption, 8)
	for i := range 8 {
		opts[i] = DecisionOption{ID: fmt.Sprintf("opt-%d", i), Label: fmt.Sprintf("Option %d", i)}
	}
	dr := DecisionRequest{RequestID: "dr-2", Kind: DecisionKindApproval, Title: "Test", Options: opts, Priority: DecisionPriorityNormal, Status: DecisionStatusPending}
	if err := dr.Validate(); err == nil {
		t.Fatal("8 concrete options should fail")
	}
}

// ── Effect types ────────────────────────────────────────────────────────

func TestStress_EffectCatalogAllParams(t *testing.T) {
	catalog := DefaultEffectCatalog()
	for _, et := range catalog.EffectTypes {
		if et.TypeID == "" || et.Name == "" {
			t.Fatalf("effect type missing ID or Name: %+v", et)
		}
		rc := EffectRiskClass(et.TypeID)
		if rc == "" {
			t.Fatalf("no risk class for %s", et.TypeID)
		}
	}
}

func TestStress_EffectUnknownDefaultsE3(t *testing.T) {
	if EffectRiskClass("UNKNOWN_TYPE") != "E3" {
		t.Fatal("unknown effect types should default to E3")
	}
}

// ── ReasonCode individual verification ──────────────────────────────────

func TestStress_ReasonCodePolicyViolation(t *testing.T) {
	if !IsCanonicalReasonCode("POLICY_VIOLATION") {
		t.Fatal("POLICY_VIOLATION should be canonical")
	}
}

func TestStress_ReasonCodeNoPolicy(t *testing.T) {
	if !IsCanonicalReasonCode("NO_POLICY_DEFINED") {
		t.Fatal("NO_POLICY_DEFINED should be canonical")
	}
}

func TestStress_ReasonCodeBudgetExceeded(t *testing.T) {
	if !IsCanonicalReasonCode("BUDGET_EXCEEDED") {
		t.Fatal("BUDGET_EXCEEDED should be canonical")
	}
}

func TestStress_ReasonCodeSystemFrozen(t *testing.T) {
	if !IsCanonicalReasonCode("SYSTEM_FROZEN") {
		t.Fatal("SYSTEM_FROZEN should be canonical")
	}
}

func TestStress_ReasonCodeAgentKilled(t *testing.T) {
	if !IsCanonicalReasonCode("AGENT_KILLED") {
		t.Fatal("AGENT_KILLED should be canonical")
	}
}

func TestStress_ReasonCodeTaintedInputDeny(t *testing.T) {
	if !IsCanonicalReasonCode("TAINTED_INPUT_HIGH_RISK_DENY") {
		t.Fatal("TAINTED_INPUT_HIGH_RISK_DENY should be canonical")
	}
}

func TestStress_ReasonCodePromptInjection(t *testing.T) {
	if !IsCanonicalReasonCode("PROMPT_INJECTION_DETECTED") {
		t.Fatal("PROMPT_INJECTION_DETECTED should be canonical")
	}
}

func TestStress_ReasonCodeDelegationInvalid(t *testing.T) {
	if !IsCanonicalReasonCode("DELEGATION_INVALID") {
		t.Fatal("DELEGATION_INVALID should be canonical")
	}
}

func TestStress_ReasonCodeInsufficientPrivilege(t *testing.T) {
	if !IsCanonicalReasonCode("INSUFFICIENT_PRIVILEGE") {
		t.Fatal("INSUFFICIENT_PRIVILEGE should be canonical")
	}
}

func TestStress_AllReasonCodesCanonical(t *testing.T) {
	codes := CoreReasonCodes()
	for _, code := range codes {
		if !IsCanonicalReasonCode(string(code)) {
			t.Fatalf("%s not canonical", code)
		}
	}
}

func TestStress_NonCanonicalReasonCode(t *testing.T) {
	if IsCanonicalReasonCode("TOTALLY_FAKE_CODE") {
		t.Fatal("fake code should not be canonical")
	}
}

func TestStress_NonCanonicalVerdict(t *testing.T) {
	if IsCanonicalVerdict("MAYBE") {
		t.Fatal("MAYBE should not be canonical")
	}
}

func TestStress_LaneStateIdle(t *testing.T) {
	ls := &LaneState{Lane: LaneResearch, ActiveRuns: 0, NextAction: ""}
	if !ls.IsIdle() {
		t.Fatal("should be idle")
	}
}

func TestStress_LaneStateNotIdle(t *testing.T) {
	ls := &LaneState{Lane: LaneBuild, ActiveRuns: 1}
	if ls.IsIdle() {
		t.Fatal("should not be idle with active runs")
	}
}

func TestStress_ReceiptV5Fields(t *testing.T) {
	r := Receipt{
		ReceiptID: "r-v5", SandboxLeaseID: "lease-1", EffectGraphNodeID: "node-1",
		NetworkLogRef: "ref-1", SecretEventsRef: "secret-1",
		PortExposures: []PortExposureEvent{{Port: 8080, Protocol: "tcp", Direction: "inbound"}},
	}
	if len(r.PortExposures) != 1 || r.PortExposures[0].Port != 8080 {
		t.Fatal("V5 port exposure mismatch")
	}
}

func TestStress_ContentHashNotEmpty(t *testing.T) {
	recipe := NewCompensationRecipe("r-hash", []CompensationStep{{StepID: "s1", Action: "a"}}, false)
	if !strings.HasPrefix(recipe.ContentHash, "sha256:") {
		t.Fatal("content hash should have sha256 prefix")
	}
}

func TestStress_DecisionRequestResolve(t *testing.T) {
	dr := DecisionRequest{
		RequestID: "dr-r", Kind: DecisionKindApproval, Title: "T",
		Options: []DecisionOption{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}},
		Status:  DecisionStatusPending,
	}
	if err := dr.Resolve("a", "admin"); err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dr.Status != DecisionStatusResolved {
		t.Fatal("should be resolved")
	}
}

func TestStress_DecisionRequestDoubleResolve(t *testing.T) {
	dr := DecisionRequest{
		RequestID: "dr-dr", Kind: DecisionKindApproval, Title: "T",
		Options: []DecisionOption{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}},
		Status:  DecisionStatusPending,
	}
	_ = dr.Resolve("a", "admin")
	if err := dr.Resolve("b", "admin"); err == nil {
		t.Fatal("second resolve should fail")
	}
}
