package contracts

import (
	"strings"
	"testing"
	"time"
)

// ─── 1: Every E4 effect type returns "E4" ─────────────────────

func TestExt_AllE4EffectTypes(t *testing.T) {
	e4s := []string{EffectTypeInfraDestroy, EffectTypeCICredentialAccess, EffectTypeSoftwarePublish, EffectTypeDataEgress, EffectTypeExecutePayment, EffectTypeRequestPurchase}
	for _, et := range e4s {
		if got := EffectRiskClass(et); got != "E4" {
			t.Errorf("EffectRiskClass(%s) = %s, want E4", et, got)
		}
	}
}

// ─── 2: Every E3 effect type returns "E3" ─────────────────────

func TestExt_AllE3EffectTypes(t *testing.T) {
	e3s := []string{EffectTypeProtectedInfraWrite, EffectTypeEnvRecreate, EffectTypeAgentInvokePrivileged, EffectTypeTunnelStart}
	for _, et := range e3s {
		if got := EffectRiskClass(et); got != "E3" {
			t.Errorf("EffectRiskClass(%s) = %s, want E3", et, got)
		}
	}
}

// ─── 3: E2 medium-risk effects ────────────────────────────────

func TestExt_E2EffectTypes(t *testing.T) {
	e2s := []string{EffectTypeCloudComputeBudget, EffectTypeSendEmail, EffectTypeScreenCandidate, EffectTypeCallWebhook}
	for _, et := range e2s {
		if got := EffectRiskClass(et); got != "E2" {
			t.Errorf("EffectRiskClass(%s) = %s, want E2", et, got)
		}
	}
}

// ─── 4: E1 low-risk effects ──────────────────────────────────

func TestExt_E1EffectTypes(t *testing.T) {
	e1s := []string{EffectTypeSendChatMessage, EffectTypeCreateCalEvent, EffectTypeUpdateDoc, EffectTypeCreateTask, EffectTypeCommentTicket, EffectTypeRunSandboxedCode}
	for _, et := range e1s {
		if got := EffectRiskClass(et); got != "E1" {
			t.Errorf("EffectRiskClass(%s) = %s, want E1", et, got)
		}
	}
}

// ─── 5: All reason codes are canonical ────────────────────────

func TestExt_AllReasonCodesCanonical(t *testing.T) {
	for _, rc := range CoreReasonCodes() {
		if !IsCanonicalReasonCode(string(rc)) {
			t.Errorf("reason code %s not canonical", rc)
		}
	}
}

// ─── 6: Non-canonical reason code rejected ────────────────────

func TestExt_NonCanonicalReasonCode(t *testing.T) {
	if IsCanonicalReasonCode("TOTALLY_FAKE_CODE") {
		t.Fatal("TOTALLY_FAKE_CODE should not be canonical")
	}
}

// ─── 7: VerdictAllow is terminal ──────────────────────────────

func TestExt_VerdictAllowTerminal(t *testing.T) {
	if !VerdictAllow.IsTerminal() {
		t.Fatal("ALLOW should be terminal")
	}
}

// ─── 8: VerdictEscalate is not terminal ───────────────────────

func TestExt_VerdictEscalateNotTerminal(t *testing.T) {
	if VerdictEscalate.IsTerminal() {
		t.Fatal("ESCALATE should not be terminal")
	}
}

// ─── 9: DecisionRequest Validate — empty RequestID ────────────

func TestExt_DecisionRequestValidateEmptyID(t *testing.T) {
	dr := &DecisionRequest{Title: "t", Kind: DecisionKindApproval, Options: twoOptions()}
	if err := dr.Validate(); err == nil || !strings.Contains(err.Error(), "request_id") {
		t.Fatal("expected error for empty request_id")
	}
}

// ─── 10: DecisionRequest Validate — empty title ───────────────

func TestExt_DecisionRequestValidateEmptyTitle(t *testing.T) {
	dr := &DecisionRequest{RequestID: "r1", Kind: DecisionKindApproval, Options: twoOptions()}
	if err := dr.Validate(); err == nil || !strings.Contains(err.Error(), "title") {
		t.Fatal("expected error for empty title")
	}
}

// ─── 11: DecisionRequest Validate — title too long ────────────

func TestExt_DecisionRequestValidateTitleTooLong(t *testing.T) {
	dr := &DecisionRequest{RequestID: "r1", Title: strings.Repeat("x", 121), Kind: DecisionKindApproval, Options: twoOptions()}
	if err := dr.Validate(); err == nil || !strings.Contains(err.Error(), "120") {
		t.Fatal("expected error for title > 120 chars")
	}
}

// ─── 12: DecisionRequest Validate — too few options ───────────

func TestExt_DecisionRequestValidateTooFewOptions(t *testing.T) {
	dr := &DecisionRequest{RequestID: "r1", Title: "t", Kind: DecisionKindApproval, Options: []DecisionOption{{ID: "o1", Label: "L"}}}
	if err := dr.Validate(); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatal("expected error for < 2 concrete options")
	}
}

// ─── 13: DecisionRequest Validate — too many options ──────────

func TestExt_DecisionRequestValidateTooManyOptions(t *testing.T) {
	opts := make([]DecisionOption, 8)
	for i := range opts {
		opts[i] = DecisionOption{ID: string(rune('a' + i)), Label: "L"}
	}
	dr := &DecisionRequest{RequestID: "r1", Title: "t", Kind: DecisionKindApproval, Options: opts}
	if err := dr.Validate(); err == nil || !strings.Contains(err.Error(), "max") {
		t.Fatal("expected error for > 7 concrete options")
	}
}

// ─── 14: DecisionRequest Validate — duplicate option ID ───────

func TestExt_DecisionRequestValidateDuplicateOptionID(t *testing.T) {
	opts := []DecisionOption{{ID: "dup", Label: "A"}, {ID: "dup", Label: "B"}}
	dr := &DecisionRequest{RequestID: "r1", Title: "t", Kind: DecisionKindApproval, Options: opts}
	if err := dr.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatal("expected error for duplicate option IDs")
	}
}

// ─── 15: DecisionRequest Resolve — unknown option ID ──────────

func TestExt_DecisionRequestResolveUnknownOption(t *testing.T) {
	dr := validDecisionRequest()
	if err := dr.Resolve("nonexistent", "user"); err == nil {
		t.Fatal("expected error for unknown option ID")
	}
}

// ─── 16: DecisionRequest Resolve — not pending ────────────────

func TestExt_DecisionRequestResolveNotPending(t *testing.T) {
	dr := validDecisionRequest()
	dr.Status = DecisionStatusResolved
	if err := dr.Resolve("o1", "user"); err == nil {
		t.Fatal("expected error resolving non-pending request")
	}
}

// ─── 17: DecisionRequest Skip — not allowed ───────────────────

func TestExt_DecisionRequestSkipNotAllowed(t *testing.T) {
	dr := validDecisionRequest()
	dr.SkipAllowed = false
	if err := dr.Skip("user"); err == nil {
		t.Fatal("expected error when skip not allowed")
	}
}

// ─── 18: DecisionRequest Skip — not pending ──────────────────

func TestExt_DecisionRequestSkipNotPending(t *testing.T) {
	dr := validDecisionRequest()
	dr.SkipAllowed = true
	dr.Status = DecisionStatusExpired
	if err := dr.Skip("user"); err == nil {
		t.Fatal("expected error skipping non-pending request")
	}
}

// ─── 19: DecisionRequest CheckExpiry — expired ────────────────

func TestExt_DecisionRequestCheckExpiryExpired(t *testing.T) {
	dr := validDecisionRequest()
	dr.ExpiresAt = time.Now().Add(-1 * time.Hour)
	if !dr.CheckExpiry() {
		t.Fatal("expected expired")
	}
	if dr.Status != DecisionStatusExpired {
		t.Fatalf("expected EXPIRED status, got %s", dr.Status)
	}
}

// ─── 20: DecisionRequest CheckExpiry — not expired ────────────

func TestExt_DecisionRequestCheckExpiryNotExpired(t *testing.T) {
	dr := validDecisionRequest()
	dr.ExpiresAt = time.Now().Add(1 * time.Hour)
	if dr.CheckExpiry() {
		t.Fatal("should not be expired")
	}
}

// ─── 21: ApprovalBinding — drift detection ────────────────────

func TestExt_ApprovalBindingDriftDetection(t *testing.T) {
	ab := NewApprovalBinding("b1", "hash-original", "a1", time.Hour)
	if ab.CheckDrift("hash-original") {
		t.Fatal("should not drift when hashes match")
	}
	if !ab.CheckDrift("hash-changed") {
		t.Fatal("should detect drift when hashes differ")
	}
}

// ─── 22: ApprovalBinding — expired ────────────────────────────

func TestExt_ApprovalBindingExpired(t *testing.T) {
	ab := NewApprovalBinding("b1", "h", "a1", -1*time.Hour)
	if ab.IsValid(time.Now()) {
		t.Fatal("expired binding should not be valid")
	}
}

// ─── 23: Posture escalation ordering ──────────────────────────

func TestExt_PostureEscalation(t *testing.T) {
	if !PostureObserve.CanEscalateTo(PostureSovereign) {
		t.Fatal("OBSERVE should escalate to SOVEREIGN")
	}
	if PostureSovereign.CanEscalateTo(PostureObserve) {
		t.Fatal("SOVEREIGN should not escalate to OBSERVE")
	}
	if PostureTransact.CanEscalateTo(PostureTransact) {
		t.Fatal("same posture should not escalate to itself")
	}
}

// ─── 24: Budget exhausted ─────────────────────────────────────

func TestExt_BudgetExhausted(t *testing.T) {
	b := &Budget{MaxTokens: 100, ConsumedTokens: 100}
	if !b.Exhausted() {
		t.Fatal("budget should be exhausted when tokens consumed")
	}
	b2 := &Budget{MaxCostCents: 50, ConsumedCostCents: 51}
	if !b2.Exhausted() {
		t.Fatal("budget should be exhausted when cost exceeded")
	}
}

// ─── 25: Budget remaining tokens ──────────────────────────────

func TestExt_BudgetRemainingTokens(t *testing.T) {
	b := &Budget{MaxTokens: 100, ConsumedTokens: 30}
	if b.RemainingTokens() != 70 {
		t.Fatalf("expected 70 remaining, got %d", b.RemainingTokens())
	}
	b2 := &Budget{MaxTokens: 10, ConsumedTokens: 20}
	if b2.RemainingTokens() != 0 {
		t.Fatalf("over-consumed should return 0, got %d", b2.RemainingTokens())
	}
}

// ─── helpers ──────────────────────────────────────────────────

func twoOptions() []DecisionOption {
	return []DecisionOption{{ID: "o1", Label: "A"}, {ID: "o2", Label: "B"}}
}

func validDecisionRequest() *DecisionRequest {
	return &DecisionRequest{
		RequestID: "r1",
		Title:     "Choose an option",
		Kind:      DecisionKindApproval,
		Status:    DecisionStatusPending,
		Options:   twoOptions(),
	}
}
