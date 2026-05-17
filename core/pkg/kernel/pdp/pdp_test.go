package pdp

import (
	"testing"
	"time"
)

func TestValidateESCALATEResponse_NotDefer(t *testing.T) {
	resp := PDPResponse{Decision: "ALLOW"}
	if err := ValidateESCALATEResponse(resp); err != nil {
		t.Errorf("non-ESCALATE should pass validation: %v", err)
	}
}

func TestValidateESCALATEResponse_Valid(t *testing.T) {
	resp := PDPResponse{
		Decision:        "ESCALATE",
		DeferReasonCode: "FACT_MISSING",
		RequiredFacts: []FactRef{
			{FactType: "identity", FactID: "user-123", RequiredBy: time.Now().Add(time.Hour)},
		},
		TimeoutPolicy: &TimeoutPolicy{
			PolicyID:          "timeout-1",
			TimeoutDurationMs: 30000,
			TimeoutAction:     "FAIL_CLOSED",
		},
		RequeryRule: &RequeryRule{
			Mode:              "EXACT_REUSE",
			OriginalQueryHash: "abc123",
		},
	}
	if err := ValidateESCALATEResponse(resp); err != nil {
		t.Errorf("valid ESCALATE should pass: %v", err)
	}
}

func TestValidateESCALATEResponse_MissingReasonCode(t *testing.T) {
	resp := PDPResponse{
		Decision:      "ESCALATE",
		RequiredFacts: []FactRef{{FactType: "x", FactID: "y"}},
		TimeoutPolicy: &TimeoutPolicy{},
		RequeryRule:   &RequeryRule{},
	}
	if err := ValidateESCALATEResponse(resp); err == nil {
		t.Error("expected error for missing defer_reason_code")
	}
}

func TestValidateESCALATEResponse_MissingFacts(t *testing.T) {
	resp := PDPResponse{
		Decision:        "ESCALATE",
		DeferReasonCode: "FACT_MISSING",
		TimeoutPolicy:   &TimeoutPolicy{},
		RequeryRule:     &RequeryRule{},
	}
	if err := ValidateESCALATEResponse(resp); err == nil {
		t.Error("expected error for missing required_facts")
	}
}

func TestValidateESCALATEResponse_MissingTimeout(t *testing.T) {
	resp := PDPResponse{
		Decision:        "ESCALATE",
		DeferReasonCode: "FACT_MISSING",
		RequiredFacts:   []FactRef{{FactType: "x", FactID: "y"}},
		RequeryRule:     &RequeryRule{},
	}
	if err := ValidateESCALATEResponse(resp); err == nil {
		t.Error("expected error for missing timeout_policy")
	}
}

func TestValidateESCALATEResponse_MissingRequery(t *testing.T) {
	resp := PDPResponse{
		Decision:        "ESCALATE",
		DeferReasonCode: "FACT_MISSING",
		RequiredFacts:   []FactRef{{FactType: "x", FactID: "y"}},
		TimeoutPolicy:   &TimeoutPolicy{},
	}
	if err := ValidateESCALATEResponse(resp); err == nil {
		t.Error("expected error for missing requery_rule")
	}
}

func TestCheckTimeout_NotExpired(t *testing.T) {
	state := ObligationState{EnteredAt: time.Now()}
	policy := TimeoutPolicy{
		TimeoutDurationMs: 60000, // 60 seconds
		TimeoutAction:     "FAIL_CLOSED",
	}
	result := CheckTimeout(state, policy, time.Now())
	if result.Expired {
		t.Error("should not be expired")
	}
	if result.RemainingMs <= 0 {
		t.Errorf("expected positive remaining time, got %d", result.RemainingMs)
	}
}

func TestCheckTimeout_Expired(t *testing.T) {
	state := ObligationState{EnteredAt: time.Now().Add(-2 * time.Minute)}
	policy := TimeoutPolicy{
		TimeoutDurationMs: 60000,
		TimeoutAction:     "ESCALATE_TO_HUMAN",
	}
	result := CheckTimeout(state, policy, time.Now())
	if !result.Expired {
		t.Error("should be expired")
	}
	if result.Action != "ESCALATE_TO_HUMAN" {
		t.Errorf("expected ESCALATE_TO_HUMAN, got %s", result.Action)
	}
}

func TestCheckTimeout_ExactBoundary(t *testing.T) {
	now := time.Now()
	state := ObligationState{EnteredAt: now.Add(-100 * time.Millisecond)}
	policy := TimeoutPolicy{
		TimeoutDurationMs: 100,
		TimeoutAction:     "FAIL_CLOSED",
	}
	// Check at exactly now (which is 100ms after entry)
	result := CheckTimeout(state, policy, now)
	// At exact boundary, deadline == now, so now.After(deadline) is false
	if result.Expired {
		t.Error("at exact boundary should not be expired (After is strict)")
	}
}
