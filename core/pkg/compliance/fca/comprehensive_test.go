package fca

import (
	"context"
	"testing"
	"time"
)

func TestFCAEngine_HasDefaultConductRules(t *testing.T) {
	engine := NewFCAEngine()
	status := engine.GetStatus()
	if status["conduct_rules"].(int) != 8 {
		t.Errorf("expected 8 default conduct rules, got %d", status["conduct_rules"].(int))
	}
}

func TestRegisterSMCRRole_ValidRole(t *testing.T) {
	engine := NewFCAEngine()
	err := engine.RegisterSMCRRole(context.Background(), &SMCRRole{
		ID: "smcr-1", FunctionCode: "SMF1", Title: "CEO",
		HolderName: "Jane Doe", ApprovedDate: time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	status := engine.GetStatus()
	if status["smcr_roles"].(int) != 1 {
		t.Error("expected 1 SMCR role")
	}
}

func TestRegisterSMCRRole_NoFunctionCodeError(t *testing.T) {
	engine := NewFCAEngine()
	err := engine.RegisterSMCRRole(context.Background(), &SMCRRole{
		ID: "smcr-1", Title: "CEO",
	})
	if err == nil {
		t.Error("expected error for missing function code")
	}
}

func TestRegisterSystemControl_ValidControl(t *testing.T) {
	engine := NewFCAEngine()
	err := engine.RegisterSystemControl(context.Background(), &SystemControl{
		ID: "sysc-1", SYSCRef: "SYSC 6.1.1", Status: "COMPLIANT",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegisterSystemControl_NoSYSCRefError(t *testing.T) {
	engine := NewFCAEngine()
	err := engine.RegisterSystemControl(context.Background(), &SystemControl{
		ID: "sysc-1", Status: "COMPLIANT",
	})
	if err == nil {
		t.Error("expected error for missing SYSC reference")
	}
}

func TestAssessConsumerDuty_MultipleOutcomes(t *testing.T) {
	engine := NewFCAEngine()
	engine.AssessConsumerDuty(OutcomeProducts, "GOOD")
	engine.AssessConsumerDuty(OutcomePrice, "FAIR")
	status := engine.GetStatus()
	if status["consumer_duty_assessments"].(int) != 2 {
		t.Errorf("expected 2 assessments, got %d", status["consumer_duty_assessments"].(int))
	}
}

func TestAssessConsumerDuty_OverwritesPrevious(t *testing.T) {
	engine := NewFCAEngine()
	engine.AssessConsumerDuty(OutcomeProducts, "POOR")
	engine.AssessConsumerDuty(OutcomeProducts, "GOOD")
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	if engine.dutyAssessments[OutcomeProducts] != "GOOD" {
		t.Error("latest assessment should overwrite previous")
	}
}

func TestGetStatus_NonCompliantControls(t *testing.T) {
	engine := NewFCAEngine()
	ctx := context.Background()
	engine.RegisterSystemControl(ctx, &SystemControl{
		ID: "s1", SYSCRef: "SYSC 6.1.1", Status: "NON_COMPLIANT",
	})
	engine.RegisterSystemControl(ctx, &SystemControl{
		ID: "s2", SYSCRef: "SYSC 6.1.2", Status: "COMPLIANT",
	})
	status := engine.GetStatus()
	if status["non_compliant"].(int) != 1 {
		t.Errorf("expected 1 non-compliant control, got %d", status["non_compliant"].(int))
	}
}

func TestGetStatus_PartiallyCompliantNotCounted(t *testing.T) {
	engine := NewFCAEngine()
	engine.RegisterSystemControl(context.Background(), &SystemControl{
		ID: "s1", SYSCRef: "SYSC 7.1.1", Status: "PARTIALLY_COMPLIANT",
	})
	status := engine.GetStatus()
	if status["non_compliant"].(int) != 0 {
		t.Error("partially compliant should not count as non-compliant")
	}
}

func TestConsumerDutyOutcomeConstants(t *testing.T) {
	outcomes := []ConsumerDutyOutcome{
		OutcomeProducts, OutcomePrice, OutcomeUnderstanding, OutcomeSupport,
	}
	if len(outcomes) != 4 {
		t.Fatalf("expected 4 consumer duty outcomes, got %d", len(outcomes))
	}
}

func TestDefaultConductRules_TierCoverage(t *testing.T) {
	engine := NewFCAEngine()
	tier1, tier2 := 0, 0
	for _, r := range engine.conductRules {
		switch r.Tier {
		case "1":
			tier1++
		case "2":
			tier2++
		}
	}
	if tier1 != 5 {
		t.Errorf("expected 5 tier-1 rules, got %d", tier1)
	}
	if tier2 != 3 {
		t.Errorf("expected 3 tier-2 rules, got %d", tier2)
	}
}

func TestDefaultConductRules_AllActive(t *testing.T) {
	engine := NewFCAEngine()
	for _, r := range engine.conductRules {
		if !r.Active {
			t.Errorf("rule %s should be active", r.ID)
		}
	}
}

func TestMultipleSMCRRoles(t *testing.T) {
	engine := NewFCAEngine()
	ctx := context.Background()
	engine.RegisterSMCRRole(ctx, &SMCRRole{ID: "r1", FunctionCode: "SMF1"})
	engine.RegisterSMCRRole(ctx, &SMCRRole{ID: "r2", FunctionCode: "SMF24"})
	status := engine.GetStatus()
	if status["smcr_roles"].(int) != 2 {
		t.Errorf("expected 2 SMCR roles, got %d", status["smcr_roles"].(int))
	}
}

func TestGetStatus_EmptyEngine(t *testing.T) {
	engine := NewFCAEngine()
	status := engine.GetStatus()
	if status["smcr_roles"].(int) != 0 || status["system_controls"].(int) != 0 {
		t.Error("empty engine should have 0 roles and controls")
	}
}
