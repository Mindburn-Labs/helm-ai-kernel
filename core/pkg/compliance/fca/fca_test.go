package fca

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewFCAEngine(t *testing.T) {
	engine := NewFCAEngine()
	require.NotNil(t, engine)
	require.Equal(t, 8, len(engine.conductRules)) // 5 Tier-1 + 3 Tier-2
}

func TestRegisterSMCRRole(t *testing.T) {
	engine := NewFCAEngine()
	ctx := context.Background()

	role := &SMCRRole{
		ID:              "smf-1",
		FunctionCode:    "SMF1",
		Title:           "CEO",
		HolderName:      "Test Holder",
		ApprovedDate:    time.Now(),
		LastAttested:    time.Now(),
		StatementOfResp: "Overall executive accountability",
	}

	err := engine.RegisterSMCRRole(ctx, role)
	require.NoError(t, err)

	status := engine.GetStatus()
	require.Equal(t, 1, status["smcr_roles"])
}

func TestRegisterSMCRRole_EmptyFunctionCode(t *testing.T) {
	engine := NewFCAEngine()
	err := engine.RegisterSMCRRole(context.Background(), &SMCRRole{ID: "bad"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "function code")
}

func TestRegisterSystemControl(t *testing.T) {
	engine := NewFCAEngine()
	ctx := context.Background()

	ctrl := &SystemControl{
		ID:           "sysc-1",
		SYSCRef:      "SYSC 6.1.1",
		Category:     "governance",
		Description:  "Appropriate governance arrangements",
		Status:       "COMPLIANT",
		EvidenceRefs: []string{"evidence-001"},
		LastReviewed: time.Now(),
	}

	err := engine.RegisterSystemControl(ctx, ctrl)
	require.NoError(t, err)

	status := engine.GetStatus()
	require.Equal(t, 1, status["system_controls"])
	require.Equal(t, 0, status["non_compliant"])
}

func TestRegisterSystemControl_NonCompliant(t *testing.T) {
	engine := NewFCAEngine()
	ctrl := &SystemControl{ID: "sysc-2", SYSCRef: "SYSC 7.1.1", Status: "NON_COMPLIANT"}
	require.NoError(t, engine.RegisterSystemControl(context.Background(), ctrl))

	status := engine.GetStatus()
	require.Equal(t, 1, status["non_compliant"])
}

func TestRegisterSystemControl_EmptySYSCRef(t *testing.T) {
	engine := NewFCAEngine()
	err := engine.RegisterSystemControl(context.Background(), &SystemControl{ID: "bad"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "SYSC reference")
}

func TestAssessConsumerDuty(t *testing.T) {
	engine := NewFCAEngine()

	engine.AssessConsumerDuty(OutcomeProducts, "GREEN")
	engine.AssessConsumerDuty(OutcomePrice, "AMBER")
	engine.AssessConsumerDuty(OutcomeUnderstanding, "RED")
	engine.AssessConsumerDuty(OutcomeSupport, "GREEN")

	status := engine.GetStatus()
	require.Equal(t, 4, status["consumer_duty_assessments"])
}

func TestGetStatus_Comprehensive(t *testing.T) {
	engine := NewFCAEngine()
	ctx := context.Background()

	// Register controls
	_ = engine.RegisterSystemControl(ctx, &SystemControl{ID: "s1", SYSCRef: "SYSC 6.1.1", Status: "COMPLIANT"})
	_ = engine.RegisterSystemControl(ctx, &SystemControl{ID: "s2", SYSCRef: "SYSC 7.1.1", Status: "NON_COMPLIANT"})

	// Register SM&CR role
	_ = engine.RegisterSMCRRole(ctx, &SMCRRole{ID: "r1", FunctionCode: "SMF1"})

	// Assess duties
	engine.AssessConsumerDuty(OutcomeProducts, "GREEN")

	status := engine.GetStatus()
	require.Equal(t, 8, status["conduct_rules"])
	require.Equal(t, 1, status["smcr_roles"])
	require.Equal(t, 2, status["system_controls"])
	require.Equal(t, 1, status["non_compliant"])
	require.Equal(t, 1, status["consumer_duty_assessments"])
}

func TestConductRuleConstants(t *testing.T) {
	rules := defaultConductRules()
	require.Equal(t, 8, len(rules))

	tier1Count := 0
	tier2Count := 0
	for _, r := range rules {
		require.NotEmpty(t, r.RuleRef)
		require.True(t, r.Active)
		switch r.Tier {
		case "1":
			tier1Count++
		case "2":
			tier2Count++
		}
	}
	require.Equal(t, 5, tier1Count)
	require.Equal(t, 3, tier2Count)
}
