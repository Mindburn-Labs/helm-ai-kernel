package cftc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCFTCEngine_AssessMarket_EventContract(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	err := engine.AssessMarket(ctx, &PredictionMarketAssessment{
		MarketID:        "polymarket-001",
		MarketName:      "US Election 2028",
		Classification:  ClassEventContract,
		IsDCMRegistered: true,
		RiskLevel:       "HIGH",
	})
	require.NoError(t, err)

	assessment, err := engine.GetMarketAssessment(ctx, "polymarket-001")
	require.NoError(t, err)
	assert.Equal(t, ClassEventContract, assessment.Classification)
	assert.Contains(t, assessment.HELMRequirements, "guardian_policy_enforcement")
	assert.Contains(t, assessment.HELMRequirements, "dcm_core_principle_compliance")
	assert.NotZero(t, assessment.AssessedAt)
}

func TestCFTCEngine_AssessMarket_Swap(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	err := engine.AssessMarket(ctx, &PredictionMarketAssessment{
		MarketID:       "swap-mkt-001",
		MarketName:     "Commodity Swap",
		Classification: ClassSwap,
		RequiresSEF:    true,
		SwapReporting:  true,
		RiskLevel:      "HIGH",
	})
	require.NoError(t, err)

	assessment, err := engine.GetMarketAssessment(ctx, "swap-mkt-001")
	require.NoError(t, err)
	assert.Contains(t, assessment.HELMRequirements, "swap_reporting_sdrs")
	assert.Contains(t, assessment.HELMRequirements, "sef_execution_method")
	assert.Contains(t, assessment.HELMRequirements, "counterparty_verification")
}

func TestCFTCEngine_AssessMarket_Excluded(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	err := engine.AssessMarket(ctx, &PredictionMarketAssessment{
		MarketID:        "excluded-001",
		MarketName:      "Excluded Event",
		Classification:  ClassExcluded,
		ExclusionReason: ExclusionGaming,
		RiskLevel:       "CRITICAL",
	})
	require.NoError(t, err)

	assessment, err := engine.GetMarketAssessment(ctx, "excluded-001")
	require.NoError(t, err)
	assert.Contains(t, assessment.HELMRequirements, "market_participation_blocked")

	// Check exclusion helper
	excluded, reason := engine.IsMarketExcluded(ctx, "excluded-001")
	assert.True(t, excluded)
	assert.Equal(t, ExclusionGaming, reason)
}

func TestCFTCEngine_AssessMarket_NotExcluded(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	excluded, _ := engine.IsMarketExcluded(ctx, "nonexistent")
	assert.False(t, excluded)
}

func TestCFTCEngine_AssessMarket_Validation(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	err := engine.AssessMarket(ctx, nil)
	assert.Error(t, err)

	err = engine.AssessMarket(ctx, &PredictionMarketAssessment{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "market_id")
}

func TestCFTCEngine_RegisterAgent(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	err := engine.RegisterAgent(ctx, &AIAgentRegistration{
		AgentID:      "agent-001",
		EntityName:   "Titan Brain",
		DirectAccess: true,
		MarketTypes:  []string{"prediction_markets", "binary_options"},
	})
	require.NoError(t, err)

	engine.mu.RLock()
	agent := engine.agents["agent-001"]
	engine.mu.RUnlock()

	assert.Equal(t, RegistrationRequired, agent.Status, "direct-access agents require registration")
}

func TestCFTCEngine_RegisterAgent_Validation(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	err := engine.RegisterAgent(ctx, nil)
	assert.Error(t, err)

	err = engine.RegisterAgent(ctx, &AIAgentRegistration{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "agent_id")
}

func TestCFTCEngine_AddRiskControl(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	err := engine.AddRiskControl(ctx, &AlgoTradingRiskControl{
		ControlID:    "ctrl-001",
		AgentID:      "agent-001",
		Type:         RiskControlKillSwitch,
		Description:  "Emergency halt for all trading",
		ThresholdVal: "immediate",
		Enabled:      true,
	})
	require.NoError(t, err)

	engine.mu.RLock()
	ctrl := engine.riskControls["ctrl-001"]
	engine.mu.RUnlock()

	assert.Equal(t, RiskControlKillSwitch, ctrl.Type)
	assert.True(t, ctrl.Enabled)
	assert.NotZero(t, ctrl.CreatedAt)
}

func TestCFTCEngine_RecordKillSwitchTrigger(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	engine.AddRiskControl(ctx, &AlgoTradingRiskControl{
		ControlID: "ctrl-kill",
		AgentID:   "agent-001",
		Type:      RiskControlKillSwitch,
		Enabled:   true,
	})

	err := engine.RecordKillSwitchTrigger(ctx, "ctrl-kill")
	require.NoError(t, err)

	engine.mu.RLock()
	ctrl := engine.riskControls["ctrl-kill"]
	engine.mu.RUnlock()

	assert.Equal(t, int64(1), ctrl.TriggerCount)
	assert.NotNil(t, ctrl.LastTriggered)

	// Trigger again
	require.NoError(t, engine.RecordKillSwitchTrigger(ctx, "ctrl-kill"))
	engine.mu.RLock()
	ctrl = engine.riskControls["ctrl-kill"]
	engine.mu.RUnlock()
	assert.Equal(t, int64(2), ctrl.TriggerCount)
}

func TestCFTCEngine_RecordKillSwitchTrigger_NotFound(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	err := engine.RecordKillSwitchTrigger(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestCFTCEngine_SubmitITFReport(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	err := engine.SubmitITFReport(ctx, &InnovationTaskForceReport{
		ReportID:    "itf-001",
		EntityName:  "TestEntity",
		Program:     "LabCFTC",
		Topic:       "AI-Driven Trading Agent Governance",
		Description: "Engagement request for AI agent oversight framework",
	})
	require.NoError(t, err)

	engine.mu.RLock()
	report := engine.itfReports["itf-001"]
	engine.mu.RUnlock()

	assert.Equal(t, "submitted", report.Status)
	assert.NotZero(t, report.SubmittedAt)
}

func TestCFTCEngine_SubmitITFReport_Validation(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	err := engine.SubmitITFReport(ctx, nil)
	assert.Error(t, err)

	err = engine.SubmitITFReport(ctx, &InnovationTaskForceReport{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "report_id")
}

func TestCFTCEngine_ComplianceStatus_Compliant(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	// Assess a non-excluded market
	engine.AssessMarket(ctx, &PredictionMarketAssessment{
		MarketID:       "mkt-001",
		Classification: ClassEventContract,
	})

	// Register an agent with controls
	engine.RegisterAgent(ctx, &AIAgentRegistration{
		AgentID:      "agent-001",
		DirectAccess: true,
		Status:       RegistrationActive,
		RiskControls: []string{"ctrl-001"},
	})

	engine.AddRiskControl(ctx, &AlgoTradingRiskControl{
		ControlID: "ctrl-001",
		Type:      RiskControlKillSwitch,
	})

	status := engine.GetComplianceStatus(ctx)
	assert.True(t, status.IsCompliant)
	assert.Equal(t, 1, status.MarketAssessmentCount)
	assert.Equal(t, 0, status.ExcludedMarketCount)
	assert.Equal(t, 0, status.UnregisteredAgentCount)
}

func TestCFTCEngine_ComplianceStatus_NonCompliant_ExcludedMarket(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	engine.AssessMarket(ctx, &PredictionMarketAssessment{
		MarketID:       "mkt-001",
		Classification: ClassExcluded,
	})

	status := engine.GetComplianceStatus(ctx)
	assert.False(t, status.IsCompliant)
	assert.Equal(t, 1, status.ExcludedMarketCount)
}

func TestCFTCEngine_ComplianceStatus_NonCompliant_UnregisteredAgent(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	engine.RegisterAgent(ctx, &AIAgentRegistration{
		AgentID:      "agent-001",
		DirectAccess: true,
		// Status will be set to RegistrationRequired
	})

	status := engine.GetComplianceStatus(ctx)
	assert.False(t, status.IsCompliant)
	assert.Equal(t, 1, status.UnregisteredAgentCount)
}

func TestCFTCEngine_ComplianceStatus_NonCompliant_MissingRiskControls(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	engine.RegisterAgent(ctx, &AIAgentRegistration{
		AgentID:      "agent-001",
		DirectAccess: true,
		Status:       RegistrationActive,
		RiskControls: []string{}, // No controls!
	})

	status := engine.GetComplianceStatus(ctx)
	assert.False(t, status.IsCompliant)
	assert.Equal(t, 1, status.MissingRiskControlCount)
}

func TestCFTCEngine_ValidateAgentRiskControls_AllPresent(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	// Add required controls
	for _, rc := range []struct {
		id string
		t  RiskControlType
	}{
		{"ctrl-1", RiskControlPreTrade},
		{"ctrl-2", RiskControlKillSwitch},
		{"ctrl-3", RiskControlMaxOrderSize},
	} {
		engine.AddRiskControl(ctx, &AlgoTradingRiskControl{
			ControlID: rc.id,
			AgentID:   "agent-001",
			Type:      rc.t,
		})
	}

	engine.RegisterAgent(ctx, &AIAgentRegistration{
		AgentID:      "agent-001",
		DirectAccess: true,
		Status:       RegistrationActive,
		RiskControls: []string{"ctrl-1", "ctrl-2", "ctrl-3"},
	})

	valid, missing := engine.ValidateAgentRiskControls(ctx, "agent-001")
	assert.True(t, valid)
	assert.Empty(t, missing)
}

func TestCFTCEngine_ValidateAgentRiskControls_Missing(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	engine.AddRiskControl(ctx, &AlgoTradingRiskControl{
		ControlID: "ctrl-1",
		AgentID:   "agent-001",
		Type:      RiskControlPreTrade,
	})

	engine.RegisterAgent(ctx, &AIAgentRegistration{
		AgentID:      "agent-001",
		DirectAccess: true,
		Status:       RegistrationActive,
		RiskControls: []string{"ctrl-1"}, // Only pre-trade, missing kill switch and max order
	})

	valid, missing := engine.ValidateAgentRiskControls(ctx, "agent-001")
	assert.False(t, valid)
	assert.Contains(t, missing, RiskControlKillSwitch)
	assert.Contains(t, missing, RiskControlMaxOrderSize)
}

func TestCFTCEngine_ValidateAgentRiskControls_NonDirectAccess(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	engine.RegisterAgent(ctx, &AIAgentRegistration{
		AgentID:      "agent-001",
		DirectAccess: false, // Not direct access
		Status:       RegistrationExempt,
	})

	valid, missing := engine.ValidateAgentRiskControls(ctx, "agent-001")
	assert.True(t, valid, "non-direct-access agents have relaxed requirements")
	assert.Empty(t, missing)
}

func TestCFTCEngine_ValidateAgentRiskControls_NotFound(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	valid, _ := engine.ValidateAgentRiskControls(ctx, "nonexistent")
	assert.False(t, valid)
}

func TestCFTCEngine_GenerateAuditReport(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	now := time.Now()

	engine.AssessMarket(ctx, &PredictionMarketAssessment{
		MarketID:       "mkt-001",
		Classification: ClassEventContract,
	})
	engine.RegisterAgent(ctx, &AIAgentRegistration{
		AgentID: "agent-001",
		Status:  RegistrationActive,
	})
	engine.AddRiskControl(ctx, &AlgoTradingRiskControl{
		ControlID: "ctrl-001",
		Type:      RiskControlKillSwitch,
	})
	engine.SubmitITFReport(ctx, &InnovationTaskForceReport{
		ReportID: "itf-001",
		Topic:    "test",
	})

	report, err := engine.GenerateAuditReport(ctx, now.Add(-1*time.Hour), now.Add(1*time.Hour))
	require.NoError(t, err)

	assert.Equal(t, "TestEntity", report.Entity)
	assert.Len(t, report.MarketAssessments, 1)
	assert.Len(t, report.AgentRegistrations, 1)
	assert.Len(t, report.RiskControls, 1)
	assert.Len(t, report.ITFReports, 1)
	assert.NotEmpty(t, report.Hash)
}

func TestCFTCEngine_GenerateAuditReport_FiltersByPeriod(t *testing.T) {
	engine := NewCFTCComplianceEngine("TestEntity")
	ctx := context.Background()

	now := time.Now()

	engine.AssessMarket(ctx, &PredictionMarketAssessment{
		MarketID:       "mkt-001",
		Classification: ClassEventContract,
	})

	// Query past period
	report, err := engine.GenerateAuditReport(ctx, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	require.NoError(t, err)
	assert.Empty(t, report.MarketAssessments)
}
