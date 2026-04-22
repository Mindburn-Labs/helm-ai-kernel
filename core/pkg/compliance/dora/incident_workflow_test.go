package dora

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewIncidentWorkflow(t *testing.T) {
	workflow := NewIncidentWorkflow("incident-123", RiskLevelHigh)

	require.Equal(t, "incident-123", workflow.IncidentID)
	require.Equal(t, WorkflowStatusDraft, workflow.Status)
	require.Equal(t, 9, len(workflow.Steps))
	require.Equal(t, 0, workflow.CurrentStep)
	require.NotNil(t, workflow.ReportDeadline)
}

func TestCriticalIncidentWorkflow(t *testing.T) {
	workflow := NewIncidentWorkflow("critical-123", RiskLevelCritical)

	require.Contains(t, workflow.NCAs, "lead_overseer")
	require.Contains(t, workflow.NCAs, "home_member_state")
}

func TestAdvanceWorkflow(t *testing.T) {
	workflow := NewIncidentWorkflow("incident-123", RiskLevelHigh)

	// Advance through first few steps
	err := workflow.AdvanceWorkflow("analyst1", "Triage complete")
	require.NoError(t, err)
	require.Equal(t, 1, workflow.CurrentStep)
	require.Equal(t, WorkflowStatusTriaged, workflow.Status)
	require.Equal(t, "completed", workflow.Steps[0].Status)

	// Advance again
	err = workflow.AdvanceWorkflow("analyst1", "Containment in place")
	require.NoError(t, err)
	require.Equal(t, 2, workflow.CurrentStep)
}

func TestWorkflowComplete(t *testing.T) {
	workflow := NewIncidentWorkflow("incident-123", RiskLevelLow)

	// Advance through all steps
	for i := 0; i < len(workflow.Steps)-1; i++ {
		err := workflow.AdvanceWorkflow("analyst", "Step completed")
		require.NoError(t, err)
	}

	require.False(t, workflow.IsComplete())

	// Mark final step complete
	workflow.Steps[workflow.CurrentStep].Status = "completed"
	require.True(t, workflow.IsComplete())
}

func TestDeadlineViolations(t *testing.T) {
	workflow := NewIncidentWorkflow("incident-123", RiskLevelHigh)

	// Simulate past deadline
	pastDeadline := time.Now().Add(-25 * time.Hour)
	workflow.ReportDeadline = &pastDeadline
	workflow.CreatedAt = time.Now().Add(-73 * time.Hour)

	violations := workflow.CheckDeadlines()
	require.Len(t, violations, 2)
	require.Contains(t, violations[0], "24h")
	require.Contains(t, violations[1], "72h")
}

func TestStartWorkflow(t *testing.T) {
	entity := EntityInfo{LEI: "TEST123", Name: "Test Entity"}
	engine := NewDORAComplianceEngine(entity)

	incident := &ICTIncident{
		ID:       "incident-1",
		Type:     IncidentCyberAttack,
		Severity: RiskLevelCritical,
	}
	err := engine.ReportIncident(context.Background(), incident)
	require.NoError(t, err)

	workflow, err := engine.StartWorkflow(context.Background(), "incident-1")
	require.NoError(t, err)
	require.NotNil(t, workflow)
	require.Equal(t, "incident-1", workflow.IncidentID)
}

func TestStartWorkflowNotFound(t *testing.T) {
	entity := EntityInfo{LEI: "TEST123", Name: "Test Entity"}
	engine := NewDORAComplianceEngine(entity)

	_, err := engine.StartWorkflow(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestGenerateNCANotification(t *testing.T) {
	entity := EntityInfo{
		LEI:  "TEST123",
		Name: "Test Financial Entity",
	}
	engine := NewDORAComplianceEngine(entity)

	incident := &ICTIncident{
		ID:               "incident-1",
		Type:             IncidentCyberAttack,
		Severity:         RiskLevelCritical,
		Description:      "Ransomware detected",
		AffectedServices: []string{"payment-gateway", "auth-service"},
		AffectedClients:  1500,
	}
	err := engine.ReportIncident(context.Background(), incident)
	require.NoError(t, err)

	notification, err := engine.GenerateNCANotification(context.Background(), "incident-1")
	require.NoError(t, err)
	require.Equal(t, "initial", notification["notification_type"])
	require.Equal(t, IncidentCyberAttack, notification["incident_type"])
	require.Equal(t, RiskLevelCritical, notification["severity"])
	require.Equal(t, 1500, notification["affected_clients"])
}

func TestGetPendingSteps(t *testing.T) {
	workflow := NewIncidentWorkflow("incident-123", RiskLevelHigh)

	pending := workflow.GetPendingSteps()
	require.Len(t, pending, 8) // All except first which is completed

	// Advance a couple steps
	_ = workflow.AdvanceWorkflow("analyst", "Done")
	_ = workflow.AdvanceWorkflow("analyst", "Done")

	pending = workflow.GetPendingSteps()
	require.Len(t, pending, 6)
}
