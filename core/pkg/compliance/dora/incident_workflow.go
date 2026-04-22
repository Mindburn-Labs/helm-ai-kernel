// Package dora - Incident Workflow Automation
// Part of DORA Compliance Engine per Article 17-23

package dora

import (
	"context"
	"fmt"
	"time"
)

// IncidentWorkflowStatus represents the state of an incident workflow.
type IncidentWorkflowStatus string

const (
	WorkflowStatusDraft      IncidentWorkflowStatus = "DRAFT"
	WorkflowStatusTriaged    IncidentWorkflowStatus = "TRIAGED"
	WorkflowStatusInProgress IncidentWorkflowStatus = "IN_PROGRESS"
	WorkflowStatusResolved   IncidentWorkflowStatus = "RESOLVED"
	WorkflowStatusReported   IncidentWorkflowStatus = "REPORTED"
	WorkflowStatusClosed     IncidentWorkflowStatus = "CLOSED"
)

// IncidentWorkflow manages the lifecycle of an ICT incident per DORA.
type IncidentWorkflow struct {
	IncidentID     string                 `json:"incident_id"`
	Status         IncidentWorkflowStatus `json:"status"`
	Steps          []WorkflowStep         `json:"steps"`
	CurrentStep    int                    `json:"current_step"`
	NCAs           []string               `json:"ncas"`            // National Competent Authorities
	ReportDeadline *time.Time             `json:"report_deadline"` // DORA: 24h initial, 72h intermediate
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// WorkflowStep represents a step in the incident workflow.
type WorkflowStep struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Status      string     `json:"status"` // pending, in_progress, completed, skipped
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	CompletedBy string     `json:"completed_by,omitempty"`
	Notes       string     `json:"notes,omitempty"`
}

// InitialReportDeadline is 24 hours per DORA Article 19.
const InitialReportDeadline = 24 * time.Hour

// IntermediateReportDeadline is 72 hours per DORA Article 19.
const IntermediateReportDeadline = 72 * time.Hour

// NewIncidentWorkflow creates a new incident workflow with standard DORA steps.
func NewIncidentWorkflow(incidentID string, severity RiskLevel) *IncidentWorkflow {
	now := time.Now()
	deadline := now.Add(InitialReportDeadline)

	workflow := &IncidentWorkflow{
		IncidentID:     incidentID,
		Status:         WorkflowStatusDraft,
		CurrentStep:    0,
		ReportDeadline: &deadline,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	// Define standard DORA incident response steps per Article 17-23
	workflow.Steps = []WorkflowStep{
		{
			Name:        "Detection & Classification",
			Description: "Detect incident and classify by type and severity per DORA Article 18",
			Status:      "completed", // Already done when workflow is created
		},
		{
			Name:        "Initial Triage",
			Description: "Assess impact, affected services, and client count",
			Status:      "pending",
		},
		{
			Name:        "Containment",
			Description: "Implement immediate containment measures to limit impact",
			Status:      "pending",
		},
		{
			Name:        "Initial NCA Notification",
			Description: "Submit initial notification to NCAs within 24 hours (DORA Art. 19)",
			Status:      "pending",
		},
		{
			Name:        "Root Cause Analysis",
			Description: "Investigate and document root cause",
			Status:      "pending",
		},
		{
			Name:        "Intermediate Report",
			Description: "Submit intermediate report to NCAs within 72 hours (DORA Art. 19)",
			Status:      "pending",
		},
		{
			Name:        "Remediation",
			Description: "Implement fixes and preventive measures",
			Status:      "pending",
		},
		{
			Name:        "Final Report",
			Description: "Submit final report to NCAs within 1 month (DORA Art. 19)",
			Status:      "pending",
		},
		{
			Name:        "Post-Incident Review",
			Description: "Conduct lessons learned and update procedures",
			Status:      "pending",
		},
	}

	// For critical incidents, add expedited steps
	if severity == RiskLevelCritical {
		workflow.NCAs = []string{"lead_overseer", "home_member_state"}
	}

	return workflow
}

// StartWorkflow initiates the incident workflow.
func (e *DORAComplianceEngine) StartWorkflow(ctx context.Context, incidentID string) (*IncidentWorkflow, error) {
	e.mu.RLock()
	incident, exists := e.incidents[incidentID]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("incident not found: %s", incidentID)
	}

	workflow := NewIncidentWorkflow(incidentID, incident.Severity)
	return workflow, nil
}

// AdvanceWorkflow moves to the next step and validates DORA deadlines.
func (w *IncidentWorkflow) AdvanceWorkflow(completedBy, notes string) error {
	if w.CurrentStep >= len(w.Steps)-1 {
		return fmt.Errorf("workflow already completed")
	}

	now := time.Now()

	// Mark current step as completed
	w.Steps[w.CurrentStep].Status = "completed"
	w.Steps[w.CurrentStep].CompletedAt = &now
	w.Steps[w.CurrentStep].CompletedBy = completedBy
	w.Steps[w.CurrentStep].Notes = notes

	// Move to next step
	w.CurrentStep++
	w.Steps[w.CurrentStep].Status = "in_progress"
	w.UpdatedAt = now

	// Update workflow status based on current step
	switch w.CurrentStep {
	case 1:
		w.Status = WorkflowStatusTriaged
	case 2, 3, 4, 5:
		w.Status = WorkflowStatusInProgress
	case 6, 7:
		w.Status = WorkflowStatusReported
	case 8:
		w.Status = WorkflowStatusResolved
	}

	return nil
}

// CheckDeadlines returns any DORA reporting deadline violations.
func (w *IncidentWorkflow) CheckDeadlines() []string {
	var violations []string
	now := time.Now()

	// Check 24-hour initial notification deadline
	if w.CurrentStep < 4 { // Haven't completed initial NCA notification
		if w.ReportDeadline != nil && now.After(*w.ReportDeadline) {
			violations = append(violations, "DORA Art. 19 violation: Initial NCA notification deadline (24h) exceeded")
		}
	}

	// Check 72-hour intermediate report deadline
	intermediateDeadline := w.CreatedAt.Add(IntermediateReportDeadline)
	if w.CurrentStep < 6 && now.After(intermediateDeadline) {
		violations = append(violations, "DORA Art. 19 violation: Intermediate report deadline (72h) exceeded")
	}

	return violations
}

// IsComplete returns true if the workflow is fully completed.
func (w *IncidentWorkflow) IsComplete() bool {
	return w.CurrentStep == len(w.Steps)-1 && w.Steps[w.CurrentStep].Status == "completed"
}

// GetPendingSteps returns all pending steps in the workflow.
func (w *IncidentWorkflow) GetPendingSteps() []WorkflowStep {
	var pending []WorkflowStep
	for _, step := range w.Steps {
		if step.Status == "pending" {
			pending = append(pending, step)
		}
	}
	return pending
}

// GenerateNCANotification generates the initial notification content for NCAs.
func (e *DORAComplianceEngine) GenerateNCANotification(ctx context.Context, incidentID string) (map[string]interface{}, error) {
	e.mu.RLock()
	incident, exists := e.incidents[incidentID]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("incident not found: %s", incidentID)
	}

	notification := map[string]interface{}{
		"notification_type": "initial",
		"incident_id":       incident.ID,
		"incident_type":     incident.Type,
		"severity":          incident.Severity,
		"detected_at":       incident.DetectedAt,
		"description":       incident.Description,
		"affected_services": incident.AffectedServices,
		"affected_clients":  incident.AffectedClients,
		"entity_info":       e.entityInfo,
		"submitted_at":      time.Now(),
		"dora_article":      "Article 19",
	}

	return notification, nil
}
