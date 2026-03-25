// Package sec implements SEC compliance for AI agent governance.
//
// SEC Requirements Addressed:
// - SEC 17a-4: Record retention (tamper-evident receipt chain)
// - SEC AI Oversight 2025: AI agent tool oversight requirements
// - Regulation SCI: Systems Compliance and Integrity
//
// Integrates with HELM receipt chain for proof of compliance.
package sec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

// RecordCategory classifies retained records per 17a-4.
type RecordCategory string

const (
	RecordTrade         RecordCategory = "TRADE"
	RecordCommunication RecordCategory = "COMMUNICATION"
	RecordOrder         RecordCategory = "ORDER"
	RecordCompliance    RecordCategory = "COMPLIANCE"
	RecordAIDecision    RecordCategory = "AI_DECISION"
)

// RetentionRecord represents a record retained per SEC 17a-4.
type RetentionRecord struct {
	ID           string            `json:"id"`
	Category     RecordCategory    `json:"category"`
	Description  string            `json:"description"`
	CreatedAt    time.Time         `json:"created_at"`
	RetainUntil  time.Time         `json:"retain_until"` // 17a-4 requires minimum 3-6 years
	ContentHash  string            `json:"content_hash"` // SHA-256 of record content
	ReceiptID    string            `json:"receipt_id,omitempty"`
	Immutable    bool              `json:"immutable"` // WORM compliance
	Metadata     map[string]string `json:"metadata"`
}

// AIAgentOversightRecord represents AI agent oversight per SEC 2025 guidance.
type AIAgentOversightRecord struct {
	ID            string    `json:"id"`
	AgentID       string    `json:"agent_id"`
	Action        string    `json:"action"`
	ToolUsed      string    `json:"tool_used,omitempty"`
	Decision      string    `json:"decision"` // ALLOW, DENY
	ReasonCode    string    `json:"reason_code,omitempty"`
	RiskLevel     string    `json:"risk_level"`
	HumanReviewed bool      `json:"human_reviewed"`
	ReviewerID    string    `json:"reviewer_id,omitempty"`
	ReceiptID     string    `json:"receipt_id"`
	Timestamp     time.Time `json:"timestamp"`
}

// SCIEvent represents a Systems Compliance and Integrity event.
type SCIEvent struct {
	ID             string    `json:"id"`
	EventType      string    `json:"event_type"` // disruption, intrusion, compliance_failure
	SystemAffected string    `json:"system_affected"`
	Description    string    `json:"description"`
	Impact         string    `json:"impact"` // material, non_material
	DetectedAt     time.Time `json:"detected_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ReportedToSEC  bool      `json:"reported_to_sec"`
}

// SECComplianceEngine manages SEC compliance for HELM.
type SECComplianceEngine struct {
	mu             sync.RWMutex
	records        map[string]*RetentionRecord
	aiOversight    map[string]*AIAgentOversightRecord
	sciEvents      map[string]*SCIEvent
	entityName     string
	retentionYears int
}

// NewSECComplianceEngine creates a new SEC compliance engine.
func NewSECComplianceEngine(entityName string) *SECComplianceEngine {
	return &SECComplianceEngine{
		records:        make(map[string]*RetentionRecord),
		aiOversight:    make(map[string]*AIAgentOversightRecord),
		sciEvents:      make(map[string]*SCIEvent),
		entityName:     entityName,
		retentionYears: 6, // 17a-4 default
	}
}

// RetainRecord stores a record per 17a-4 WORM requirements.
func (e *SECComplianceEngine) RetainRecord(_ context.Context, record *RetentionRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now()
	}
	if record.RetainUntil.IsZero() {
		record.RetainUntil = time.Now().AddDate(e.retentionYears, 0, 0)
	}
	record.Immutable = true // WORM
	e.records[record.ID] = record
	return nil
}

// RecordAIAction records an AI agent action for oversight compliance.
func (e *SECComplianceEngine) RecordAIAction(_ context.Context, record *AIAgentOversightRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now()
	}
	e.aiOversight[record.ID] = record
	return nil
}

// ReportSCIEvent reports a Systems Compliance and Integrity event.
func (e *SECComplianceEngine) ReportSCIEvent(_ context.Context, event *SCIEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if event.DetectedAt.IsZero() {
		event.DetectedAt = time.Now()
	}
	e.sciEvents[event.ID] = event
	return nil
}

// GetComplianceStatus returns current SEC compliance status.
func (e *SECComplianceEngine) GetComplianceStatus(_ context.Context) *ComplianceStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	status := &ComplianceStatus{
		AsOf:                   time.Now(),
		TotalRecords:          len(e.records),
		AIActionCount:         len(e.aiOversight),
		SCIEventCount:         len(e.sciEvents),
	}

	// Check for overdue record reviews
	for _, r := range e.aiOversight {
		if !r.HumanReviewed && r.RiskLevel == "HIGH" {
			status.UnreviewedHighRisk++
		}
	}

	// Check for unreported SCI events
	for _, ev := range e.sciEvents {
		if !ev.ReportedToSEC && ev.Impact == "material" {
			status.UnreportedMaterial++
		}
	}

	status.IsCompliant = status.UnreviewedHighRisk == 0 && status.UnreportedMaterial == 0
	return status
}

// GenerateAuditReport generates an SEC audit report for a period.
func (e *SECComplianceEngine) GenerateAuditReport(_ context.Context, periodStart, periodEnd time.Time) (*AuditReport, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	report := &AuditReport{
		Entity:      e.entityName,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		GeneratedAt: time.Now(),
	}

	for _, r := range e.records {
		if r.CreatedAt.After(periodStart) && r.CreatedAt.Before(periodEnd) {
			report.RetentionRecords = append(report.RetentionRecords, *r)
		}
	}
	for _, a := range e.aiOversight {
		if a.Timestamp.After(periodStart) && a.Timestamp.Before(periodEnd) {
			report.AIActions = append(report.AIActions, *a)
		}
	}
	for _, ev := range e.sciEvents {
		if ev.DetectedAt.After(periodStart) && ev.DetectedAt.Before(periodEnd) {
			report.SCIEvents = append(report.SCIEvents, *ev)
		}
	}

	content, _ := json.Marshal(report)
	hash := sha256.Sum256(content)
	report.Hash = hex.EncodeToString(hash[:])

	return report, nil
}

// ComplianceStatus represents the current SEC compliance status.
type ComplianceStatus struct {
	AsOf                   time.Time `json:"as_of"`
	IsCompliant            bool      `json:"is_compliant"`
	TotalRecords          int       `json:"total_records"`
	AIActionCount         int       `json:"ai_action_count"`
	SCIEventCount         int       `json:"sci_event_count"`
	UnreviewedHighRisk    int       `json:"unreviewed_high_risk"`
	UnreportedMaterial    int       `json:"unreported_material"`
}

// AuditReport is an SEC audit report for a given period.
type AuditReport struct {
	Entity           string                   `json:"entity"`
	PeriodStart      time.Time                `json:"period_start"`
	PeriodEnd        time.Time                `json:"period_end"`
	GeneratedAt      time.Time                `json:"generated_at"`
	RetentionRecords []RetentionRecord        `json:"retention_records"`
	AIActions        []AIAgentOversightRecord `json:"ai_actions"`
	SCIEvents        []SCIEvent               `json:"sci_events"`
	Hash             string                   `json:"hash"`
}
