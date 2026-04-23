// Package cftc implements CFTC compliance for AI agent governance.
//
// CFTC Requirements Addressed:
//   - CEA Section 5c(c)(5)(C): Event contract (prediction market) classification
//   - Proposed Regulation AT: Algorithmic trading risk controls
//   - CFTC Innovation Task Force: AI trading agent engagement requirements
//   - TAC AI Recommendations: Model governance, explainability, drift monitoring
//   - Part 23: Swap dealer business conduct standards for AI execution
//   - DCM Core Principles: System safeguards for algorithmic infrastructure
//
// Integrates with HELM receipt chain for proof of compliance.
package cftc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// PredictionMarketClass classifies a prediction market instrument for CFTC purposes.
type PredictionMarketClass string

const (
	ClassEventContract PredictionMarketClass = "EVENT_CONTRACT" // CEA 5c(c)(5)(C)
	ClassBinaryOption  PredictionMarketClass = "BINARY_OPTION"  // Regulated as swap
	ClassSwap          PredictionMarketClass = "SWAP"           // Full swap regulation
	ClassExcluded      PredictionMarketClass = "EXCLUDED"       // Gaming, terrorism, etc.
	ClassExempt        PredictionMarketClass = "EXEMPT"         // Exempt from regulation
)

// ExclusionReason documents why an event contract is excluded under CEA.
type ExclusionReason string

const (
	ExclusionGaming        ExclusionReason = "GAMING" // Activity, war, terrorism per CEA
	ExclusionTerrorism     ExclusionReason = "TERRORISM"
	ExclusionAssassination ExclusionReason = "ASSASSINATION"
	ExclusionOther         ExclusionReason = "OTHER_UNLAWFUL"
)

// RiskControlType classifies algorithmic trading risk controls (Reg AT).
type RiskControlType string

const (
	RiskControlPreTrade        RiskControlType = "PRE_TRADE"        // Pre-trade risk limits
	RiskControlMessageThrottle RiskControlType = "MESSAGE_THROTTLE" // Order message rate limits
	RiskControlKillSwitch      RiskControlType = "KILL_SWITCH"      // Emergency halt capability
	RiskControlMaxOrderSize    RiskControlType = "MAX_ORDER_SIZE"   // Maximum order size
	RiskControlPriceCollar     RiskControlType = "PRICE_COLLAR"     // Price deviation limits
	RiskControlDailyLoss       RiskControlType = "DAILY_LOSS"       // Daily loss limits
)

// AgentRegistrationStatus tracks whether an AI agent is registered as an AT Person.
type AgentRegistrationStatus string

const (
	RegistrationRequired  AgentRegistrationStatus = "REQUIRED"
	RegistrationExempt    AgentRegistrationStatus = "EXEMPT"
	RegistrationPending   AgentRegistrationStatus = "PENDING"
	RegistrationActive    AgentRegistrationStatus = "ACTIVE"
	RegistrationSuspended AgentRegistrationStatus = "SUSPENDED"
)

// PredictionMarketAssessment is the result of classifying a prediction market
// for CFTC regulatory purposes.
type PredictionMarketAssessment struct {
	MarketID         string                `json:"market_id"`
	MarketName       string                `json:"market_name"`
	Classification   PredictionMarketClass `json:"classification"`
	ExclusionReason  ExclusionReason       `json:"exclusion_reason,omitempty"`
	DCMID            string                `json:"dcm_id,omitempty"` // Designated Contract Market
	IsDCMRegistered  bool                  `json:"is_dcm_registered"`
	RequiresSEF      bool                  `json:"requires_sef"`      // Swap Execution Facility
	SwapReporting    bool                  `json:"swap_reporting"`    // Real-time reporting required
	RiskLevel        string                `json:"risk_level"`        // HIGH, MEDIUM, LOW
	HELMRequirements []string              `json:"helm_requirements"` // HELM controls needed
	AssessedAt       time.Time             `json:"assessed_at"`
	AssessedBy       string                `json:"assessed_by"`
	Notes            string                `json:"notes,omitempty"`
}

// AlgoTradingRiskControl documents a risk control for algorithmic trading.
type AlgoTradingRiskControl struct {
	ControlID     string          `json:"control_id"`
	AgentID       string          `json:"agent_id"`
	Type          RiskControlType `json:"type"`
	Description   string          `json:"description"`
	ThresholdVal  string          `json:"threshold_value"` // String to support various units
	Enabled       bool            `json:"enabled"`
	LastTriggered *time.Time      `json:"last_triggered,omitempty"`
	TriggerCount  int64           `json:"trigger_count"`
	CreatedAt     time.Time       `json:"created_at"`
}

// AIAgentRegistration tracks the CFTC registration status of an AI trading agent.
type AIAgentRegistration struct {
	AgentID        string                  `json:"agent_id"`
	EntityName     string                  `json:"entity_name"`
	Status         AgentRegistrationStatus `json:"registration_status"`
	RegistrationID string                  `json:"registration_id,omitempty"`
	DirectAccess   bool                    `json:"direct_electronic_access"` // Triggers AT Person requirement
	MarketTypes    []string                `json:"market_types"`
	RiskControls   []string                `json:"risk_control_ids"` // References to AlgoTradingRiskControl
	AuditTrailHash string                  `json:"audit_trail_hash,omitempty"`
	LastAuditDate  *time.Time              `json:"last_audit_date,omitempty"`
	RegisteredAt   *time.Time              `json:"registered_at,omitempty"`
}

// InnovationTaskForceReport documents engagement with the CFTC Innovation Task Force.
type InnovationTaskForceReport struct {
	ReportID     string     `json:"report_id"`
	EntityName   string     `json:"entity_name"`
	Program      string     `json:"program"` // "LabCFTC", "Sandbox", "General"
	Topic        string     `json:"topic"`
	Description  string     `json:"description"`
	SubmittedAt  time.Time  `json:"submitted_at"`
	ResponseDate *time.Time `json:"response_date,omitempty"`
	Status       string     `json:"status"` // "submitted", "under_review", "responded", "closed"
}

// ComplianceStatus represents the current CFTC compliance status.
type ComplianceStatus struct {
	AsOf                    time.Time `json:"as_of"`
	IsCompliant             bool      `json:"is_compliant"`
	MarketAssessmentCount   int       `json:"market_assessment_count"`
	ExcludedMarketCount     int       `json:"excluded_market_count"`
	UnregisteredAgentCount  int       `json:"unregistered_agent_count"`
	MissingRiskControlCount int       `json:"missing_risk_control_count"`
	PendingITFReports       int       `json:"pending_itf_reports"`
}

// AuditReport is a CFTC audit report for a given period.
type AuditReport struct {
	Entity             string                       `json:"entity"`
	PeriodStart        time.Time                    `json:"period_start"`
	PeriodEnd          time.Time                    `json:"period_end"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	MarketAssessments  []PredictionMarketAssessment `json:"market_assessments"`
	AgentRegistrations []AIAgentRegistration        `json:"agent_registrations"`
	RiskControls       []AlgoTradingRiskControl     `json:"risk_controls"`
	ITFReports         []InnovationTaskForceReport  `json:"itf_reports"`
	Hash               string                       `json:"hash"`
}

// CFTCComplianceEngine manages CFTC compliance for HELM.
type CFTCComplianceEngine struct {
	mu           sync.RWMutex
	entityName   string
	markets      map[string]*PredictionMarketAssessment
	agents       map[string]*AIAgentRegistration
	riskControls map[string]*AlgoTradingRiskControl
	itfReports   map[string]*InnovationTaskForceReport
}

// NewCFTCComplianceEngine creates a new CFTC compliance engine.
func NewCFTCComplianceEngine(entityName string) *CFTCComplianceEngine {
	return &CFTCComplianceEngine{
		entityName:   entityName,
		markets:      make(map[string]*PredictionMarketAssessment),
		agents:       make(map[string]*AIAgentRegistration),
		riskControls: make(map[string]*AlgoTradingRiskControl),
		itfReports:   make(map[string]*InnovationTaskForceReport),
	}
}

// AssessMarket classifies a prediction market for CFTC regulatory purposes.
func (e *CFTCComplianceEngine) AssessMarket(_ context.Context, assessment *PredictionMarketAssessment) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if assessment == nil {
		return fmt.Errorf("cftc: assessment is nil")
	}
	if assessment.MarketID == "" {
		return fmt.Errorf("cftc: market_id is required")
	}

	if assessment.AssessedAt.IsZero() {
		assessment.AssessedAt = time.Now()
	}

	// Determine HELM requirements based on classification
	assessment.HELMRequirements = e.deriveHELMRequirements(assessment)

	e.markets[assessment.MarketID] = assessment
	return nil
}

// deriveHELMRequirements computes which HELM controls are needed for a market classification.
func (e *CFTCComplianceEngine) deriveHELMRequirements(a *PredictionMarketAssessment) []string {
	var reqs []string

	switch a.Classification {
	case ClassEventContract:
		reqs = append(reqs, "guardian_policy_enforcement", "receipt_chain_audit")
		if a.IsDCMRegistered {
			reqs = append(reqs, "dcm_core_principle_compliance", "system_safeguards")
		}
	case ClassBinaryOption, ClassSwap:
		reqs = append(reqs,
			"guardian_policy_enforcement",
			"receipt_chain_audit",
			"swap_reporting_sdrs",
			"counterparty_verification",
			"pre_trade_risk_controls",
		)
		if a.RequiresSEF {
			reqs = append(reqs, "sef_execution_method")
		}
	case ClassExcluded:
		reqs = append(reqs, "market_participation_blocked", "compliance_alert_immediate")
	case ClassExempt:
		reqs = append(reqs, "receipt_chain_audit")
	}

	return reqs
}

// GetMarketAssessment retrieves a market assessment.
func (e *CFTCComplianceEngine) GetMarketAssessment(_ context.Context, marketID string) (*PredictionMarketAssessment, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	a, ok := e.markets[marketID]
	if !ok {
		return nil, fmt.Errorf("cftc: market %s not found", marketID)
	}
	return a, nil
}

// RegisterAgent registers an AI trading agent for CFTC compliance tracking.
func (e *CFTCComplianceEngine) RegisterAgent(_ context.Context, reg *AIAgentRegistration) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if reg == nil {
		return fmt.Errorf("cftc: registration is nil")
	}
	if reg.AgentID == "" {
		return fmt.Errorf("cftc: agent_id is required")
	}

	// Determine registration requirement
	if reg.DirectAccess && reg.Status == "" {
		reg.Status = RegistrationRequired
	}

	e.agents[reg.AgentID] = reg
	return nil
}

// AddRiskControl adds an algorithmic trading risk control.
func (e *CFTCComplianceEngine) AddRiskControl(_ context.Context, control *AlgoTradingRiskControl) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if control == nil {
		return fmt.Errorf("cftc: control is nil")
	}
	if control.ControlID == "" {
		return fmt.Errorf("cftc: control_id is required")
	}

	if control.CreatedAt.IsZero() {
		control.CreatedAt = time.Now()
	}

	e.riskControls[control.ControlID] = control
	return nil
}

// RecordKillSwitchTrigger records a kill switch activation for audit trail.
func (e *CFTCComplianceEngine) RecordKillSwitchTrigger(_ context.Context, controlID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	control, ok := e.riskControls[controlID]
	if !ok {
		return fmt.Errorf("cftc: control %s not found", controlID)
	}

	now := time.Now()
	control.LastTriggered = &now
	control.TriggerCount++
	return nil
}

// SubmitITFReport submits a report to the Innovation Task Force tracker.
func (e *CFTCComplianceEngine) SubmitITFReport(_ context.Context, report *InnovationTaskForceReport) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if report == nil {
		return fmt.Errorf("cftc: report is nil")
	}
	if report.ReportID == "" {
		return fmt.Errorf("cftc: report_id is required")
	}

	if report.SubmittedAt.IsZero() {
		report.SubmittedAt = time.Now()
	}
	if report.Status == "" {
		report.Status = "submitted"
	}

	e.itfReports[report.ReportID] = report
	return nil
}

// GetComplianceStatus returns current CFTC compliance status.
func (e *CFTCComplianceEngine) GetComplianceStatus(_ context.Context) *ComplianceStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	status := &ComplianceStatus{
		AsOf:                  time.Now(),
		MarketAssessmentCount: len(e.markets),
	}

	// Count excluded markets
	for _, m := range e.markets {
		if m.Classification == ClassExcluded {
			status.ExcludedMarketCount++
		}
	}

	// Count unregistered agents that need registration
	for _, a := range e.agents {
		if a.Status == RegistrationRequired {
			status.UnregisteredAgentCount++
		}
	}

	// Check each agent has required risk controls
	for _, a := range e.agents {
		if a.DirectAccess && len(a.RiskControls) == 0 {
			status.MissingRiskControlCount++
		}
	}

	// Count pending ITF reports
	for _, r := range e.itfReports {
		if r.Status == "submitted" || r.Status == "under_review" {
			status.PendingITFReports++
		}
	}

	// Compliant if: no excluded markets being traded, all agents registered, all have risk controls
	status.IsCompliant = status.ExcludedMarketCount == 0 &&
		status.UnregisteredAgentCount == 0 &&
		status.MissingRiskControlCount == 0

	return status
}

// GenerateAuditReport generates a CFTC audit report for a period.
func (e *CFTCComplianceEngine) GenerateAuditReport(_ context.Context, periodStart, periodEnd time.Time) (*AuditReport, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	report := &AuditReport{
		Entity:      e.entityName,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		GeneratedAt: time.Now(),
	}

	for _, m := range e.markets {
		if m.AssessedAt.After(periodStart) && m.AssessedAt.Before(periodEnd) {
			report.MarketAssessments = append(report.MarketAssessments, *m)
		}
	}
	for _, a := range e.agents {
		report.AgentRegistrations = append(report.AgentRegistrations, *a)
	}
	for _, c := range e.riskControls {
		if c.CreatedAt.After(periodStart) && c.CreatedAt.Before(periodEnd) {
			report.RiskControls = append(report.RiskControls, *c)
		}
	}
	for _, r := range e.itfReports {
		if r.SubmittedAt.After(periodStart) && r.SubmittedAt.Before(periodEnd) {
			report.ITFReports = append(report.ITFReports, *r)
		}
	}

	content, _ := json.Marshal(report)
	hash := sha256.Sum256(content)
	report.Hash = hex.EncodeToString(hash[:])

	return report, nil
}

// IsMarketExcluded checks whether a market is classified as excluded (blocked).
func (e *CFTCComplianceEngine) IsMarketExcluded(_ context.Context, marketID string) (bool, ExclusionReason) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	m, ok := e.markets[marketID]
	if !ok {
		return false, ""
	}
	return m.Classification == ClassExcluded, m.ExclusionReason
}

// ValidateAgentRiskControls checks if an agent has all required risk controls
// under proposed Regulation AT.
func (e *CFTCComplianceEngine) ValidateAgentRiskControls(_ context.Context, agentID string) (bool, []RiskControlType) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	agent, ok := e.agents[agentID]
	if !ok {
		return false, nil
	}

	// Minimum required controls for direct-access algo traders
	requiredTypes := []RiskControlType{
		RiskControlPreTrade,
		RiskControlKillSwitch,
		RiskControlMaxOrderSize,
	}

	if !agent.DirectAccess {
		return true, nil // Non-direct-access agents have relaxed requirements
	}

	existingTypes := make(map[RiskControlType]bool)
	for _, cid := range agent.RiskControls {
		if control, ok := e.riskControls[cid]; ok {
			existingTypes[control.Type] = true
		}
	}

	var missing []RiskControlType
	for _, rt := range requiredTypes {
		if !existingTypes[rt] {
			missing = append(missing, rt)
		}
	}

	return len(missing) == 0, missing
}
