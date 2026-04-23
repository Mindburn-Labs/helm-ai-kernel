// Package fca implements UK FCA (Financial Conduct Authority) compliance profile.
package fca

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ── FCA Types ─────────────────────────────────────────────────

// ConsumerDutyOutcome represents the FCA Consumer Duty outcomes (PS22/9).
type ConsumerDutyOutcome string

const (
	OutcomeProducts      ConsumerDutyOutcome = "PRODUCTS_SERVICES"
	OutcomePrice         ConsumerDutyOutcome = "PRICE_VALUE"
	OutcomeUnderstanding ConsumerDutyOutcome = "CONSUMER_UNDERSTANDING"
	OutcomeSupport       ConsumerDutyOutcome = "CONSUMER_SUPPORT"
)

// ConductRule represents an individual FCA conduct rule (COCON).
type ConductRule struct {
	ID          string `json:"id"`
	RuleRef     string `json:"rule_ref"` // e.g., "COCON 2.1.1"
	Description string `json:"description"`
	Tier        string `json:"tier"` // "1" (all staff) or "2" (senior managers)
	Active      bool   `json:"active"`
}

// SMCRRole represents a Senior Managers & Certification Regime role.
type SMCRRole struct {
	ID              string    `json:"id"`
	FunctionCode    string    `json:"function_code"` // SMF1, SMF24, etc.
	Title           string    `json:"title"`
	HolderName      string    `json:"holder_name"`
	ApprovedDate    time.Time `json:"approved_date"`
	LastAttested    time.Time `json:"last_attested"`
	StatementOfResp string    `json:"statement_of_responsibilities"`
}

// SystemControl represents a SYSC (Systems and Controls) requirement.
type SystemControl struct {
	ID           string    `json:"id"`
	SYSCRef      string    `json:"sysc_ref"` // e.g., "SYSC 6.1.1"
	Category     string    `json:"category"` // governance, risk, compliance, operational
	Description  string    `json:"description"`
	Status       string    `json:"status"` // COMPLIANT, NON_COMPLIANT, PARTIALLY_COMPLIANT
	EvidenceRefs []string  `json:"evidence_refs,omitempty"`
	LastReviewed time.Time `json:"last_reviewed"`
}

// ── FCA Engine ────────────────────────────────────────────────

// FCAEngine manages FCA compliance requirements.
type FCAEngine struct {
	mu              sync.RWMutex
	conductRules    []ConductRule
	smcrRoles       map[string]*SMCRRole
	systemControls  map[string]*SystemControl
	dutyAssessments map[ConsumerDutyOutcome]string // outcome → status
}

// NewFCAEngine creates a new FCA compliance engine with default conduct rules.
func NewFCAEngine() *FCAEngine {
	return &FCAEngine{
		conductRules:    defaultConductRules(),
		smcrRoles:       make(map[string]*SMCRRole),
		systemControls:  make(map[string]*SystemControl),
		dutyAssessments: make(map[ConsumerDutyOutcome]string),
	}
}

func defaultConductRules() []ConductRule {
	return []ConductRule{
		{ID: "cr-1", RuleRef: "COCON 2.1.1", Description: "Act with integrity", Tier: "1", Active: true},
		{ID: "cr-2", RuleRef: "COCON 2.1.2", Description: "Act with due skill, care and diligence", Tier: "1", Active: true},
		{ID: "cr-3", RuleRef: "COCON 2.1.3", Description: "Be open and cooperative with regulators", Tier: "1", Active: true},
		{ID: "cr-4", RuleRef: "COCON 2.1.4", Description: "Pay due regard to interests of customers", Tier: "1", Active: true},
		{ID: "cr-5", RuleRef: "COCON 2.1.5", Description: "Observe proper standards of market conduct", Tier: "1", Active: true},
		{ID: "cr-6", RuleRef: "COCON 2.2.1", Description: "Take reasonable steps to ensure effective control", Tier: "2", Active: true},
		{ID: "cr-7", RuleRef: "COCON 2.2.2", Description: "Take reasonable steps to ensure compliance", Tier: "2", Active: true},
		{ID: "cr-8", RuleRef: "COCON 2.2.3", Description: "Disclose information the FCA would expect", Tier: "2", Active: true},
	}
}

// RegisterSMCRRole registers a senior manager role under SM&CR.
func (e *FCAEngine) RegisterSMCRRole(_ context.Context, role *SMCRRole) error {
	if role.FunctionCode == "" {
		return fmt.Errorf("function code is required")
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.smcrRoles[role.ID] = role
	return nil
}

// RegisterSystemControl registers a SYSC requirement.
func (e *FCAEngine) RegisterSystemControl(_ context.Context, ctrl *SystemControl) error {
	if ctrl.SYSCRef == "" {
		return fmt.Errorf("SYSC reference is required")
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.systemControls[ctrl.ID] = ctrl
	return nil
}

// AssessConsumerDuty records a Consumer Duty outcome assessment.
func (e *FCAEngine) AssessConsumerDuty(outcome ConsumerDutyOutcome, status string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dutyAssessments[outcome] = status
}

// GetStatus returns FCA compliance summary.
func (e *FCAEngine) GetStatus() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	nonCompliant := 0
	for _, c := range e.systemControls {
		if c.Status == "NON_COMPLIANT" {
			nonCompliant++
		}
	}

	return map[string]interface{}{
		"conduct_rules":             len(e.conductRules),
		"smcr_roles":                len(e.smcrRoles),
		"system_controls":           len(e.systemControls),
		"non_compliant":             nonCompliant,
		"consumer_duty_assessments": len(e.dutyAssessments),
	}
}
