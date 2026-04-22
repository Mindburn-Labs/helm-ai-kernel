// Package gdpr implements EU GDPR (General Data Protection Regulation) compliance profile.
package gdpr

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ── GDPR Types ────────────────────────────────────────────────

// LawfulBasis represents the legal basis for data processing under GDPR Article 6.
type LawfulBasis string

const (
	BasisConsent            LawfulBasis = "CONSENT"
	BasisContract           LawfulBasis = "CONTRACT"
	BasisLegalObligation    LawfulBasis = "LEGAL_OBLIGATION"
	BasisVitalInterest      LawfulBasis = "VITAL_INTEREST"
	BasisPublicInterest     LawfulBasis = "PUBLIC_INTEREST"
	BasisLegitimateInterest LawfulBasis = "LEGITIMATE_INTEREST"
)

// DataSubjectRight represents GDPR data subject rights (Articles 15-22).
type DataSubjectRight string

const (
	RightAccess      DataSubjectRight = "ACCESS"             // Art 15
	RightRectify     DataSubjectRight = "RECTIFICATION"      // Art 16
	RightErasure     DataSubjectRight = "ERASURE"            // Art 17
	RightRestrict    DataSubjectRight = "RESTRICTION"        // Art 18
	RightPortability DataSubjectRight = "PORTABILITY"        // Art 20
	RightObject      DataSubjectRight = "OBJECTION"          // Art 21
	RightAutomated   DataSubjectRight = "AUTOMATED_DECISION" // Art 22
)

// ProcessingActivity represents a GDPR Article 30 Record of Processing Activity.
type ProcessingActivity struct {
	ID             string      `json:"id"`
	Purpose        string      `json:"purpose"`
	LawfulBasis    LawfulBasis `json:"lawful_basis"`
	DataCategories []string    `json:"data_categories"`
	DataSubjects   []string    `json:"data_subjects"`
	Recipients     []string    `json:"recipients,omitempty"`
	Retention      string      `json:"retention_period"`
	CrossBorder    bool        `json:"cross_border_transfer"`
	TransferBasis  string      `json:"transfer_basis,omitempty"` // SCCs, Adequacy, BCRs
	DPIA           *DPIARecord `json:"dpia,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
	LastReviewed   time.Time   `json:"last_reviewed"`
}

// DPIARecord represents a Data Protection Impact Assessment (Article 35).
type DPIARecord struct {
	ID             string    `json:"id"`
	Status         string    `json:"status"` // REQUIRED, COMPLETED, NOT_REQUIRED
	AssessmentDate time.Time `json:"assessment_date,omitempty"`
	RiskLevel      string    `json:"risk_level,omitempty"`
	Mitigations    []string  `json:"mitigations,omitempty"`
	DPOApproval    bool      `json:"dpo_approval"`
}

// SubjectRequest represents a data subject rights request.
type SubjectRequest struct {
	ID          string           `json:"id"`
	SubjectID   string           `json:"subject_id"`
	Right       DataSubjectRight `json:"right"`
	Status      string           `json:"status"` // RECEIVED, IN_PROGRESS, COMPLETED, REJECTED
	ReceivedAt  time.Time        `json:"received_at"`
	Deadline    time.Time        `json:"deadline"` // 30 days from receipt
	CompletedAt *time.Time       `json:"completed_at,omitempty"`
	Response    string           `json:"response,omitempty"`
}

// ── GDPR Engine ───────────────────────────────────────────────

// GDPREngine manages GDPR compliance obligations.
type GDPREngine struct {
	mu         sync.RWMutex
	dpo        string // Data Protection Officer
	activities map[string]*ProcessingActivity
	requests   map[string]*SubjectRequest
	breaches   []BreachNotification
}

// BreachNotification represents an Article 33/34 data breach notification.
type BreachNotification struct {
	ID               string     `json:"id"`
	DiscoveredAt     time.Time  `json:"discovered_at"`
	ReportedAt       *time.Time `json:"reported_at,omitempty"`
	NotifiedDPA      bool       `json:"notified_dpa"`      // Art 33: within 72 hours
	NotifiedSubjects bool       `json:"notified_subjects"` // Art 34: if high risk
	AffectedCount    int        `json:"affected_count"`
	DataCategories   []string   `json:"data_categories"`
	RiskLevel        string     `json:"risk_level"`
}

// NewGDPREngine creates a new GDPR compliance engine.
func NewGDPREngine(dpo string) *GDPREngine {
	return &GDPREngine{
		dpo:        dpo,
		activities: make(map[string]*ProcessingActivity),
		requests:   make(map[string]*SubjectRequest),
	}
}

// RegisterProcessingActivity registers an Article 30 processing activity.
func (e *GDPREngine) RegisterProcessingActivity(_ context.Context, act *ProcessingActivity) error {
	if act.Purpose == "" {
		return fmt.Errorf("purpose is required")
	}
	if act.LawfulBasis == "" {
		return fmt.Errorf("lawful basis is required")
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.activities[act.ID] = act
	return nil
}

// HandleSubjectRequest processes a data subject rights request.
func (e *GDPREngine) HandleSubjectRequest(_ context.Context, req *SubjectRequest) error {
	if req.SubjectID == "" {
		return fmt.Errorf("subject ID is required")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	req.Status = "RECEIVED"
	req.Deadline = req.ReceivedAt.Add(30 * 24 * time.Hour) // 30 days
	e.requests[req.ID] = req
	return nil
}

// GetStatus returns the current GDPR compliance status.
func (e *GDPREngine) GetStatus() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	openRequests := 0
	for _, r := range e.requests {
		if r.Status != "COMPLETED" {
			openRequests++
		}
	}

	noDPIACount := 0
	for _, a := range e.activities {
		if a.DPIA == nil || a.DPIA.Status != "COMPLETED" {
			noDPIACount++
		}
	}

	return map[string]interface{}{
		"dpo":                   e.dpo,
		"processing_activities": len(e.activities),
		"open_subject_requests": openRequests,
		"pending_dpias":         noDPIACount,
		"breach_notifications":  len(e.breaches),
	}
}
