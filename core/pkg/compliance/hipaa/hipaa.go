// Package hipaa implements HIPAA compliance for AI agent governance.
//
// HIPAA Requirements Addressed:
// - Privacy Rule (45 CFR Part 164, Subpart E): PHI access controls
// - Security Rule (45 CFR Part 164, Subpart C): Technical safeguards
// - Breach Notification Rule (45 CFR Part 164, Subpart D): Incident reporting
//
// Integrates with HELM's DLP scanner (pkg/security/dlp/) and privacy
// framework (pkg/privacy/) for enforcement.
package hipaa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// PHICategory represents the 18 HIPAA identifiers.
type PHICategory string

const (
	PHIName          PHICategory = "NAME"
	PHIAddress       PHICategory = "ADDRESS"
	PHIDates         PHICategory = "DATES"
	PHIPhone         PHICategory = "PHONE"
	PHIFax           PHICategory = "FAX"
	PHIEmail         PHICategory = "EMAIL"
	PHISSN           PHICategory = "SSN"
	PHIMedicalRecord PHICategory = "MEDICAL_RECORD"
	PHIHealthPlan    PHICategory = "HEALTH_PLAN"
	PHIAccount       PHICategory = "ACCOUNT"
	PHICertLicense   PHICategory = "CERT_LICENSE"
	PHIVehicle       PHICategory = "VEHICLE"
	PHIDevice        PHICategory = "DEVICE_ID"
	PHIWebURL        PHICategory = "WEB_URL"
	PHIIP            PHICategory = "IP_ADDRESS"
	PHIBiometric     PHICategory = "BIOMETRIC"
	PHIPhoto         PHICategory = "PHOTO"
	PHIOther         PHICategory = "OTHER_UNIQUE"
)

// AccessPurpose represents the reason for PHI access.
type AccessPurpose string

const (
	PurposeTreatment     AccessPurpose = "TREATMENT"
	PurposePayment       AccessPurpose = "PAYMENT"
	PurposeHealthcareOps AccessPurpose = "HEALTHCARE_OPS"
	PurposeResearch      AccessPurpose = "RESEARCH"
	PurposePublicHealth  AccessPurpose = "PUBLIC_HEALTH"
	PurposeBreakGlass    AccessPurpose = "BREAK_GLASS"
)

// PHIAccessRecord records a PHI access event for audit trail.
type PHIAccessRecord struct {
	ID               string        `json:"id"`
	AgentID          string        `json:"agent_id"`
	PatientID        string        `json:"patient_id"` // De-identified reference
	PHICategories    []PHICategory `json:"phi_categories"`
	Purpose          AccessPurpose `json:"purpose"`
	MinimumNecessary bool          `json:"minimum_necessary"`
	Justification    string        `json:"justification"`
	BreakGlass       bool          `json:"break_glass"`
	Timestamp        time.Time     `json:"timestamp"`
	ReceiptID        string        `json:"receipt_id,omitempty"`
}

// BreachRecord represents a HIPAA breach per the Breach Notification Rule.
type BreachRecord struct {
	ID                  string        `json:"id"`
	Description         string        `json:"description"`
	PHICategories       []PHICategory `json:"phi_categories"`
	IndividualsAffected int           `json:"individuals_affected"`
	DiscoveredAt        time.Time     `json:"discovered_at"`
	ReportedAt          *time.Time    `json:"reported_at,omitempty"` // Must be within 60 days
	ReportedToHHS       bool          `json:"reported_to_hhs"`
	ReportedToMedia     bool          `json:"reported_to_media"` // Required if >500 individuals
	RiskAssessment      string        `json:"risk_assessment"`
	Mitigations         []string      `json:"mitigations"`
}

// BAARecord represents a Business Associate Agreement.
type BAARecord struct {
	ID             string     `json:"id"`
	AssociateName  string     `json:"associate_name"`
	AssociateType  string     `json:"associate_type"` // cloud, vendor, processor
	AgreementDate  time.Time  `json:"agreement_date"`
	ExpirationDate *time.Time `json:"expiration_date,omitempty"`
	Active         bool       `json:"active"`
}

// HIPAAComplianceEngine manages HIPAA compliance for HELM.
type HIPAAComplianceEngine struct {
	mu         sync.RWMutex
	accessLog  map[string]*PHIAccessRecord
	breaches   map[string]*BreachRecord
	baas       map[string]*BAARecord
	entityName string
}

// NewHIPAAComplianceEngine creates a new HIPAA compliance engine.
func NewHIPAAComplianceEngine(entityName string) *HIPAAComplianceEngine {
	return &HIPAAComplianceEngine{
		accessLog:  make(map[string]*PHIAccessRecord),
		breaches:   make(map[string]*BreachRecord),
		baas:       make(map[string]*BAARecord),
		entityName: entityName,
	}
}

// RecordPHIAccess logs a PHI access event.
func (e *HIPAAComplianceEngine) RecordPHIAccess(_ context.Context, record *PHIAccessRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now()
	}
	if !record.MinimumNecessary && record.Purpose != PurposeBreakGlass {
		return fmt.Errorf("hipaa: minimum necessary standard not met (set MinimumNecessary=true or Purpose=BREAK_GLASS)")
	}
	e.accessLog[record.ID] = record
	return nil
}

// ReportBreach reports a HIPAA breach.
func (e *HIPAAComplianceEngine) ReportBreach(_ context.Context, breach *BreachRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if breach.DiscoveredAt.IsZero() {
		breach.DiscoveredAt = time.Now()
	}
	e.breaches[breach.ID] = breach
	return nil
}

// RegisterBAA registers a Business Associate Agreement.
func (e *HIPAAComplianceEngine) RegisterBAA(_ context.Context, baa *BAARecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.baas[baa.ID] = baa
	return nil
}

// GetComplianceStatus returns HIPAA compliance status.
func (e *HIPAAComplianceEngine) GetComplianceStatus(_ context.Context) *ComplianceStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	status := &ComplianceStatus{
		AsOf:           time.Now(),
		PHIAccessCount: len(e.accessLog),
		BreachCount:    len(e.breaches),
		BAACount:       len(e.baas),
	}

	// Check for breaches needing notification (60-day deadline)
	deadline := time.Now().AddDate(0, 0, -60)
	for _, b := range e.breaches {
		if !b.ReportedToHHS && b.DiscoveredAt.Before(deadline) {
			status.OverdueNotifications++
		}
		if b.IndividualsAffected >= 500 && !b.ReportedToMedia {
			status.MediaNotificationRequired++
		}
	}

	// Check for break-glass access needing review
	for _, a := range e.accessLog {
		if a.BreakGlass {
			status.BreakGlassCount++
		}
	}

	// Check for expired BAAs
	for _, baa := range e.baas {
		if baa.ExpirationDate != nil && baa.ExpirationDate.Before(time.Now()) && baa.Active {
			status.ExpiredBAAs++
		}
	}

	status.IsCompliant = status.OverdueNotifications == 0 &&
		status.MediaNotificationRequired == 0 &&
		status.ExpiredBAAs == 0

	return status
}

// GenerateAuditReport generates a HIPAA audit report.
func (e *HIPAAComplianceEngine) GenerateAuditReport(_ context.Context, periodStart, periodEnd time.Time) (*AuditReport, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	report := &AuditReport{
		Entity:      e.entityName,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		GeneratedAt: time.Now(),
	}

	for _, a := range e.accessLog {
		if a.Timestamp.After(periodStart) && a.Timestamp.Before(periodEnd) {
			report.PHIAccesses = append(report.PHIAccesses, *a)
		}
	}
	for _, b := range e.breaches {
		if b.DiscoveredAt.After(periodStart) && b.DiscoveredAt.Before(periodEnd) {
			report.Breaches = append(report.Breaches, *b)
		}
	}

	content, _ := json.Marshal(report)
	hash := sha256.Sum256(content)
	report.Hash = hex.EncodeToString(hash[:])

	return report, nil
}

// ComplianceStatus is the HIPAA compliance status.
type ComplianceStatus struct {
	AsOf                      time.Time `json:"as_of"`
	IsCompliant               bool      `json:"is_compliant"`
	PHIAccessCount            int       `json:"phi_access_count"`
	BreachCount               int       `json:"breach_count"`
	BAACount                  int       `json:"baa_count"`
	BreakGlassCount           int       `json:"break_glass_count"`
	OverdueNotifications      int       `json:"overdue_notifications"`
	MediaNotificationRequired int       `json:"media_notification_required"`
	ExpiredBAAs               int       `json:"expired_baas"`
}

// AuditReport is a HIPAA audit report.
type AuditReport struct {
	Entity      string            `json:"entity"`
	PeriodStart time.Time         `json:"period_start"`
	PeriodEnd   time.Time         `json:"period_end"`
	GeneratedAt time.Time         `json:"generated_at"`
	PHIAccesses []PHIAccessRecord `json:"phi_accesses"`
	Breaches    []BreachRecord    `json:"breaches"`
	Hash        string            `json:"hash"`
}
