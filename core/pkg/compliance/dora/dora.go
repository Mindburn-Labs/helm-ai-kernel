// Package dora implements EU DORA (Digital Operational Resilience Act) compliance.
// Part of HELM Sovereign Compliance Oracle (SCO).
//
// DORA Requirements Addressed:
// - ICT Risk Management Framework (Article 6-16)
// - ICT Incident Reporting (Article 17-23)
// - Digital Resilience Testing (Article 24-27)
// - Third-Party ICT Risk (Article 28-44)
// - Register of Information (ROI) generation
//
// Full enforcement: January 2026
package dora

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// RiskLevel represents the ICT risk classification.
type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "CRITICAL"
	RiskLevelHigh     RiskLevel = "HIGH"
	RiskLevelMedium   RiskLevel = "MEDIUM"
	RiskLevelLow      RiskLevel = "LOW"
)

// IncidentType represents DORA incident classifications.
type IncidentType string

const (
	IncidentCyberAttack       IncidentType = "CYBER_ATTACK"
	IncidentSystemFailure     IncidentType = "SYSTEM_FAILURE"
	IncidentDataBreach        IncidentType = "DATA_BREACH"
	IncidentServiceDisruption IncidentType = "SERVICE_DISRUPTION"
	IncidentThirdPartyFailure IncidentType = "THIRD_PARTY_FAILURE"
)

// ICTRisk represents an identified ICT risk per DORA Article 6-16.
type ICTRisk struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	Level          RiskLevel         `json:"level"`
	Category       string            `json:"category"` // network, application, data, etc.
	AffectedAssets []string          `json:"affected_assets"`
	MitigationPlan string            `json:"mitigation_plan"`
	Owner          string            `json:"owner"`
	Status         string            `json:"status"` // identified, mitigated, accepted
	IdentifiedAt   time.Time         `json:"identified_at"`
	ReviewDate     time.Time         `json:"review_date"`
	Metadata       map[string]string `json:"metadata"`
}

// ICTIncident represents a reportable incident per DORA Article 17-23.
type ICTIncident struct {
	ID                string            `json:"id"`
	Type              IncidentType      `json:"type"`
	Description       string            `json:"description"`
	DetectedAt        time.Time         `json:"detected_at"`
	ResolvedAt        *time.Time        `json:"resolved_at,omitempty"`
	Severity          RiskLevel         `json:"severity"`
	AffectedServices  []string          `json:"affected_services"`
	AffectedClients   int               `json:"affected_clients"`
	RootCause         string            `json:"root_cause,omitempty"`
	RemediationSteps  []string          `json:"remediation_steps"`
	ReportedToNCAs    bool              `json:"reported_to_ncas"` // National Competent Authorities
	ReportSubmittedAt *time.Time        `json:"report_submitted_at,omitempty"`
	Metadata          map[string]string `json:"metadata"`
}

// ThirdPartyProvider represents a third-party ICT provider per DORA Article 28-44.
type ThirdPartyProvider struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	ServiceType          string            `json:"service_type"` // cloud, software, infrastructure
	Criticality          RiskLevel         `json:"criticality"`
	ContractStart        time.Time         `json:"contract_start"`
	ContractEnd          *time.Time        `json:"contract_end,omitempty"`
	ExitStrategy         string            `json:"exit_strategy"`
	SubstitutabilityPlan string            `json:"substitutability_plan"`
	LastAudit            *time.Time        `json:"last_audit,omitempty"`
	Certifications       []string          `json:"certifications"` // ISO 27001, SOC2, etc.
	Location             string            `json:"location"`       // EU, non-EU
	DataResidency        []string          `json:"data_residency"` // Countries where data is stored
	Metadata             map[string]string `json:"metadata"`
}

// ResilienceTest represents a digital resilience test per DORA Article 24-27.
type ResilienceTest struct {
	ID            string            `json:"id"`
	Type          string            `json:"type"` // tlpt, vulnerability_scan, pentest
	Description   string            `json:"description"`
	ExecutedAt    time.Time         `json:"executed_at"`
	Duration      time.Duration     `json:"duration"`
	Scope         []string          `json:"scope"`
	Findings      []string          `json:"findings"`
	Remediated    bool              `json:"remediated"`
	NextScheduled *time.Time        `json:"next_scheduled,omitempty"`
	Metadata      map[string]string `json:"metadata"`
}

// RegisterOfInformation (ROI) represents the annual DORA submission.
type RegisterOfInformation struct {
	ID                   string               `json:"id"`
	GeneratedAt          time.Time            `json:"generated_at"`
	ReportingPeriodStart time.Time            `json:"reporting_period_start"`
	ReportingPeriodEnd   time.Time            `json:"reporting_period_end"`
	EntityInfo           EntityInfo           `json:"entity_info"`
	ICTRisks             []ICTRisk            `json:"ict_risks"`
	Incidents            []ICTIncident        `json:"incidents"`
	ThirdPartyProviders  []ThirdPartyProvider `json:"third_party_providers"`
	ResilienceTests      []ResilienceTest     `json:"resilience_tests"`
	Hash                 string               `json:"hash"` // SHA256 of content for integrity
}

// EntityInfo represents the financial entity's information.
type EntityInfo struct {
	LEI          string   `json:"lei"` // Legal Entity Identifier
	Name         string   `json:"name"`
	Type         string   `json:"type"`         // credit_institution, investment_firm, etc.
	Jurisdiction string   `json:"jurisdiction"` // Primary jurisdiction (e.g., "BG", "EU")
	Regulators   []string `json:"regulators"`   // NCAs (e.g., "BNB", "FSC")
	ICTOfficer   string   `json:"ict_officer"`  // Chief ICT Officer
	ContactEmail string   `json:"contact_email"`
}

// DORAComplianceEngine manages DORA compliance for HELM entities.
type DORAComplianceEngine struct {
	mu         sync.RWMutex
	entityInfo EntityInfo
	risks      map[string]*ICTRisk
	incidents  map[string]*ICTIncident
	providers  map[string]*ThirdPartyProvider
	tests      map[string]*ResilienceTest
	lastROI    *RegisterOfInformation
}

// NewDORAComplianceEngine creates a new DORA compliance engine.
func NewDORAComplianceEngine(entity EntityInfo) *DORAComplianceEngine {
	return &DORAComplianceEngine{
		entityInfo: entity,
		risks:      make(map[string]*ICTRisk),
		incidents:  make(map[string]*ICTIncident),
		providers:  make(map[string]*ThirdPartyProvider),
		tests:      make(map[string]*ResilienceTest),
	}
}

// RegisterRisk registers a new ICT risk.
func (e *DORAComplianceEngine) RegisterRisk(ctx context.Context, risk *ICTRisk) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if risk.ID == "" {
		risk.ID = generateID("risk")
	}
	if risk.IdentifiedAt.IsZero() {
		risk.IdentifiedAt = time.Now()
	}
	if risk.Status == "" {
		risk.Status = "identified"
	}

	e.risks[risk.ID] = risk
	return nil
}

// ReportIncident reports an ICT incident.
func (e *DORAComplianceEngine) ReportIncident(ctx context.Context, incident *ICTIncident) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if incident.ID == "" {
		incident.ID = generateID("incident")
	}
	if incident.DetectedAt.IsZero() {
		incident.DetectedAt = time.Now()
	}

	e.incidents[incident.ID] = incident
	return nil
}

// RegisterProvider registers a third-party ICT provider.
func (e *DORAComplianceEngine) RegisterProvider(ctx context.Context, provider *ThirdPartyProvider) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if provider.ID == "" {
		provider.ID = generateID("provider")
	}

	e.providers[provider.ID] = provider
	return nil
}

// RecordResilienceTest records a resilience test.
func (e *DORAComplianceEngine) RecordResilienceTest(ctx context.Context, test *ResilienceTest) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if test.ID == "" {
		test.ID = generateID("test")
	}
	if test.ExecutedAt.IsZero() {
		test.ExecutedAt = time.Now()
	}

	e.tests[test.ID] = test
	return nil
}

// GenerateROI generates the Register of Information for DORA submission.
func (e *DORAComplianceEngine) GenerateROI(ctx context.Context, periodStart, periodEnd time.Time) (*RegisterOfInformation, error) {
	// Read data under RLock
	e.mu.RLock()

	roi := &RegisterOfInformation{
		ID:                   generateID("roi"),
		GeneratedAt:          time.Now(),
		ReportingPeriodStart: periodStart,
		ReportingPeriodEnd:   periodEnd,
		EntityInfo:           e.entityInfo,
	}

	// Collect risks
	for _, r := range e.risks {
		if r.IdentifiedAt.After(periodStart) && r.IdentifiedAt.Before(periodEnd) {
			roi.ICTRisks = append(roi.ICTRisks, *r)
		}
	}

	// Collect incidents
	for _, i := range e.incidents {
		if i.DetectedAt.After(periodStart) && i.DetectedAt.Before(periodEnd) {
			roi.Incidents = append(roi.Incidents, *i)
		}
	}

	// Collect all providers (regardless of period)
	for _, p := range e.providers {
		roi.ThirdPartyProviders = append(roi.ThirdPartyProviders, *p)
	}

	// Collect tests
	for _, t := range e.tests {
		if t.ExecutedAt.After(periodStart) && t.ExecutedAt.Before(periodEnd) {
			roi.ResilienceTests = append(roi.ResilienceTests, *t)
		}
	}

	e.mu.RUnlock()

	// Generate integrity hash (no lock needed — roi is local)
	content, _ := json.Marshal(roi)
	hash := sha256.Sum256(content)
	roi.Hash = hex.EncodeToString(hash[:])

	// Store under write lock
	e.mu.Lock()
	e.lastROI = roi
	e.mu.Unlock()

	return roi, nil
}

// ExportROIJSON exports the ROI as JSON for submission.
func (e *DORAComplianceEngine) ExportROIJSON(ctx context.Context, roi *RegisterOfInformation) ([]byte, error) {
	return json.MarshalIndent(roi, "", "  ")
}

// GetComplianceStatus returns the current DORA compliance status.
func (e *DORAComplianceEngine) GetComplianceStatus(ctx context.Context) *ComplianceStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	status := &ComplianceStatus{
		AsOf:                time.Now(),
		ICTRiskCount:        len(e.risks),
		IncidentCount:       len(e.incidents),
		ThirdPartyCount:     len(e.providers),
		ResilienceTestCount: len(e.tests),
	}

	// Count unmitigated critical risks
	for _, r := range e.risks {
		if r.Level == RiskLevelCritical && r.Status != "mitigated" {
			status.UnmitigatedCritical++
		}
	}

	// Count unreported incidents
	for _, i := range e.incidents {
		if !i.ReportedToNCAs && i.Severity == RiskLevelCritical {
			status.UnreportedIncidents++
		}
	}

	// Check provider audits
	oneYearAgo := time.Now().AddDate(-1, 0, 0)
	for _, p := range e.providers {
		if p.Criticality == RiskLevelCritical {
			if p.LastAudit == nil || p.LastAudit.Before(oneYearAgo) {
				status.OverdueAudits++
			}
		}
	}

	// Determine overall compliance
	status.IsCompliant = status.UnmitigatedCritical == 0 &&
		status.UnreportedIncidents == 0 &&
		status.OverdueAudits == 0

	return status
}

// ComplianceStatus represents the current DORA compliance status.
type ComplianceStatus struct {
	AsOf                time.Time `json:"as_of"`
	IsCompliant         bool      `json:"is_compliant"`
	ICTRiskCount        int       `json:"ict_risk_count"`
	IncidentCount       int       `json:"incident_count"`
	ThirdPartyCount     int       `json:"third_party_count"`
	ResilienceTestCount int       `json:"resilience_test_count"`
	UnmitigatedCritical int       `json:"unmitigated_critical"`
	UnreportedIncidents int       `json:"unreported_incidents"`
	OverdueAudits       int       `json:"overdue_audits"`
}

// generateID generates a unique ID with prefix.
func generateID(prefix string) string {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		panic(fmt.Sprintf("failed to generate random ID: %v", err))
	}
	hash := sha256.Sum256(randomBytes)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(hash[:])[:12])
}
