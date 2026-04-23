// Package docs implements compliance documentation generation for HELM.
//
// Supported frameworks:
// - MiCA (Markets in Crypto-Assets) Article 68
// - EU AI Act transparency requirements
// - SOC 2 Type II evidence collection
// - Standard audit trail export formats
package docs

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// ComplianceFramework represents a regulatory framework.
type ComplianceFramework string

const (
	FrameworkMiCA    ComplianceFramework = "MiCA"
	FrameworkEUAIAct ComplianceFramework = "EU_AI_ACT"
	FrameworkSOC2    ComplianceFramework = "SOC2_TYPE_II"
	FrameworkGDPR    ComplianceFramework = "GDPR"
)

// AttestationStatus represents compliance status.
type AttestationStatus string

const (
	StatusCompliant     AttestationStatus = "COMPLIANT"
	StatusPartial       AttestationStatus = "PARTIALLY_COMPLIANT"
	StatusNonCompliant  AttestationStatus = "NON_COMPLIANT"
	StatusNotApplicable AttestationStatus = "NOT_APPLICABLE"
	StatusPending       AttestationStatus = "PENDING_REVIEW"
)

// ---- MiCA Article 68 Compliance ----

// MiCAAttestation represents MiCA Article 68 compliance attestation.
type MiCAAttestation struct {
	EntityID         string                        `json:"entity_id"`
	EntityType       string                        `json:"entity_type"`
	Jurisdictions    []string                      `json:"jurisdictions"`
	LicenseNumber    string                        `json:"license_number,omitempty"`
	AttestationDate  time.Time                     `json:"attestation_date"`
	ExpiryDate       time.Time                     `json:"expiry_date"`
	Status           AttestationStatus             `json:"status"`
	Articles         map[string]*ArticleCompliance `json:"articles"`
	AuditorID        string                        `json:"auditor_id,omitempty"`
	EvidencePackRefs []string                      `json:"evidence_pack_refs"`
}

// ArticleCompliance represents compliance status for a specific article.
type ArticleCompliance struct {
	ArticleID    string            `json:"article_id"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	Status       AttestationStatus `json:"status"`
	Requirements []Requirement     `json:"requirements"`
	Evidence     []EvidenceRef     `json:"evidence"`
}

// Requirement represents a regulatory requirement.
type Requirement struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Status      AttestationStatus `json:"status"`
	Notes       string            `json:"notes,omitempty"`
}

// EvidenceRef references evidence supporting compliance.
type EvidenceRef struct {
	Type        string    `json:"type"`
	Reference   string    `json:"reference"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Hash        string    `json:"hash,omitempty"`
}

// NewMiCAAttestation creates a new MiCA attestation.
func NewMiCAAttestation(entityID, entityType string) *MiCAAttestation {
	return &MiCAAttestation{
		EntityID:        entityID,
		EntityType:      entityType,
		AttestationDate: time.Now(),
		ExpiryDate:      time.Now().AddDate(1, 0, 0), // 1 year
		Status:          StatusPending,
		Articles:        make(map[string]*ArticleCompliance),
	}
}

// AddArticle68 adds MiCA Article 68 compliance (orderly wind-down).
func (m *MiCAAttestation) AddArticle68() {
	m.Articles["68"] = &ArticleCompliance{
		ArticleID:   "68",
		Title:       "Orderly wind-down",
		Description: "Crypto-asset service providers shall have procedures for orderly wind-down of activities.",
		Status:      StatusPending,
		Requirements: []Requirement{
			{ID: "68.1.a", Description: "Procedures for orderly wind-down", Status: StatusPending},
			{ID: "68.1.b", Description: "Client asset protection during wind-down", Status: StatusPending},
			{ID: "68.1.c", Description: "Continuity of critical operations", Status: StatusPending},
			{ID: "68.1.d", Description: "Transfer of client assets", Status: StatusPending},
		},
	}
}

// SetRequirementStatus updates a requirement's status.
func (m *MiCAAttestation) SetRequirementStatus(articleID, reqID string, status AttestationStatus, notes string) error {
	article, exists := m.Articles[articleID]
	if !exists {
		return fmt.Errorf("article %s not found", articleID)
	}

	for i := range article.Requirements {
		if article.Requirements[i].ID == reqID {
			article.Requirements[i].Status = status
			article.Requirements[i].Notes = notes
			return nil
		}
	}
	return fmt.Errorf("requirement %s not found in article %s", reqID, articleID)
}

// AddEvidence adds evidence to an article.
func (m *MiCAAttestation) AddEvidence(articleID string, evidence EvidenceRef) error {
	article, exists := m.Articles[articleID]
	if !exists {
		return fmt.Errorf("article %s not found", articleID)
	}

	evidence.Timestamp = time.Now()
	article.Evidence = append(article.Evidence, evidence)
	return nil
}

// CalculateOverallStatus calculates overall compliance status.
func (m *MiCAAttestation) CalculateOverallStatus() {
	compliant := 0
	partial := 0
	nonCompliant := 0

	for _, article := range m.Articles {
		switch article.Status {
		case StatusCompliant:
			compliant++
		case StatusPartial:
			partial++
		case StatusNonCompliant:
			nonCompliant++
		}
	}

	if nonCompliant > 0 {
		m.Status = StatusNonCompliant
	} else if partial > 0 {
		m.Status = StatusPartial
	} else if compliant == len(m.Articles) && len(m.Articles) > 0 {
		m.Status = StatusCompliant
	} else {
		m.Status = StatusPending
	}
}

// ---- EU AI Act Transparency ----

// AIActTransparency represents EU AI Act transparency requirements.
type AIActTransparency struct {
	SystemID        string               `json:"system_id"`
	SystemName      string               `json:"system_name"`
	RiskCategory    AIRiskCategory       `json:"risk_category"`
	Provider        string               `json:"provider"`
	Version         string               `json:"version"`
	TransparencyDoc TransparencyDocument `json:"transparency_document"`
	TechnicalDoc    TechnicalDocument    `json:"technical_document"`
	Status          AttestationStatus    `json:"status"`
	GeneratedAt     time.Time            `json:"generated_at"`
}

// AIRiskCategory represents AI system risk classification.
type AIRiskCategory string

const (
	RiskMinimal      AIRiskCategory = "MINIMAL"
	RiskLimited      AIRiskCategory = "LIMITED"
	RiskHigh         AIRiskCategory = "HIGH"
	RiskUnacceptable AIRiskCategory = "UNACCEPTABLE"
)

// TransparencyDocument per EU AI Act Article 52.
type TransparencyDocument struct {
	Purpose        string   `json:"purpose"`
	Capabilities   []string `json:"capabilities"`
	Limitations    []string `json:"limitations"`
	IntendedUse    string   `json:"intended_use"`
	ProhibitedUses []string `json:"prohibited_uses,omitempty"`
	HumanOversight string   `json:"human_oversight"`
	DataSources    []string `json:"data_sources"`
	TrainingDate   string   `json:"training_date,omitempty"`
}

// TechnicalDocument per EU AI Act Annex IV.
type TechnicalDocument struct {
	Architecture       string             `json:"architecture"`
	TrainingData       string             `json:"training_data_description"`
	ValidationMethod   string             `json:"validation_method"`
	PerformanceMetrics map[string]float64 `json:"performance_metrics"`
	KnownBiases        []string           `json:"known_biases,omitempty"`
	Cybersecurity      string             `json:"cybersecurity_measures"`
	QualityManagement  string             `json:"quality_management"`
}

// NewAIActTransparency creates a new AI Act transparency record.
func NewAIActTransparency(systemID, systemName string, risk AIRiskCategory) *AIActTransparency {
	return &AIActTransparency{
		SystemID:     systemID,
		SystemName:   systemName,
		RiskCategory: risk,
		Status:       StatusPending,
		GeneratedAt:  time.Now(),
	}
}

// SetTransparencyDoc sets the transparency document.
func (a *AIActTransparency) SetTransparencyDoc(doc TransparencyDocument) {
	a.TransparencyDoc = doc
}

// SetTechnicalDoc sets the technical document.
func (a *AIActTransparency) SetTechnicalDoc(doc TechnicalDocument) {
	a.TechnicalDoc = doc
}

// ---- SOC 2 Type II ----

// SOC2Attestation represents SOC 2 Type II evidence collection.
type SOC2Attestation struct {
	OrganizationID   string                     `json:"organization_id"`
	OrganizationName string                     `json:"organization_name"`
	PeriodStart      time.Time                  `json:"period_start"`
	PeriodEnd        time.Time                  `json:"period_end"`
	TrustPrinciples  map[string]*TrustPrinciple `json:"trust_principles"`
	ControlTests     []ControlTest              `json:"control_tests"`
	Status           AttestationStatus          `json:"status"`
	AuditorOpinion   string                     `json:"auditor_opinion,omitempty"`
}

// TrustPrinciple represents a SOC 2 trust service principle.
type TrustPrinciple struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Status      AttestationStatus `json:"status"`
	Controls    []Control         `json:"controls"`
}

// Control represents a SOC 2 control.
type Control struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Status      AttestationStatus `json:"status"`
	Evidence    []EvidenceRef     `json:"evidence"`
}

// ControlTest represents a test of controls.
type ControlTest struct {
	ControlID  string    `json:"control_id"`
	TestDate   time.Time `json:"test_date"`
	Tester     string    `json:"tester"`
	Result     string    `json:"result"`
	Exceptions []string  `json:"exceptions,omitempty"`
}

// NewSOC2Attestation creates a new SOC 2 attestation.
func NewSOC2Attestation(orgID, orgName string, start, end time.Time) *SOC2Attestation {
	soc := &SOC2Attestation{
		OrganizationID:   orgID,
		OrganizationName: orgName,
		PeriodStart:      start,
		PeriodEnd:        end,
		TrustPrinciples:  make(map[string]*TrustPrinciple),
		Status:           StatusPending,
	}
	soc.initTrustPrinciples()
	return soc
}

func (s *SOC2Attestation) initTrustPrinciples() {
	s.TrustPrinciples["security"] = &TrustPrinciple{
		ID:          "CC",
		Name:        "Security",
		Description: "Information and systems are protected against unauthorized access.",
		Status:      StatusPending,
	}
	s.TrustPrinciples["availability"] = &TrustPrinciple{
		ID:          "A",
		Name:        "Availability",
		Description: "Information and systems are available for operation and use.",
		Status:      StatusPending,
	}
	s.TrustPrinciples["processing_integrity"] = &TrustPrinciple{
		ID:          "PI",
		Name:        "Processing Integrity",
		Description: "System processing is complete, valid, accurate, timely and authorized.",
		Status:      StatusPending,
	}
	s.TrustPrinciples["confidentiality"] = &TrustPrinciple{
		ID:          "C",
		Name:        "Confidentiality",
		Description: "Information designated as confidential is protected.",
		Status:      StatusPending,
	}
	s.TrustPrinciples["privacy"] = &TrustPrinciple{
		ID:          "P",
		Name:        "Privacy",
		Description: "Personal information is collected, used, retained and disposed of properly.",
		Status:      StatusPending,
	}
}

// AddControl adds a control to a trust principle.
func (s *SOC2Attestation) AddControl(principle, controlID, description, category string) error {
	tp, exists := s.TrustPrinciples[principle]
	if !exists {
		return fmt.Errorf("unknown principle: %s", principle)
	}

	tp.Controls = append(tp.Controls, Control{
		ID:          controlID,
		Description: description,
		Category:    category,
		Status:      StatusPending,
	})
	return nil
}

// RecordTest records a control test.
func (s *SOC2Attestation) RecordTest(controlID, tester, result string, exceptions []string) {
	s.ControlTests = append(s.ControlTests, ControlTest{
		ControlID:  controlID,
		TestDate:   time.Now(),
		Tester:     tester,
		Result:     result,
		Exceptions: exceptions,
	})
}

// ---- Audit Trail Export ----

// AuditTrailExporter exports audit trails to standard formats.
type AuditTrailExporter struct {
	OrganizationID string
	ExportFormats  []string
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	Timestamp    time.Time      `json:"timestamp"`
	EventType    string         `json:"event_type"`
	Actor        string         `json:"actor"`
	Resource     string         `json:"resource"`
	Action       string         `json:"action"`
	Outcome      string         `json:"outcome"`
	Details      map[string]any `json:"details,omitempty"`
	EvidencePack string         `json:"evidence_pack,omitempty"`
}

// NewAuditTrailExporter creates a new exporter.
func NewAuditTrailExporter(orgID string) *AuditTrailExporter {
	return &AuditTrailExporter{
		OrganizationID: orgID,
		ExportFormats:  []string{"JSON", "SIEM", "CEF", "CSV"},
	}
}

// ExportJSON exports entries to JSON format.
func (e *AuditTrailExporter) ExportJSON(entries []AuditEntry) ([]byte, error) {
	return json.MarshalIndent(entries, "", "  ")
}

// ExportCEF exports entries to Common Event Format.
func (e *AuditTrailExporter) ExportCEF(entries []AuditEntry) string {
	var result string
	for _, entry := range entries {
		cef := fmt.Sprintf("CEF:0|HELM|Governance Engine|1.0|%s|%s|5|src=%s dst=%s outcome=%s",
			entry.EventType,
			entry.Action,
			entry.Actor,
			entry.Resource,
			entry.Outcome)
		result += cef + "\n"
	}
	return result
}

// ExportCSV exports entries to CSV format.
func (e *AuditTrailExporter) ExportCSV(entries []AuditEntry) string {
	result := "timestamp,event_type,actor,resource,action,outcome\n"
	for _, entry := range entries {
		result += fmt.Sprintf("%s,%s,%s,%s,%s,%s\n",
			entry.Timestamp.Format(time.RFC3339),
			entry.EventType,
			entry.Actor,
			entry.Resource,
			entry.Action,
			entry.Outcome)
	}
	return result
}

// SupportedFormats returns list of supported export formats.
func (e *AuditTrailExporter) SupportedFormats() []string {
	formats := make([]string, len(e.ExportFormats))
	copy(formats, e.ExportFormats)
	sort.Strings(formats)
	return formats
}
