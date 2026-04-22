// Package euaiact implements EU AI Act (Regulation 2024/1689) compliance.
// Part of HELM Sovereign Compliance Oracle (SCO).
//
// EU AI Act Requirements Addressed:
// - High-Risk AI System Classification (Art.6 + Annex III)
// - Risk Management System (Art.9)
// - Human Oversight mapped to Guardian pipeline (Art.14)
// - Transparency Obligations for GPAI (Art.50)
// - Serious Incident Reporting within 72h (Art.62)
// - CE Marking and EU Database Registration (Art.49)
//
// Key enforcement dates:
//
//	2025-02-02: Prohibited practices (Title II) + AI literacy (Art.4)
//	2025-08-02: GPAI transparency (Chapter V) + penalties
//	2026-08-02: High-risk obligations (Title III) + CE marking + EU DB
//	2027-08-02: High-risk per Annex I (existing product safety)
//
// HELM relevance: Guardian pipeline decisions may constitute "high-risk AI"
// under Annex III when used in critical infrastructure, safety components,
// or financial services.
//
// References:
// - Regulation (EU) 2024/1689
// - EUR-Lex CELEX: 32024R1689
package euaiact

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

// -----------------------------------------------------------------------
// Constants & Enumerations
// -----------------------------------------------------------------------

// RiskCategory classifies AI systems per Article 6 and Annex III.
type RiskCategory string

const (
	RiskCategoryUnacceptable RiskCategory = "UNACCEPTABLE" // Art.5 — prohibited
	RiskCategoryHigh         RiskCategory = "HIGH"         // Art.6 + Annex III
	RiskCategoryLimited      RiskCategory = "LIMITED"      // Transparency-only (Art.50)
	RiskCategoryMinimal      RiskCategory = "MINIMAL"      // No obligations beyond voluntary codes
)

// AnnexIIIArea enumerates the eight high-risk areas from Annex III.
type AnnexIIIArea string

const (
	AnnexIIIBiometrics           AnnexIIIArea = "BIOMETRICS"             // 1. Biometric identification
	AnnexIIICriticalInfra        AnnexIIIArea = "CRITICAL_INFRASTRUCTURE" // 2. Critical infrastructure
	AnnexIIIEducation            AnnexIIIArea = "EDUCATION"              // 3. Education & vocational
	AnnexIIIEmployment           AnnexIIIArea = "EMPLOYMENT"             // 4. Employment, workers
	AnnexIIIEssentialServices    AnnexIIIArea = "ESSENTIAL_SERVICES"     // 5. Access to essential services
	AnnexIIILawEnforcement       AnnexIIIArea = "LAW_ENFORCEMENT"        // 6. Law enforcement
	AnnexIIIMigration            AnnexIIIArea = "MIGRATION"              // 7. Migration, asylum, border
	AnnexIIIJustice              AnnexIIIArea = "JUSTICE"                // 8. Administration of justice
)

// ObligationCategory groups EU AI Act obligations for tracking.
type ObligationCategory string

const (
	ObligationHighRiskClassification ObligationCategory = "HIGH_RISK_CLASSIFICATION" // Art.6+AnnexIII
	ObligationRiskManagement         ObligationCategory = "RISK_MANAGEMENT"          // Art.9
	ObligationHumanOversight         ObligationCategory = "HUMAN_OVERSIGHT"          // Art.14
	ObligationTransparency           ObligationCategory = "TRANSPARENCY"             // Art.50
	ObligationIncidentReporting      ObligationCategory = "INCIDENT_REPORTING"       // Art.62
	ObligationConformityAssessment   ObligationCategory = "CONFORMITY_ASSESSMENT"    // Art.49
)

// IncidentReportingDeadline is the maximum time allowed to report a serious
// incident to market surveillance authorities per Article 62.
const IncidentReportingDeadline = 72 * time.Hour

// -----------------------------------------------------------------------
// Enforcement Dates
// -----------------------------------------------------------------------

var (
	// DateProhibitedPractices is when prohibited AI practices (Title II) and
	// AI literacy obligations (Art.4) take effect.
	DateProhibitedPractices = time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC)

	// DateGPAITransparency is when GPAI model transparency requirements
	// (Chapter V) and associated penalties apply.
	DateGPAITransparency = time.Date(2025, 8, 2, 0, 0, 0, 0, time.UTC)

	// DateHighRiskObligations is when high-risk AI system obligations
	// (Title III, Chapters 2-5), CE marking, and EU DB registration apply.
	DateHighRiskObligations = time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	// DateAnnexIHighRisk is when high-risk obligations for Annex I systems
	// (existing product safety legislation) apply.
	DateAnnexIHighRisk = time.Date(2027, 8, 2, 0, 0, 0, 0, time.UTC)
)

// -----------------------------------------------------------------------
// Guardian Gate Mapping (Art.14 Human Oversight)
// -----------------------------------------------------------------------

// GuardianGate identifies a gate in the HELM Guardian 6-gate pipeline.
type GuardianGate string

const (
	GuardianGateFreeze     GuardianGate = "FREEZE"     // Gate 1: Emergency halt
	GuardianGateContext    GuardianGate = "CONTEXT"    // Gate 2: Context enrichment
	GuardianGateIdentity   GuardianGate = "IDENTITY"   // Gate 3: Identity verification
	GuardianGateEgress     GuardianGate = "EGRESS"     // Gate 4: Egress control
	GuardianGateThreat     GuardianGate = "THREAT"     // Gate 5: Threat detection
	GuardianGateDelegation GuardianGate = "DELEGATION" // Gate 6: Delegation policy
)

// HumanOversightMapping maps Art.14 requirements to Guardian gates.
// Each Art.14 sub-requirement has specific gates that satisfy it.
type HumanOversightMapping struct {
	Article14Ref string         `json:"article_14_ref"`
	Requirement  string         `json:"requirement"`
	GuardianGates []GuardianGate `json:"guardian_gates"`
	Description  string         `json:"description"`
}

// DefaultHumanOversightMappings returns the Art.14 → Guardian gate mappings.
func DefaultHumanOversightMappings() []HumanOversightMapping {
	return []HumanOversightMapping{
		{
			Article14Ref:  "Art.14(1)",
			Requirement:   "understand_capabilities",
			GuardianGates: []GuardianGate{GuardianGateContext, GuardianGateIdentity},
			Description:   "Human overseers can understand AI system capabilities and limitations via Context and Identity gates.",
		},
		{
			Article14Ref:  "Art.14(2)",
			Requirement:   "monitor_operation",
			GuardianGates: []GuardianGate{GuardianGateContext, GuardianGateThreat, GuardianGateEgress},
			Description:   "Continuous monitoring of AI operation through Context, Threat detection, and Egress control gates.",
		},
		{
			Article14Ref:  "Art.14(3)",
			Requirement:   "intervene_interrupt",
			GuardianGates: []GuardianGate{GuardianGateFreeze, GuardianGateDelegation},
			Description:   "Ability to intervene or interrupt AI operation via Freeze (emergency halt) and Delegation gates.",
		},
		{
			Article14Ref:  "Art.14(4)",
			Requirement:   "decide_not_to_use",
			GuardianGates: []GuardianGate{GuardianGateFreeze},
			Description:   "Ability to decide not to use or disregard AI output via Freeze gate.",
		},
	}
}

// -----------------------------------------------------------------------
// Core Types
// -----------------------------------------------------------------------

// AISystem represents a registered AI system subject to EU AI Act obligations.
type AISystem struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Provider         string            `json:"provider"`
	Deployer         string            `json:"deployer,omitempty"`
	Description      string            `json:"description"`
	RiskCategory     RiskCategory      `json:"risk_category"`
	AnnexIIIAreas    []AnnexIIIArea    `json:"annex_iii_areas,omitempty"`
	IntendedPurpose  string            `json:"intended_purpose"`
	CEMarking        bool              `json:"ce_marking"`
	EUDBRegistered   bool              `json:"eu_db_registered"`
	RegisteredAt     *time.Time        `json:"registered_at,omitempty"`
	Metadata         map[string]string `json:"metadata"`
}

// RiskManagementRecord represents the Art.9 risk management system requirement.
type RiskManagementRecord struct {
	ID                string            `json:"id"`
	AISystemID        string            `json:"ai_system_id"`
	RisksIdentified   []IdentifiedRisk  `json:"risks_identified"`
	MitigationMeasures []string         `json:"mitigation_measures"`
	TestingResults    []string          `json:"testing_results"`
	LastReviewDate    time.Time         `json:"last_review_date"`
	NextReviewDate    time.Time         `json:"next_review_date"`
	Status            string            `json:"status"` // active, under_review, outdated
	Metadata          map[string]string `json:"metadata"`
}

// IdentifiedRisk is a single risk entry within the risk management system.
type IdentifiedRisk struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // critical, high, medium, low
	Likelihood  string `json:"likelihood"`
	Mitigated   bool   `json:"mitigated"`
}

// SeriousIncident represents a reportable serious incident per Art.62.
type SeriousIncident struct {
	ID                 string            `json:"id"`
	AISystemID         string            `json:"ai_system_id"`
	Description        string            `json:"description"`
	DetectedAt         time.Time         `json:"detected_at"`
	ReportedAt         *time.Time        `json:"reported_at,omitempty"`
	AffectedPersons    int               `json:"affected_persons"`
	Severity           string            `json:"severity"`
	RootCause          string            `json:"root_cause,omitempty"`
	CorrectiveActions  []string          `json:"corrective_actions"`
	ReportedToAuthority bool             `json:"reported_to_authority"`
	AuthorityID        string            `json:"authority_id,omitempty"`
	EvidencePackHash   string            `json:"evidence_pack_hash,omitempty"`
	Metadata           map[string]string `json:"metadata"`
}

// TransparencyRecord tracks GPAI transparency obligations per Art.50.
type TransparencyRecord struct {
	ID                    string            `json:"id"`
	AISystemID            string            `json:"ai_system_id"`
	AIGeneratedDisclosure bool              `json:"ai_generated_disclosure"`
	TrainingDataSummary   string            `json:"training_data_summary"`
	ModelCapabilities     string            `json:"model_capabilities"`
	ModelLimitations      string            `json:"model_limitations"`
	CopyrightCompliance   bool              `json:"copyright_compliance"`
	PublishedAt           *time.Time        `json:"published_at,omitempty"`
	Metadata              map[string]string `json:"metadata"`
}

// Obligation defines a single EU AI Act obligation with enforcement context.
type Obligation struct {
	Category      ObligationCategory `json:"category"`
	ArticleRef    string             `json:"article_ref"`
	Title         string             `json:"title"`
	Description   string             `json:"description"`
	EffectiveFrom time.Time          `json:"effective_from"`
	PenaltyMax    string             `json:"penalty_max"`
	EvidenceReqs  []string           `json:"evidence_requirements"`
	HELMImpact    string             `json:"helm_impact,omitempty"`
}

// ComplianceStatus represents the current EU AI Act compliance posture.
type ComplianceStatus struct {
	AsOf                      time.Time `json:"as_of"`
	IsCompliant               bool      `json:"is_compliant"`
	RegisteredSystems         int       `json:"registered_systems"`
	HighRiskSystems           int       `json:"high_risk_systems"`
	SystemsWithoutCEMarking   int       `json:"systems_without_ce_marking"`
	SystemsWithoutEUDB        int       `json:"systems_without_eu_db"`
	OverdueRiskReviews        int       `json:"overdue_risk_reviews"`
	UnreportedIncidents       int       `json:"unreported_incidents"`
	OverdueIncidentReports    int       `json:"overdue_incident_reports"`
	TransparencyGaps          int       `json:"transparency_gaps"`
}

// -----------------------------------------------------------------------
// Engine
// -----------------------------------------------------------------------

// EUAIActComplianceEngine manages EU AI Act compliance for HELM deployments.
type EUAIActComplianceEngine struct {
	mu            sync.RWMutex
	systems       map[string]*AISystem
	riskRecords   map[string]*RiskManagementRecord
	incidents     map[string]*SeriousIncident
	transparency  map[string]*TransparencyRecord
}

// NewEUAIActComplianceEngine creates a new EU AI Act compliance engine.
func NewEUAIActComplianceEngine() *EUAIActComplianceEngine {
	return &EUAIActComplianceEngine{
		systems:      make(map[string]*AISystem),
		riskRecords:  make(map[string]*RiskManagementRecord),
		incidents:    make(map[string]*SeriousIncident),
		transparency: make(map[string]*TransparencyRecord),
	}
}

// RegisterAISystem registers an AI system for compliance tracking.
func (e *EUAIActComplianceEngine) RegisterAISystem(ctx context.Context, system *AISystem) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if system.ID == "" {
		system.ID = generateID("aisys")
	}
	if system.RiskCategory == "" {
		system.RiskCategory = RiskCategoryMinimal
	}

	e.systems[system.ID] = system
	return nil
}

// ClassifyRisk classifies an AI system per Art.6 + Annex III.
// Returns the determined risk category based on declared Annex III areas.
func (e *EUAIActComplianceEngine) ClassifyRisk(ctx context.Context, systemID string) (RiskCategory, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	system, ok := e.systems[systemID]
	if !ok {
		return "", fmt.Errorf("AI system not found: %s", systemID)
	}

	// Systems in Annex III areas are automatically high-risk.
	if len(system.AnnexIIIAreas) > 0 {
		return RiskCategoryHigh, nil
	}

	return system.RiskCategory, nil
}

// RecordRiskManagement records risk management activity per Art.9.
func (e *EUAIActComplianceEngine) RecordRiskManagement(ctx context.Context, record *RiskManagementRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if record.ID == "" {
		record.ID = generateID("risk")
	}
	if record.LastReviewDate.IsZero() {
		record.LastReviewDate = time.Now()
	}
	if record.Status == "" {
		record.Status = "active"
	}

	e.riskRecords[record.ID] = record
	return nil
}

// ReportIncident reports a serious incident per Art.62.
func (e *EUAIActComplianceEngine) ReportIncident(ctx context.Context, incident *SeriousIncident) error {
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

// IsIncidentReportOverdue checks whether the 72h reporting deadline has passed.
func (e *EUAIActComplianceEngine) IsIncidentReportOverdue(incident *SeriousIncident) bool {
	if incident.ReportedToAuthority {
		return false
	}
	return time.Since(incident.DetectedAt) > IncidentReportingDeadline
}

// RecordTransparency records GPAI transparency compliance per Art.50.
func (e *EUAIActComplianceEngine) RecordTransparency(ctx context.Context, record *TransparencyRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if record.ID == "" {
		record.ID = generateID("trans")
	}

	e.transparency[record.ID] = record
	return nil
}

// GetObligations returns the canonical set of EU AI Act obligations with
// enforcement dates, penalty caps, and HELM impact annotations.
func (e *EUAIActComplianceEngine) GetObligations() []Obligation {
	return []Obligation{
		{
			Category:      ObligationHighRiskClassification,
			ArticleRef:    "Art.6+AnnexIII",
			Title:         "High-Risk AI System Classification",
			Description:   "AI systems in Annex III areas (critical infrastructure, safety components, financial services) must comply with Chapter 2 requirements: risk management, data governance, technical docs, record-keeping, transparency, human oversight, accuracy/robustness/cybersecurity.",
			EffectiveFrom: DateHighRiskObligations,
			PenaltyMax:    "EUR 15M or 3% global annual turnover",
			EvidenceReqs:  []string{"ai_inventory", "risk_assessment", "technical_documentation"},
			HELMImpact:    "guardian_pipeline",
		},
		{
			Category:      ObligationRiskManagement,
			ArticleRef:    "Art.9",
			Title:         "Risk Management System",
			Description:   "Continuous risk management system required: identify risks, estimate/evaluate, adopt management measures, test. HELM Guardian 6-gate pipeline maps to this requirement.",
			EffectiveFrom: DateHighRiskObligations,
			PenaltyMax:    "EUR 15M or 3% global annual turnover",
			EvidenceReqs:  []string{"risk_management_plan", "risk_register", "test_results", "review_records"},
			HELMImpact:    "guardian_risk_management",
		},
		{
			Category:      ObligationHumanOversight,
			ArticleRef:    "Art.14",
			Title:         "Human Oversight",
			Description:   "High-risk AI must enable human oversight: understand capabilities/limitations, monitor operation, intervene/interrupt, decide not to use. HELM intervention gates and escalation ceremonies map here.",
			EffectiveFrom: DateHighRiskObligations,
			PenaltyMax:    "EUR 15M or 3% global annual turnover",
			EvidenceReqs:  []string{"oversight_procedures", "intervention_logs", "escalation_records"},
			HELMImpact:    "escalation_ceremony",
		},
		{
			Category:      ObligationTransparency,
			ArticleRef:    "Art.50",
			Title:         "Transparency for GPAI Providers",
			Description:   "General-purpose AI providers must: disclose AI-generated content, publish training data summaries, comply with copyright, publish model capabilities and limitations.",
			EffectiveFrom: DateGPAITransparency,
			PenaltyMax:    "EUR 15M or 3% global annual turnover",
			EvidenceReqs:  []string{"model_card", "training_data_summary", "capability_assessment", "copyright_policy"},
			HELMImpact:    "transparency_notice",
		},
		{
			Category:      ObligationIncidentReporting,
			ArticleRef:    "Art.62",
			Title:         "Serious Incident Reporting (72h)",
			Description:   "Providers/deployers of high-risk AI must report serious incidents to market surveillance authorities within 72 hours of becoming aware. HELM evidence packs provide audit trail.",
			EffectiveFrom: DateHighRiskObligations,
			PenaltyMax:    "EUR 15M or 3% global annual turnover",
			EvidenceReqs:  []string{"incident_report", "evidence_pack", "notification_receipt"},
			HELMImpact:    "evidence_pack_reporting",
		},
		{
			Category:      ObligationConformityAssessment,
			ArticleRef:    "Art.49",
			Title:         "CE Marking and EU Database Registration",
			Description:   "High-risk AI systems require CE marking and registration in EU database before placing on market or putting into service.",
			EffectiveFrom: DateHighRiskObligations,
			PenaltyMax:    "EUR 15M or 3% global annual turnover",
			EvidenceReqs:  []string{"conformity_declaration", "ce_certificate", "eu_db_registration"},
			HELMImpact:    "conformity_assessment",
		},
	}
}

// GetComplianceStatus returns the current EU AI Act compliance posture.
func (e *EUAIActComplianceEngine) GetComplianceStatus(ctx context.Context) *ComplianceStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	status := &ComplianceStatus{
		AsOf:              time.Now(),
		RegisteredSystems: len(e.systems),
	}

	now := time.Now()

	// Count high-risk systems and check CE marking / EU DB registration.
	for _, sys := range e.systems {
		if sys.RiskCategory == RiskCategoryHigh || len(sys.AnnexIIIAreas) > 0 {
			status.HighRiskSystems++
			if !sys.CEMarking {
				status.SystemsWithoutCEMarking++
			}
			if !sys.EUDBRegistered {
				status.SystemsWithoutEUDB++
			}
		}
	}

	// Check overdue risk management reviews.
	for _, rec := range e.riskRecords {
		if !rec.NextReviewDate.IsZero() && now.After(rec.NextReviewDate) {
			status.OverdueRiskReviews++
		}
	}

	// Check unreported and overdue incident reports.
	for _, inc := range e.incidents {
		if !inc.ReportedToAuthority {
			status.UnreportedIncidents++
			if e.IsIncidentReportOverdue(inc) {
				status.OverdueIncidentReports++
			}
		}
	}

	// Check transparency gaps for systems that have no transparency record.
	transparencySystems := make(map[string]bool)
	for _, tr := range e.transparency {
		transparencySystems[tr.AISystemID] = true
	}
	for id, sys := range e.systems {
		if sys.RiskCategory == RiskCategoryHigh || sys.RiskCategory == RiskCategoryLimited {
			if !transparencySystems[id] {
				status.TransparencyGaps++
			}
		}
	}

	// Determine overall compliance.
	status.IsCompliant = status.SystemsWithoutCEMarking == 0 &&
		status.SystemsWithoutEUDB == 0 &&
		status.OverdueRiskReviews == 0 &&
		status.OverdueIncidentReports == 0 &&
		status.TransparencyGaps == 0

	return status
}

// ExportComplianceJSON exports the compliance status as JSON.
func (e *EUAIActComplianceEngine) ExportComplianceJSON(ctx context.Context) ([]byte, error) {
	status := e.GetComplianceStatus(ctx)
	return json.MarshalIndent(status, "", "  ")
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// generateID generates a unique ID with the given prefix.
func generateID(prefix string) string {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		panic(fmt.Sprintf("failed to generate random ID: %v", err))
	}
	hash := sha256.Sum256(randomBytes)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(hash[:])[:12])
}
