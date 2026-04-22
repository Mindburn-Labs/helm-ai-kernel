// Package normalize provides canonical output models for compliance source adapters.
// Each adapter class produces typed records that are normalized into a common schema
// for downstream obligations compilation and controls mapping.
package normalize

import (
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// CanonicalRecord is the base for all normalized compliance records.
type CanonicalRecord struct {
	RecordID        string               `json:"record_id"`
	SourceID        string               `json:"source_id"`
	SourceType      string               `json:"source_type"`
	Jurisdiction    jkg.JurisdictionCode `json:"jurisdiction"`
	Title           string               `json:"title"`
	ContentHash     string               `json:"content_hash"`     // SHA-256 of normalized content
	RawContentHash  string               `json:"raw_content_hash"` // SHA-256 of raw fetched content
	FetchedAt       time.Time            `json:"fetched_at"`
	EffectiveDate   time.Time            `json:"effective_date"`
	ExpirationDate  *time.Time           `json:"expiration_date,omitempty"`
	SourceURL       string               `json:"source_url"`
	Provenance      string               `json:"provenance"`
	Version         string               `json:"version"`
	AmendmentsChain []string             `json:"amendments_chain,omitempty"`
}

// --- Class 2: Privacy ---

// GuidanceRecord is the output model for privacy authority adapters (P2).
type GuidanceRecord struct {
	CanonicalRecord
	Topic              string   `json:"topic"`               // e.g., "data transfers", "consent mechanisms"
	Scope              string   `json:"scope"`               // e.g., "all controllers", "processors only"
	EnforcementPosture string   `json:"enforcement_posture"` // "binding", "advisory", "best_practice"
	References         []string `json:"references"`          // Links to underlying legislation
	LawfulBasisLogic   string   `json:"lawful_basis_logic,omitempty"`
	DPIATriggers       []string `json:"dpia_triggers,omitempty"`
	DSARWorkflow       string   `json:"dsar_workflow,omitempty"`
	BreachTimerHours   int      `json:"breach_timer_hours,omitempty"` // e.g., 72 for GDPR
	CrossBorderRules   string   `json:"cross_border_rules,omitempty"`
}

// --- Class 3: AI Governance ---

// AIObligationRecord is the output model for AI governance adapters (P3).
type AIObligationRecord struct {
	CanonicalRecord
	SystemClassTriggers    []string `json:"system_class_triggers"`     // e.g., ["high-risk", "limited-risk"]
	DocumentationDuties    []string `json:"documentation_duties"`      // Required documentation
	MonitoringDuties       []string `json:"monitoring_duties"`         // Post-market monitoring
	TransparencyNotices    []string `json:"transparency_notices"`      // Required disclosures
	TrainingDataProvenance bool     `json:"training_data_provenance"`  // Must track training data origin
	IncidentReporting      bool     `json:"incident_reporting"`        // Must report incidents
	HumanOversight         string   `json:"human_oversight,omitempty"` // Required human oversight level
}

// --- Class 4: Sanctions/AML ---

// SanctionsEntityRecord is the output model for sanctions list entries.
type SanctionsEntityRecord struct {
	CanonicalRecord
	EntityName    string            `json:"entity_name"`
	EntityType    string            `json:"entity_type"` // "individual", "entity", "vessel", "aircraft"
	Aliases       []string          `json:"aliases"`
	Identifiers   map[string]string `json:"identifiers"` // passport, national_id, etc.
	Programs      []string          `json:"programs"`    // Sanctions program names
	ListingDate   time.Time         `json:"listing_date"`
	DelistingDate *time.Time        `json:"delisting_date,omitempty"`
}

// ScreeningRuleRecord defines matching logic for sanctions screening.
type ScreeningRuleRecord struct {
	CanonicalRecord
	MatchAlgorithm   string  `json:"match_algorithm"`   // "exact", "fuzzy", "phonetic", "alias_expansion"
	MinMatchScore    float64 `json:"min_match_score"`   // Threshold for flagging
	EscalationPolicy string  `json:"escalation_policy"` // What happens on match
	ReviewerRequired bool    `json:"reviewer_required"`
}

// ExportControlRecord is the output for export/trade control lists.
type ExportControlRecord struct {
	CanonicalRecord
	ControlledItems  []string `json:"controlled_items"` // ECCNs, categories
	DestinationRules string   `json:"destination_rules"`
	LicenseRequired  bool     `json:"license_required"`
}

// --- Class 5: Security Controls ---

// ControlCatalogRecord is the output model for security framework adapters (P5).
type ControlCatalogRecord struct {
	CanonicalRecord
	ControlID      string   `json:"control_id"`                // e.g., "AC-1", "A.5.1"
	Family         string   `json:"family"`                    // e.g., "Access Control", "Policies"
	Requirements   []string `json:"requirements"`              // Specific requirements
	Mappings       []string `json:"mappings,omitempty"`        // Cross-references to other frameworks
	AutomationHint string   `json:"automation_hint,omitempty"` // How to verify automatically
}

// --- Class 6: Resilience ---

// ResilienceObligationRecord is the output model for resilience adapters (P6).
type ResilienceObligationRecord struct {
	CanonicalRecord
	RTORequirement         string   `json:"rto_requirement,omitempty"`       // Recovery Time Objective
	RPORequirement         string   `json:"rpo_requirement,omitempty"`       // Recovery Point Objective
	TestingCadence         string   `json:"testing_cadence"`                 // e.g., "annual", "biannual"
	ScenarioTypes          []string `json:"scenario_types"`                  // Required test scenarios
	SupplierRiskDuties     []string `json:"supplier_risk_duties"`            // Third-party risk requirements
	IncidentClassification string   `json:"incident_classification"`         // Classification scheme
	ReportingClockHours    int      `json:"reporting_clock_hours,omitempty"` // Hours to report
	RegulatorNotifyBody    string   `json:"regulator_notify_body"`           // Who to notify
}

// --- Class 7: Identity/Trust ---

// TrustAnchorRecord is the output model for identity/trust adapters (P7).
type TrustAnchorRecord struct {
	CanonicalRecord
	ServiceType     string    `json:"service_type"` // "qualified_esig", "qualified_seal", "timestamp"
	ProviderName    string    `json:"provider_name"`
	ProviderCountry string    `json:"provider_country"`
	CertificateHash string    `json:"certificate_hash"`
	ValidFrom       time.Time `json:"valid_from"`
	ValidTo         time.Time `json:"valid_to"`
	Qualified       bool      `json:"qualified"` // EU qualified status
}

// ValidationRuleRecord defines signature/trust validation rules.
type ValidationRuleRecord struct {
	CanonicalRecord
	RuleType           string   `json:"rule_type"`           // "signature", "timestamp", "chain"
	RequiredAlgorithms []string `json:"required_algorithms"` // e.g., ["RSA-2048", "ECDSA-P256"]
	LTVPolicy          string   `json:"ltv_policy"`          // Long-term validation policy
}

// --- Class 8: Supply Chain ---

// VulnRecord is the output model for vulnerability intelligence adapters (P8).
type VulnRecord struct {
	CanonicalRecord
	CVEID            string     `json:"cve_id"`
	CVSS3Score       float64    `json:"cvss3_score"`
	Severity         string     `json:"severity"` // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	AffectedPackages []string   `json:"affected_packages"`
	ExploitedInWild  bool       `json:"exploited_in_wild"`
	PatchAvailable   bool       `json:"patch_available"`
	RemediationDue   *time.Time `json:"remediation_due,omitempty"` // KEV deadline
}

// ProvenanceSignalRecord captures artifact provenance from transparency logs.
type ProvenanceSignalRecord struct {
	CanonicalRecord
	ArtifactDigest string `json:"artifact_digest"`
	LogIndex       int64  `json:"log_index"`
	IntegratedTime int64  `json:"integrated_time"`
	InclusionProof string `json:"inclusion_proof"`
	SignerIdentity string `json:"signer_identity,omitempty"`
}

// --- Class 9: Certification ---

// CertificationProgramRecord is the output model for certification adapters (P9).
type CertificationProgramRecord struct {
	CanonicalRecord
	ProgramName      string     `json:"program_name"` // e.g., "FedRAMP High", "CSA STAR Level 2"
	AuthorizedEntity string     `json:"authorized_entity"`
	ScopeStatement   string     `json:"scope_statement"`
	ImpactLevel      string     `json:"impact_level,omitempty"` // FedRAMP: Low/Moderate/High
	ExpirationDate   *time.Time `json:"certification_expiry,omitempty"`
	ControlMappings  []string   `json:"control_mappings"` // Which control frameworks are covered
}

// --- Class 10: Entity Registry ---

// EntityIdentityRecord is the output model for entity/registry adapters (P10).
type EntityIdentityRecord struct {
	CanonicalRecord
	LEI             string            `json:"lei,omitempty"`             // Legal Entity Identifier
	NationalRegID   string            `json:"national_reg_id,omitempty"` // Company number, etc.
	SecuritiesIDs   map[string]string `json:"securities_ids,omitempty"`  // CIK, ISIN, etc.
	EntityLegalName string            `json:"entity_legal_name"`
	EntityStatus    string            `json:"entity_status"` // "active", "inactive", "dissolved"
	RegisteredAddr  string            `json:"registered_address,omitempty"`
	OwnershipLinks  []string          `json:"ownership_links,omitempty"` // Parent/subsidiary LEIs
	FilingsLinks    []string          `json:"filings_links,omitempty"`
}
