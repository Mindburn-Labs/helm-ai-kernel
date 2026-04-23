// Package csr implements the Compliance Source Registry (CSR) — a first-class
// product surface that defines every compliance source connector HELM integrates.
// It provides canonical source definitions, trust models, evidence packs, and
// screening receipts per the CSR specification.
package csr

import (
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// SourceClass identifies the compliance domain a source belongs to.
type SourceClass string

const (
	ClassLaw              SourceClass = "LAW"               // Primary law and regulatory publication feeds
	ClassPrivacy          SourceClass = "PRIVACY"           // Data protection and privacy authorities
	ClassAIGovernance     SourceClass = "AI_GOVERNANCE"     // AI governance and algorithmic accountability
	ClassSanctions        SourceClass = "SANCTIONS"         // Financial crime, sanctions, export controls
	ClassSecurityControls SourceClass = "SECURITY_CONTROLS" // Security control catalogs and compliance frameworks
	ClassResilience       SourceClass = "RESILIENCE"        // Critical infrastructure and operational resilience
	ClassIdentityTrust    SourceClass = "IDENTITY_TRUST"    // Identity, trust, e-signature, and verification
	ClassSupplyChain      SourceClass = "SUPPLY_CHAIN"      // Software supply chain and vulnerability intelligence
	ClassCertification    SourceClass = "CERTIFICATION"     // Certification and assurance registries
	ClassEntityRegistry   SourceClass = "ENTITY_REGISTRY"   // Legal entity, corporate registry, and ownership
)

// AllSourceClasses returns every defined source class.
func AllSourceClasses() []SourceClass {
	return []SourceClass{
		ClassLaw, ClassPrivacy, ClassAIGovernance, ClassSanctions,
		ClassSecurityControls, ClassResilience, ClassIdentityTrust,
		ClassSupplyChain, ClassCertification, ClassEntityRegistry,
	}
}

// FetchMethod identifies how HELM retrieves data from a compliance source.
type FetchMethod string

const (
	FetchREST               FetchMethod = "REST"
	FetchSOAP               FetchMethod = "SOAP"
	FetchRSS                FetchMethod = "RSS"
	FetchSPARQL             FetchMethod = "SPARQL"
	FetchHTMLScrape         FetchMethod = "HTML_SCRAPE"
	FetchStructuredDownload FetchMethod = "STRUCTURED_DOWNLOAD"
	FetchGraphQL            FetchMethod = "GRAPHQL"
	FetchManualImport       FetchMethod = "MANUAL_IMPORT" // Paywalled standards (ISO), manually uploaded
	FetchPortalExport       FetchMethod = "PORTAL_EXPORT" // Vendor portals / gated registries
)

// AuthType identifies the authentication mechanism for a compliance source.
type AuthType string

const (
	AuthNone        AuthType = "NONE"
	AuthAPIKey      AuthType = "API_KEY"
	AuthOAuth2      AuthType = "OAUTH2"
	AuthBasic       AuthType = "BASIC"
	AuthCertificate AuthType = "CERTIFICATE"
)

// TrustModel defines the verification and integrity constraints for a source.
type TrustModel struct {
	RequireTLS       bool   `json:"require_tls"`                // Enforce TLS for all fetches
	TLSMinVersion    string `json:"tls_min_version,omitempty"`  // Minimum TLS version ("1.2", "1.3")
	TLSPinning       bool   `json:"tls_pinning"`                // Pin TLS certificates
	RequireSignature bool   `json:"require_signature"`          // Verify cryptographic signatures on retrieved content
	SignatureFormat  string `json:"signature_format,omitempty"` // "xmldsig", "vendor-json-signature", "jws", etc.
	HashChain        string `json:"hash_chain"`                 // Hash chain scheme: "sha256+rfc8785-json", "sha256", etc.
	TimestampPolicy  string `json:"timestamp_policy"`           // "rfc3161", "http-date", "internal", "source-provided"
	TransparencyLog  string `json:"transparency_log,omitempty"` // "rekor", "ct", etc. if applicable

	// Legacy fields (kept for backward compatibility with existing tests)
	SignatureCheck   bool   `json:"signature_check,omitempty"`
	TLSPinningPolicy string `json:"tls_pinning_policy,omitempty"`
	HashChainPolicy  string `json:"hash_chain_policy,omitempty"`
}

// NormalizationMapping defines how source data maps into HELM's obligations schema.
type NormalizationMapping struct {
	ObligationSchema string            `json:"obligation_schema"`         // Target schema identifier
	ControlSchema    string            `json:"control_schema"`            // Target control framework
	FieldMappings    map[string]string `json:"field_mappings,omitempty"`  // Source field → HELM field
	Transformations  []string          `json:"transformations,omitempty"` // Ordered transform pipeline
}

// EvidenceEmissionRules defines what gets stamped into receipts for a source.
type EvidenceEmissionRules struct {
	EmitSourceVersion       bool `json:"emit_source_version"`
	EmitContentHash         bool `json:"emit_content_hash"`
	EmitRetrievalTime       bool `json:"emit_retrieval_time"`
	EmitSignatureProof      bool `json:"emit_signature_proof"`
	EmitAmendmentsChain     bool `json:"emit_amendments_chain"`
	EmitValidationArtifacts bool `json:"emit_validation_artifacts"`
}

// ComplianceSource defines a canonical compliance data source in the CSR.
type ComplianceSource struct {
	// Identity
	SourceID    string `json:"source_id"`   // Globally unique identifier (e.g., "eu-eurlex")
	Name        string `json:"name"`        // Human-readable name
	Description string `json:"description"` // What this source provides

	// Classification
	Class        SourceClass          `json:"class"`        // Compliance domain
	SourceType   string               `json:"source_type"`  // Sub-type within class (e.g., "gazette", "sanctions_list", "standard")
	Jurisdiction jkg.JurisdictionCode `json:"jurisdiction"` // Primary jurisdiction scope
	Authority    jkg.RegulatorID      `json:"authority"`    // Authoritative body (e.g., "EU-OP", "US-OFAC")
	Binding      Bindingness          `json:"bindingness"`  // LAW, REGULATION, GUIDANCE, STANDARD, ADVISORY

	// Fetch configuration
	FetchMethod       FetchMethod `json:"fetch_method"`
	EndpointURL       string      `json:"endpoint_url"`
	AuthType          AuthType    `json:"auth_type"`
	RateLimitRPS      int         `json:"rate_limit_rps,omitempty"` // Requests per second limit
	Notes             string      `json:"notes,omitempty"`          // Adapter-specific notes (e.g., parsing strategy)
	FetchPolicyConfig FetchPolicy `json:"fetch_policy"`             // Full fetch contract from contracts.go

	// Trust and integrity
	Trust TrustModel `json:"trust"`

	// Normalization
	Normalization NormalizationMapping `json:"normalization"`
	NormProfile   NormalizationProfile `json:"norm_profile,omitempty"` // Full normalization contract from contracts.go

	// Cadence and lifecycle
	UpdateCadence        string         `json:"update_cadence"`          // Cron expression or descriptor: "realtime", "daily", "weekly"
	TTL                  time.Duration  `json:"ttl"`                     // Max age before content is considered stale
	ChangeDetection      string         `json:"change_detection"`        // "hash", "etag", "last-modified", "sequence"
	ChangeDetectorConfig ChangeDetector `json:"change_detector"`         // Full change detection contract from contracts.go
	RollbackPlan         string         `json:"rollback_plan,omitempty"` // How to revert to prior version

	// Evidence
	EvidenceRules EvidenceEmissionRules `json:"evidence_rules"`

	// Metadata
	Provenance  string    `json:"provenance"` // Authoritative provenance statement
	LastUpdated time.Time `json:"last_updated"`
	CreatedAt   time.Time `json:"created_at"`
}

// CSREvidencePack is the proof-first output of every compliance decision.
// Every screening, evaluation, or mapping decision yields a CSREvidencePack
// containing full provenance and audit trail.
type CSREvidencePack struct {
	PackID            string             `json:"pack_id"`
	Timestamp         time.Time          `json:"timestamp"`
	SourceVersions    map[string]string  `json:"source_versions"`       // sourceID → version/hash
	ArtifactHashes    map[string]string  `json:"artifact_hashes"`       // artifact path → SHA-256 hash
	MappingDecisions  []MappingDecision  `json:"mapping_decisions"`     // How sources mapped to obligations
	PolicyTrace       []PolicyTraceEntry `json:"policy_trace"`          // Step-by-step policy evaluation
	EnforcementAction string             `json:"enforcement_action"`    // Resulting action taken
	ReviewerID        string             `json:"reviewer_id,omitempty"` // Human reviewer if escalated
	EscalationTrail   []EscalationEntry  `json:"escalation_trail,omitempty"`
}

// EvidencePack is kept for backwards compatibility within this package.
// It is an alias and does not introduce a second struct definition.
type EvidencePack = CSREvidencePack

// MappingDecision records how a source artifact was mapped to an obligation/control.
type MappingDecision struct {
	SourceID     string  `json:"source_id"`
	ObligationID string  `json:"obligation_id"`
	ControlID    string  `json:"control_id,omitempty"`
	Rationale    string  `json:"rationale"`
	Confidence   float64 `json:"confidence"` // 0.0 – 1.0
}

// PolicyTraceEntry records a single step in the policy evaluation.
type PolicyTraceEntry struct {
	Step      int       `json:"step"`
	Rule      string    `json:"rule"`
	Input     string    `json:"input"`
	Output    string    `json:"output"`
	Timestamp time.Time `json:"timestamp"`
}

// EscalationEntry records an escalation in the decision chain.
type EscalationEntry struct {
	Level       int       `json:"level"`
	Reason      string    `json:"reason"`
	EscalatedTo string    `json:"escalated_to"`
	Timestamp   time.Time `json:"timestamp"`
}

// ScreeningReceipt is the deterministic output of a sanctions/AML screening decision.
// Every screening decision produces this receipt including list versions, match logic,
// and reviewer/escalation trails.
type ScreeningReceipt struct {
	ReceiptID       string            `json:"receipt_id"`
	Timestamp       time.Time         `json:"timestamp"`
	SubjectName     string            `json:"subject_name"`
	SubjectID       string            `json:"subject_id"`
	ListVersions    map[string]string `json:"list_versions"` // list name → version/date
	MatchLogic      string            `json:"match_logic"`   // Algorithm used (exact, fuzzy, phonetic)
	MatchScore      float64           `json:"match_score"`   // 0.0 – 1.0
	MatchResult     string            `json:"match_result"`  // "NO_MATCH", "POTENTIAL_MATCH", "CONFIRMED_MATCH"
	ReviewerID      string            `json:"reviewer_id,omitempty"`
	EscalationTrail []EscalationEntry `json:"escalation_trail,omitempty"`
	EvidencePackID  string            `json:"evidence_pack_id"`
}

// LegalSourceRecord stores per-document provenance as required for legal sources.
// What HELM must store per legal source: document identifier, effective dates,
// amendments chain, hash of retrieved content, retrieval method, and validation artifacts.
type LegalSourceRecord struct {
	DocumentID       string               `json:"document_id"`
	Title            string               `json:"title"`
	EffectiveDate    time.Time            `json:"effective_date"`
	ExpirationDate   *time.Time           `json:"expiration_date,omitempty"`
	AmendmentsChain  []string             `json:"amendments_chain"` // Ordered list of amendment document IDs
	ContentHash      string               `json:"content_hash"`     // SHA-256 of retrieved content
	RetrievalMethod  string               `json:"retrieval_method"` // How it was fetched
	RetrievedAt      time.Time            `json:"retrieved_at"`
	ValidatedAt      time.Time            `json:"validated_at"`
	SignaturePresent bool                 `json:"signature_present"`
	SignatureValid   bool                 `json:"signature_valid"`
	SourceID         string               `json:"source_id"` // CSR source reference
	JurisdictionCode jkg.JurisdictionCode `json:"jurisdiction_code"`
}
