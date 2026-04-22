// Package evidence provides the EvidencePack builder and dedicated receipt types.
// Every enforcement decision references an EvidencePack hash.
// Determinism: stable JSON canonicalization, stable artifact filenames,
// no wall-clock randomness without explicit inclusion.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// ComplianceEvidencePack is the auditable proof bundle for every compliance decision.
type ComplianceEvidencePack struct {
	PackID             string               `json:"pack_id"`
	RunID              string               `json:"run_id"`
	Timestamp          time.Time            `json:"timestamp"`
	SourceVersions     map[string]string    `json:"source_versions"` // sourceID → version/hash
	ArtifactHashes     map[string]string    `json:"artifact_hashes"` // artifact path → SHA-256
	TrustChecks        []TrustCheckResult   `json:"trust_checks"`
	NormalizationTrace []NormalizationEntry `json:"normalization_trace"`
	MappingDecisions   []MappingDecision    `json:"mapping_decisions"`
	CompilerTrace      []CompilerTraceEntry `json:"compiler_trace"`
	PolicyTrace        []PolicyTraceEntry   `json:"policy_trace"`
	EnforcementAction  string               `json:"enforcement_action"`
	Notes              string               `json:"notes,omitempty"`
}

// EvidencePack is kept for backwards compatibility within this package.
// It is an alias and does not introduce a second struct definition.
type EvidencePack = ComplianceEvidencePack

// TrustCheckResult records a trust verification outcome.
type TrustCheckResult struct {
	SourceID      string `json:"source_id"`
	CheckType     string `json:"check_type"` // "signature", "hash", "tls", "ct_inclusion"
	Passed        bool   `json:"passed"`
	Details       string `json:"details"`
	FailureAction string `json:"failure_action,omitempty"` // "escalate", "block", "warn"
}

// NormalizationEntry records a normalization decision.
type NormalizationEntry struct {
	Step       int    `json:"step"`
	SourceID   string `json:"source_id"`
	InputHash  string `json:"input_hash"`
	OutputHash string `json:"output_hash"`
	Profile    string `json:"profile"`
}

// MappingDecision records how a source mapped to an obligation/control.
type MappingDecision struct {
	SourceID     string  `json:"source_id"`
	ObligationID string  `json:"obligation_id"`
	ControlID    string  `json:"control_id,omitempty"`
	Rationale    string  `json:"rationale"`
	Confidence   float64 `json:"confidence"`
}

// CompilerTraceEntry records a step in obligations compilation.
type CompilerTraceEntry struct {
	Step      int    `json:"step"`
	Phase     string `json:"phase"` // "tier1_load", "overlay_apply", "conflict_resolve"
	ControlID string `json:"control_id,omitempty"`
	OverlayID string `json:"overlay_id,omitempty"`
	Result    string `json:"result"`
}

// PolicyTraceEntry records a step in policy evaluation.
type PolicyTraceEntry struct {
	Step      int       `json:"step"`
	Rule      string    `json:"rule"`
	Input     string    `json:"input"`
	Output    string    `json:"output"`
	Timestamp time.Time `json:"timestamp"`
}

// Builder creates EvidencePacks incrementally.
type Builder struct {
	pack *EvidencePack
}

// NewBuilder creates a new EvidencePack builder.
func NewBuilder(packID, runID string) *Builder {
	return &Builder{
		pack: &EvidencePack{
			PackID:         packID,
			RunID:          runID,
			Timestamp:      time.Now(),
			SourceVersions: make(map[string]string),
			ArtifactHashes: make(map[string]string),
		},
	}
}

// AddSourceVersion records a source version used in this decision.
func (b *Builder) AddSourceVersion(sourceID, version string) *Builder {
	b.pack.SourceVersions[sourceID] = version
	return b
}

// AddArtifactHash records a hashed artifact.
func (b *Builder) AddArtifactHash(path, hash string) *Builder {
	b.pack.ArtifactHashes[path] = hash
	return b
}

// AddTrustCheck records a trust verification result.
func (b *Builder) AddTrustCheck(result TrustCheckResult) *Builder {
	b.pack.TrustChecks = append(b.pack.TrustChecks, result)
	return b
}

// AddNormalization records a normalization step.
func (b *Builder) AddNormalization(entry NormalizationEntry) *Builder {
	b.pack.NormalizationTrace = append(b.pack.NormalizationTrace, entry)
	return b
}

// AddMapping records a mapping decision.
func (b *Builder) AddMapping(decision MappingDecision) *Builder {
	b.pack.MappingDecisions = append(b.pack.MappingDecisions, decision)
	return b
}

// AddCompilerStep records a compilation step.
func (b *Builder) AddCompilerStep(entry CompilerTraceEntry) *Builder {
	b.pack.CompilerTrace = append(b.pack.CompilerTrace, entry)
	return b
}

// AddPolicyStep records a policy evaluation step.
func (b *Builder) AddPolicyStep(entry PolicyTraceEntry) *Builder {
	b.pack.PolicyTrace = append(b.pack.PolicyTrace, entry)
	return b
}

// SetAction sets the enforcement action taken.
func (b *Builder) SetAction(action string) *Builder {
	b.pack.EnforcementAction = action
	return b
}

// Build finalizes and returns the EvidencePack.
func (b *Builder) Build() *EvidencePack {
	return b.pack
}

// Hash returns a deterministic hash of the EvidencePack.
func (ep *ComplianceEvidencePack) Hash() string {
	data, _ := canonicalJSON(ep)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// --- Dedicated Receipt Types ---

// SanctionsScreeningReceipt is the deterministic receipt for sanctions screening.
type SanctionsScreeningReceipt struct {
	ReceiptID      string            `json:"receipt_id"`
	Timestamp      time.Time         `json:"timestamp"`
	SubjectName    string            `json:"subject_name"`
	SubjectID      string            `json:"subject_id"`
	ListVersions   map[string]string `json:"list_versions"`
	MatchAlgorithm string            `json:"match_algorithm"`
	MatchScore     float64           `json:"match_score"`
	MatchResult    string            `json:"match_result"` // "NO_MATCH", "POTENTIAL_MATCH", "CONFIRMED_MATCH"
	ReviewerID     string            `json:"reviewer_id,omitempty"`
	EvidencePackID string            `json:"evidence_pack_id"`
}

// DataProtectionReceipt covers DSAR, DPIA, breach clock decisions.
type DataProtectionReceipt struct {
	ReceiptID        string     `json:"receipt_id"`
	Timestamp        time.Time  `json:"timestamp"`
	RequestType      string     `json:"request_type"` // "DSAR", "DPIA", "BREACH_NOTIFICATION"
	LawfulBasis      string     `json:"lawful_basis"`
	DataSubjectScope string     `json:"data_subject_scope"`
	ResponseDeadline time.Time  `json:"response_deadline"`
	BreachClockStart *time.Time `json:"breach_clock_start,omitempty"`
	NotificationSent bool       `json:"notification_sent"`
	SupervisoryAuth  string     `json:"supervisory_authority"`
	EvidencePackID   string     `json:"evidence_pack_id"`
}

// SupplyChainReceipt covers SBOM + vuln snapshot + provenance decisions.
type SupplyChainReceipt struct {
	ReceiptID        string          `json:"receipt_id"`
	Timestamp        time.Time       `json:"timestamp"`
	SBOMHash         string          `json:"sbom_hash"`
	VulnSnapshotHash string          `json:"vuln_snapshot_hash"`
	CriticalVulns    int             `json:"critical_vulns"`
	HighVulns        int             `json:"high_vulns"`
	KEVMatches       int             `json:"kev_matches"`
	ProvenanceChecks map[string]bool `json:"provenance_checks"` // artifact → verified
	PolicyDecision   string          `json:"policy_decision"`   // "PASS", "WARN", "BLOCK"
	EvidencePackID   string          `json:"evidence_pack_id"`
}

// IdentityTrustReceipt covers signature validation + trust anchor decisions.
type IdentityTrustReceipt struct {
	ReceiptID          string    `json:"receipt_id"`
	Timestamp          time.Time `json:"timestamp"`
	SignatureValid     bool      `json:"signature_valid"`
	SignerIdentity     string    `json:"signer_identity"`
	TrustAnchorID      string    `json:"trust_anchor_id"`
	CertificateChain   []string  `json:"certificate_chain"`
	QualifiedSignature bool      `json:"qualified_signature"`
	TimestampValid     bool      `json:"timestamp_valid"`
	LTVStatus          string    `json:"ltv_status"` // "VALID", "EXPIRED", "UNKNOWN"
	EvidencePackID     string    `json:"evidence_pack_id"`
}

// canonicalJSON produces deterministic JSON with sorted keys.
func canonicalJSON(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	// Re-marshal through a map to get sorted keys
	var m interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	return marshalSorted(m)
}

func marshalSorted(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		result := "{"
		for i, k := range keys {
			if i > 0 {
				result += ","
			}
			keyJSON, _ := json.Marshal(k)
			valJSON, _ := marshalSorted(val[k])
			result += fmt.Sprintf("%s:%s", keyJSON, valJSON)
		}
		result += "}"
		return []byte(result), nil
	default:
		return json.Marshal(v)
	}
}
