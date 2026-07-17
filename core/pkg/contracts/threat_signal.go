// Package contracts — threat_signal.go defines canonical threat-signal types.
//
// These types form the canonical contract between the threat scanning
// subsystem and the HELM enforcement kernel (Guardian/PDP). Findings
// are informational signals — they do NOT carry final verdicts. The
// Guardian and PDP remain the sole policy authorities.
//
// Per HELM Standard v1.2: all typed contracts live in this package to
// prevent dual-truth registries.
package contracts

import "time"

// ────────────────────────────────────────────────────────────────
// Threat Classification Enums
// ────────────────────────────────────────────────────────────────

// ThreatClass categorizes the family of a detected threat signal.
type ThreatClass string

const (
	ThreatClassPromptInjection    ThreatClass = "PROMPT_INJECTION_PATTERN"
	ThreatClassCommandExecution   ThreatClass = "COMMAND_EXECUTION_PATTERN"
	ThreatClassUnicodeObfuscation ThreatClass = "UNICODE_OBFUSCATION_PATTERN"
	ThreatClassSocialEngineering  ThreatClass = "SOCIAL_ENGINEERING_PATTERN"
	ThreatClassEncodingEvasion    ThreatClass = "ENCODING_EVASION_PATTERN"
	ThreatClassSuspiciousFetch    ThreatClass = "SUSPICIOUS_EXTERNAL_FETCH_PATTERN"
	ThreatClassCredentialExposure ThreatClass = "CREDENTIAL_EXPOSURE_PATTERN"
	ThreatClassSoftwarePublish    ThreatClass = "SOFTWARE_PUBLISH_PATTERN"

	// Phase G: expanded detection vectors for prompt defense hardening
	ThreatClassPrivilegeEscalation ThreatClass = "PRIVILEGE_ESCALATION_PATTERN"
	ThreatClassDataExfiltration    ThreatClass = "DATA_EXFILTRATION_PATTERN"
	ThreatClassModelManipulation   ThreatClass = "MODEL_MANIPULATION_PATTERN"
	ThreatClassContextAbuse        ThreatClass = "CONTEXT_ABUSE_PATTERN"
	ThreatClassIndirectInjection   ThreatClass = "INDIRECT_INJECTION_PATTERN"

	// ThreatClassSemanticSimilarity is an advisory similarity signal. It is
	// intentionally INFO-only and must never be treated as direct DENY authority.
	ThreatClassSemanticSimilarity ThreatClass = "SEMANTIC_SIMILARITY_PATTERN"
)

// ThreatSeverity grades the confidence/impact of a finding.
type ThreatSeverity string

const (
	ThreatSeverityInfo     ThreatSeverity = "INFO"
	ThreatSeverityLow      ThreatSeverity = "LOW"
	ThreatSeverityMedium   ThreatSeverity = "MEDIUM"
	ThreatSeverityHigh     ThreatSeverity = "HIGH"
	ThreatSeverityCritical ThreatSeverity = "CRITICAL"
)

// InputTrustLevel classifies the provenance trust of an input channel.
type InputTrustLevel string

const (
	InputTrustTrusted            InputTrustLevel = "TRUSTED"
	InputTrustInternalUnverified InputTrustLevel = "INTERNAL_UNVERIFIED"
	InputTrustExternalUntrusted  InputTrustLevel = "EXTERNAL_UNTRUSTED"
	InputTrustTainted            InputTrustLevel = "TAINTED"
)

// SourceChannel identifies the origin system of untrusted input.
type SourceChannel string

const (
	SourceChannelGitHubIssue   SourceChannel = "GITHUB_ISSUE"
	SourceChannelGitHubPR      SourceChannel = "GITHUB_PR_COMMENT"
	SourceChannelGitHubWebhook SourceChannel = "GITHUB_WEBHOOK"
	SourceChannelToolOutput    SourceChannel = "TOOL_OUTPUT"
	SourceChannelChatUser      SourceChannel = "CHAT_USER"
	SourceChannelMCPClient     SourceChannel = "MCP_CLIENT"
	SourceChannelAPIRequest    SourceChannel = "API_REQUEST"
	SourceChannelExternalAgent SourceChannel = "EXTERNAL_AGENT"
	SourceChannelUnknown       SourceChannel = "UNKNOWN"
)

// ────────────────────────────────────────────────────────────────
// Threat Finding
// ────────────────────────────────────────────────────────────────

// ThreatFinding represents a single detected signal within scanned input.
// Findings are informational — they do not carry allow/deny semantics.
//
//nolint:govet // fieldalignment: struct layout matches JSON display order
type ThreatFinding struct {
	Class         ThreatClass    `json:"class"`
	Severity      ThreatSeverity `json:"severity"`
	RuleID        string         `json:"rule_id"`
	SourceChannel SourceChannel  `json:"source_channel"`
	SourceRef     string         `json:"source_ref,omitempty"`

	// Matched content evidence
	MatchedSpans  []MatchedSpan `json:"matched_spans,omitempty"`
	MatchedTokens []string      `json:"matched_tokens,omitempty"`

	// Hash evidence
	NormalizedInputHash string `json:"normalized_input_hash"`
	RawInputHash        string `json:"raw_input_hash"`

	// Metadata
	Notes    string         `json:"notes,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// MatchedSpan records an exact byte range of matched content.
type MatchedSpan struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Text  string `json:"text"`
}

// ────────────────────────────────────────────────────────────────
// Threat Scan Result
// ────────────────────────────────────────────────────────────────

// ThreatScanResult is the complete output of a deterministic threat scan.
// It aggregates all findings and normalization evidence for a single input.
//
//nolint:govet // fieldalignment: struct layout matches JSON display order
type ThreatScanResult struct {
	// Scan metadata
	ScanID    string    `json:"scan_id"`
	Timestamp time.Time `json:"timestamp"`

	// Input provenance
	SourceChannel SourceChannel   `json:"source_channel"`
	TrustLevel    InputTrustLevel `json:"trust_level"`

	// Aggregate assessment (informational, not a verdict)
	MaxSeverity  ThreatSeverity `json:"max_severity"`
	FindingCount int            `json:"finding_count"`

	// All findings
	Findings []ThreatFinding `json:"findings"`

	// Normalization evidence
	Normalization *NormalizationEvidence `json:"normalization,omitempty"`

	// Content hashes for evidence/replay binding
	RawInputHash        string `json:"raw_input_hash"`
	NormalizedInputHash string `json:"normalized_input_hash"`

	// Semantic is the deterministic advisory classifier assessment. It is
	// present even when the classifier is unavailable so evidence never turns
	// a missing or mismatched model into silent success.
	Semantic *SemanticThreatAssessment `json:"semantic,omitempty"`
}

// SemanticThreatAssessment binds deterministic advisory similarity evidence.
// Scores are integer cosine similarity in basis points (0..10000).
//
//nolint:govet // fieldalignment: struct layout matches JSON display order
type SemanticThreatAssessment struct {
	Available         bool   `json:"available"`
	ModelVersion      string `json:"model_version,omitempty"`
	ModelHash         string `json:"model_hash,omitempty"`
	ExpectedModelHash string `json:"expected_model_hash,omitempty"`
	FailureReason     string `json:"failure_reason,omitempty"`
	ThresholdBP       int    `json:"threshold_bp"`
	MaxBP             int    `json:"max_bp"`
	NearestClass      string `json:"nearest_class,omitempty"`
	Flagged           bool   `json:"flagged"`
	InputTruncated    bool   `json:"input_truncated,omitempty"`
}

// NormalizationEvidence records how Unicode normalization transformed the input.
type NormalizationEvidence struct {
	OriginalLength    int      `json:"original_length"`
	NormalizedLength  int      `json:"normalized_length"`
	LengthDelta       int      `json:"length_delta"`
	ZeroWidthsRemoved int      `json:"zero_widths_removed"`
	HomoglyphsFound   int      `json:"homoglyphs_found"`
	NFKCApplied       bool     `json:"nfkc_applied"`
	SuspiciousChars   []string `json:"suspicious_chars,omitempty"`
}

// ────────────────────────────────────────────────────────────────
// Severity Comparison
// ────────────────────────────────────────────────────────────────

// severityOrder maps ThreatSeverity to a numerical order for comparison.
var severityOrder = map[ThreatSeverity]int{
	ThreatSeverityInfo:     0,
	ThreatSeverityLow:      1,
	ThreatSeverityMedium:   2,
	ThreatSeverityHigh:     3,
	ThreatSeverityCritical: 4,
}

// SeverityAtLeast returns true if severity is >= threshold.
func SeverityAtLeast(severity, threshold ThreatSeverity) bool {
	return severityOrder[severity] >= severityOrder[threshold]
}

// MaxSeverityOf returns the highest severity from a list of findings.
func MaxSeverityOf(findings []ThreatFinding) ThreatSeverity {
	max := ThreatSeverityInfo
	for _, f := range findings {
		if severityOrder[f.Severity] > severityOrder[max] {
			max = f.Severity
		}
	}
	return max
}

// ────────────────────────────────────────────────────────────────
// Trust Level Helpers
// ────────────────────────────────────────────────────────────────

// IsTainted returns true if the trust level is TAINTED or EXTERNAL_UNTRUSTED.
func (t InputTrustLevel) IsTainted() bool {
	return t == InputTrustTainted || t == InputTrustExternalUntrusted
}

// ────────────────────────────────────────────────────────────────
// EvidencePack Reference
// ────────────────────────────────────────────────────────────────

// ThreatScanRef is a lightweight reference to a ThreatScanResult for
// embedding in EvidencePacks and Receipts without duplicating the full result.
type ThreatScanRef struct {
	ScanID       string                    `json:"scan_id"`
	MaxSeverity  ThreatSeverity            `json:"max_severity"`
	FindingCount int                       `json:"finding_count"`
	TrustLevel   InputTrustLevel           `json:"trust_level"`
	InputHash    string                    `json:"input_hash"`
	Semantic     *SemanticThreatAssessment `json:"semantic,omitempty"`
}

// Ref produces a ThreatScanRef from a ThreatScanResult.
func (r *ThreatScanResult) Ref() ThreatScanRef {
	var semantic *SemanticThreatAssessment
	if r.Semantic != nil {
		copy := *r.Semantic
		semantic = &copy
	}
	return ThreatScanRef{
		ScanID:       r.ScanID,
		MaxSeverity:  r.MaxSeverity,
		FindingCount: r.FindingCount,
		TrustLevel:   r.TrustLevel,
		InputHash:    r.RawInputHash,
		Semantic:     semantic,
	}
}

// PolicyContext returns a CEL-compatible representation of trusted scan
// evidence. Semantic fields are flattened under threat_scan so policy authors
// can use stable expressions such as threat_scan.semantic_max_bp >= 7000.
func (r ThreatScanRef) PolicyContext() map[string]any {
	context := map[string]any{
		"scan_id":       r.ScanID,
		"max_severity":  string(r.MaxSeverity),
		"finding_count": r.FindingCount,
		"trust_level":   string(r.TrustLevel),
		"input_hash":    r.InputHash,
	}
	if r.Semantic == nil {
		return context
	}
	semantic := map[string]any{
		"available":           r.Semantic.Available,
		"model_version":       r.Semantic.ModelVersion,
		"model_hash":          r.Semantic.ModelHash,
		"expected_model_hash": r.Semantic.ExpectedModelHash,
		"failure_reason":      r.Semantic.FailureReason,
		"threshold_bp":        r.Semantic.ThresholdBP,
		"max_bp":              r.Semantic.MaxBP,
		"nearest_class":       r.Semantic.NearestClass,
		"flagged":             r.Semantic.Flagged,
		"input_truncated":     r.Semantic.InputTruncated,
	}
	context["semantic"] = semantic
	context["semantic_available"] = r.Semantic.Available
	context["semantic_model_version"] = r.Semantic.ModelVersion
	context["semantic_model_hash"] = r.Semantic.ModelHash
	context["semantic_expected_model_hash"] = r.Semantic.ExpectedModelHash
	context["semantic_failure_reason"] = r.Semantic.FailureReason
	context["semantic_threshold_bp"] = r.Semantic.ThresholdBP
	context["semantic_max_bp"] = r.Semantic.MaxBP
	context["semantic_nearest_class"] = r.Semantic.NearestClass
	context["semantic_flagged"] = r.Semantic.Flagged
	context["semantic_input_truncated"] = r.Semantic.InputTruncated
	return context
}
