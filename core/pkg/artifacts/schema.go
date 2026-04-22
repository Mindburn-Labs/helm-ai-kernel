package artifacts

import (
	"encoding/json"
	"time"
)

// Type definitions for Evidence-based Artifacts.
const (
	TypeAlertEvidence      = "evidence/alert"
	TypePredictedReceipt   = "evidence/prediction"
	TypePolicyDraft        = "governance/policy-draft"
	TypeVerificationRecord = "evidence/verification"
	TypeVisualEvidence     = "evidence/visual"
)

// VisualEvidence (H5) - Multimodal Grounding output.
type VisualEvidence struct {
	ScreenshotHash  string `json:"screenshot_hash"`   // SHA256 of the PNG blob
	DOMSnapshotHash string `json:"dom_snapshot_hash"` // SHA256 of the HTML content
	URL             string `json:"url"`
	VPPTimestamp    int64  `json:"vpp_timestamp"` // Video presentation timestamp (ms)
	ActionID        string `json:"action_id"`     // Link to the specific action taken
}

// ArtifactEnvelope is the signed wrapper for all evidence.
type ArtifactEnvelope struct {
	Type           string          `json:"type"`             // e.g., "evidence/alert"
	SchemaVersion  string          `json:"schema_version"`   // e.g., "v1"
	ProducerID     string          `json:"producer_id"`      // e.g., "signal.controller"
	Timestamp      time.Time       `json:"timestamp"`        // RFC3339
	Payload        json.RawMessage `json:"payload"`          // The actual Typed Evidence
	Signature      string          `json:"signature"`        // Signature of (Type+Ver+Producer+Time+Payload)
	SignatureKeyID string          `json:"signature_key_id"` // ID of the key used to sign
}

// AlertEvidence (H1) - Signal Controller output.
type AlertEvidence struct {
	MetricName      string  `json:"metric_name"`
	Value           float64 `json:"value"`
	Threshold       float64 `json:"threshold"`
	Severity        string  `json:"severity"`         // INFO, WARN, CRITICAL
	ContextSnapshot string  `json:"context_snapshot"` // Hash or JSON dump
}

// PredictedReceipt (H2) - State Estimator output.
type PredictedReceipt struct {
	ObligationID       string  `json:"obligation_id"`
	EffectType         string  `json:"effect_type"`
	EstimatedDuration  string  `json:"estimated_duration"`
	SuccessProbability float64 `json:"success_probability"` // 0.0 - 1.0
	ConfidenceScore    float64 `json:"confidence_score"`    // 0.0 - 1.0
}

// PolicyDraft (H3) - Policy Inductor output.
type PolicyDraft struct {
	PolicyName         string `json:"policy_name"`
	RegoContent        string `json:"rego_content"`
	SourceHistoryRange string `json:"source_history_range"` // e.g. "ev-100 to ev-2000"
	Rationale          string `json:"rationale"`
}

// VerificationRecord (H4) - Activation Probe output.
type VerificationRecord struct {
	SubjectHash    string  `json:"subject_hash"`    // What was verified
	VerifierID     string  `json:"verifier_id"`     // Who verified it
	DeceptionScore float64 `json:"deception_score"` // 0.0 - 1.0
	IsPass         bool    `json:"is_pass"`
}
