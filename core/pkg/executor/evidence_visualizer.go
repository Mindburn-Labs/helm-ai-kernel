// Package executor provides Visual Evidence Verification.
// Inspired by Kimi K2.5's visual debugging and reasoning verification.
package executor

import (
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// VisualEvidenceConfig configures the visual evidence verifier.
type VisualEvidenceConfig struct {
	// MaxSnapshotsPerPack limits snapshots per evidence pack
	MaxSnapshotsPerPack int `json:"max_snapshots_per_pack"`

	// EnableDiffTracking tracks differences between snapshots
	EnableDiffTracking bool `json:"enable_diff_tracking"`

	// VerifyReasoningChain validates causal reasoning
	VerifyReasoningChain bool `json:"verify_reasoning_chain"`

	// MaxReasoningSteps limits reasoning chain depth
	MaxReasoningSteps int `json:"max_reasoning_steps"`
}

// VisualSnapshot represents a point-in-time visual state.
type VisualSnapshot struct {
	SnapshotID   string                 `json:"snapshot_id"`
	Timestamp    time.Time              `json:"timestamp"`
	SequenceNum  int                    `json:"sequence_num"`
	ContentType  string                 `json:"content_type"` // e.g., "state", "ui", "log"
	ContentHash  string                 `json:"content_hash"`
	Content      map[string]interface{} `json:"content,omitempty"`
	Screenshot   string                 `json:"screenshot,omitempty"` // Base64 encoded
	Annotations  []Annotation           `json:"annotations,omitempty"`
	DiffFromPrev *SnapshotDiff          `json:"diff_from_prev,omitempty"`
}

// Annotation marks a region or value in a snapshot.
type Annotation struct {
	AnnotationID string `json:"annotation_id"`
	Type         string `json:"type"` // "highlight", "arrow", "bbox", "text"
	Target       string `json:"target"`
	Description  string `json:"description"`
	Severity     string `json:"severity,omitempty"` // "info", "warning", "error"
}

// SnapshotDiff captures changes between snapshots.
type SnapshotDiff struct {
	PreviousSnapshotID string   `json:"previous_snapshot_id"`
	AddedPaths         []string `json:"added_paths,omitempty"`
	RemovedPaths       []string `json:"removed_paths,omitempty"`
	ModifiedPaths      []string `json:"modified_paths,omitempty"`
	DiffHash           string   `json:"diff_hash"`
}

// ReasoningStep represents a step in the causal chain.
type ReasoningStep struct {
	StepID         string    `json:"step_id"`
	SequenceNum    int       `json:"sequence_num"`
	Action         string    `json:"action"`
	Rationale      string    `json:"rationale"`
	InputRefs      []string  `json:"input_refs,omitempty"`  // References to evidence
	OutputRefs     []string  `json:"output_refs,omitempty"` // References to outputs
	SnapshotBefore string    `json:"snapshot_before,omitempty"`
	SnapshotAfter  string    `json:"snapshot_after,omitempty"`
	Confidence     float64   `json:"confidence,omitempty"` // 0.0-1.0
	Timestamp      time.Time `json:"timestamp"`
	DurationMs     int64     `json:"duration_ms,omitempty"`
}

// ReasoningChain represents the causal reasoning for a decision.
type ReasoningChain struct {
	ChainID      string          `json:"chain_id"`
	PackID       string          `json:"pack_id"`
	Steps        []ReasoningStep `json:"steps"`
	FinalOutcome string          `json:"final_outcome"`
	ChainHash    string          `json:"chain_hash"`
	Verified     bool            `json:"verified"`
	VerifiedAt   time.Time       `json:"verified_at,omitempty"`
}

// VisualEvidence extends EvidencePack with visual verification.
type VisualEvidence struct {
	Pack           *contracts.EvidencePack `json:"pack"`
	Snapshots      []VisualSnapshot        `json:"snapshots"`
	ReasoningChain *ReasoningChain         `json:"reasoning_chain,omitempty"`
	VisualHash     string                  `json:"visual_hash"`
	CreatedAt      time.Time               `json:"created_at"`
}

// VerificationResult contains the outcome of visual verification.
type VerificationResult struct {
	Verified        bool                `json:"verified"`
	VerificationID  string              `json:"verification_id"`
	ChecksPassed    []string            `json:"checks_passed"`
	ChecksFailed    []VerificationError `json:"checks_failed,omitempty"`
	CausalIntegrity bool                `json:"causal_integrity"`
	Timestamp       time.Time           `json:"timestamp"`
}

// VerificationError describes a failed verification check.
type VerificationError struct {
	CheckID     string `json:"check_id"`
	Type        string `json:"type"` // "missing_snapshot", "broken_chain", "hash_mismatch"
	Description string `json:"description"`
	Severity    string `json:"severity"` // "error", "warning"
}

// VisualEvidenceVerifier provides K2.5-style visual evidence verification.
type VisualEvidenceVerifier struct {
	mu      sync.RWMutex
	config  *VisualEvidenceConfig
	metrics *VisualVerifierMetric
}

// VisualVerifierMetric tracks verification statistics.
type VisualVerifierMetric struct {
	mu                      sync.RWMutex
	TotalVerifications      int     `json:"total_verifications"`
	SuccessfulVerifications int     `json:"successful_verifications"`
	FailedVerifications     int     `json:"failed_verifications"`
	AvgSnapshotsPerPack     float64 `json:"avg_snapshots_per_pack"`
	AvgReasoningSteps       float64 `json:"avg_reasoning_steps"`
	TotalSnapshotsProcessed int     `json:"total_snapshots_processed"`
}

// Helper functions
