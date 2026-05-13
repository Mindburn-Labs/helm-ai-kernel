// Package executor provides Visual Evidence Verification.
// Inspired by Kimi K2.5's visual debugging and reasoning verification.
package executor

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
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

// DefaultVisualEvidenceConfig returns production defaults.
func DefaultVisualEvidenceConfig() *VisualEvidenceConfig {
	return &VisualEvidenceConfig{
		MaxSnapshotsPerPack:  10,
		EnableDiffTracking:   true,
		VerifyReasoningChain: true,
		MaxReasoningSteps:    50,
	}
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

// NewVisualEvidenceVerifier creates a new visual verifier.
func NewVisualEvidenceVerifier(config *VisualEvidenceConfig) *VisualEvidenceVerifier {
	if config == nil {
		config = DefaultVisualEvidenceConfig()
	}

	return &VisualEvidenceVerifier{
		config:  config,
		metrics: &VisualVerifierMetric{},
	}
}

// CreateVisualEvidence wraps an EvidencePack with visual evidence.
func (v *VisualEvidenceVerifier) CreateVisualEvidence(pack *contracts.EvidencePack, snapshots []VisualSnapshot) (*VisualEvidence, error) {
	if pack == nil {
		return nil, fmt.Errorf("evidence pack is required")
	}

	if len(snapshots) > v.config.MaxSnapshotsPerPack {
		return nil, fmt.Errorf("too many snapshots: %d > %d", len(snapshots), v.config.MaxSnapshotsPerPack)
	}

	// Assign sequence numbers and compute diffs
	sortedSnapshots := make([]VisualSnapshot, len(snapshots))
	copy(sortedSnapshots, snapshots)
	sort.Slice(sortedSnapshots, func(i, j int) bool {
		return sortedSnapshots[i].Timestamp.Before(sortedSnapshots[j].Timestamp)
	})

	for i := range sortedSnapshots {
		sortedSnapshots[i].SequenceNum = i + 1
		if i > 0 && v.config.EnableDiffTracking {
			sortedSnapshots[i].DiffFromPrev = computeSnapshotDiff(&sortedSnapshots[i-1], &sortedSnapshots[i])
		}
	}

	evidence := &VisualEvidence{
		Pack:      pack,
		Snapshots: sortedSnapshots,
		CreatedAt: time.Now(),
	}

	evidence.VisualHash = computeVisualHash(evidence)

	return evidence, nil
}

// AttachReasoningChain adds a reasoning chain to visual evidence.
func (v *VisualEvidenceVerifier) AttachReasoningChain(evidence *VisualEvidence, steps []ReasoningStep) (*ReasoningChain, error) {
	if len(steps) > v.config.MaxReasoningSteps {
		return nil, fmt.Errorf("too many reasoning steps: %d > %d", len(steps), v.config.MaxReasoningSteps)
	}

	// Sort and assign sequence numbers
	sortedSteps := make([]ReasoningStep, len(steps))
	copy(sortedSteps, steps)
	sort.Slice(sortedSteps, func(i, j int) bool {
		return sortedSteps[i].Timestamp.Before(sortedSteps[j].Timestamp)
	})

	for i := range sortedSteps {
		sortedSteps[i].SequenceNum = i + 1
	}

	chain := &ReasoningChain{
		ChainID: fmt.Sprintf("chain-%s", evidence.Pack.PackID),
		PackID:  evidence.Pack.PackID,
		Steps:   sortedSteps,
	}

	if len(sortedSteps) > 0 {
		chain.FinalOutcome = sortedSteps[len(sortedSteps)-1].Action
	}

	chain.ChainHash = computeChainHash(chain)
	evidence.ReasoningChain = chain

	return chain, nil
}

// Verify performs comprehensive visual verification.
func (v *VisualEvidenceVerifier) Verify(ctx context.Context, evidence *VisualEvidence) (*VerificationResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	result := &VerificationResult{
		VerificationID: fmt.Sprintf("verify-%s-%d", evidence.Pack.PackID, time.Now().UnixNano()),
		ChecksPassed:   make([]string, 0),
		ChecksFailed:   make([]VerificationError, 0),
		Timestamp:      time.Now(),
	}

	// Check 1: Visual hash integrity
	expectedHash := computeVisualHash(evidence)
	if expectedHash == evidence.VisualHash {
		result.ChecksPassed = append(result.ChecksPassed, "visual_hash_integrity")
	} else {
		result.ChecksFailed = append(result.ChecksFailed, VerificationError{
			CheckID:     "visual_hash_integrity",
			Type:        "hash_mismatch",
			Description: "visual hash does not match computed hash",
			Severity:    "error",
		})
	}

	// Check 2: Snapshot sequence integrity
	if v.verifySnapshotSequence(evidence.Snapshots) {
		result.ChecksPassed = append(result.ChecksPassed, "snapshot_sequence")
	} else {
		result.ChecksFailed = append(result.ChecksFailed, VerificationError{
			CheckID:     "snapshot_sequence",
			Type:        "broken_chain",
			Description: "snapshot sequence numbers are not contiguous",
			Severity:    "error",
		})
	}

	// Check 3: Snapshot content hashes
	if v.verifySnapshotHashes(evidence.Snapshots) {
		result.ChecksPassed = append(result.ChecksPassed, "snapshot_content_hashes")
	} else {
		result.ChecksFailed = append(result.ChecksFailed, VerificationError{
			CheckID:     "snapshot_content_hashes",
			Type:        "hash_mismatch",
			Description: "one or more snapshot content hashes do not match",
			Severity:    "error",
		})
	}

	// Check 4: Reasoning chain integrity (if present)
	if evidence.ReasoningChain != nil && v.config.VerifyReasoningChain {
		if v.verifyReasoningChain(evidence.ReasoningChain, evidence.Snapshots) {
			result.ChecksPassed = append(result.ChecksPassed, "reasoning_chain")
			result.CausalIntegrity = true
		} else {
			result.ChecksFailed = append(result.ChecksFailed, VerificationError{
				CheckID:     "reasoning_chain",
				Type:        "broken_chain",
				Description: "reasoning chain has invalid references or missing links",
				Severity:    "warning",
			})
		}
	}

	// Check 5: Diff chain integrity
	if v.config.EnableDiffTracking && len(evidence.Snapshots) > 1 {
		if v.verifyDiffChain(evidence.Snapshots) {
			result.ChecksPassed = append(result.ChecksPassed, "diff_chain")
		} else {
			result.ChecksFailed = append(result.ChecksFailed, VerificationError{
				CheckID:     "diff_chain",
				Type:        "broken_chain",
				Description: "diff chain references are inconsistent",
				Severity:    "warning",
			})
		}
	}

	// Overall verdict
	hasErrors := false
	for _, err := range result.ChecksFailed {
		if err.Severity == "error" {
			hasErrors = true
			break
		}
	}
	result.Verified = !hasErrors && len(result.ChecksPassed) > 0

	// Update metrics
	v.updateMetrics(evidence, result)

	return result, nil
}

// verifySnapshotSequence checks that sequence numbers are contiguous.
func (v *VisualEvidenceVerifier) verifySnapshotSequence(snapshots []VisualSnapshot) bool {
	for i, snap := range snapshots {
		if snap.SequenceNum != i+1 {
			return false
		}
	}
	return true
}

// verifySnapshotHashes verifies content hashes match computed values.
func (v *VisualEvidenceVerifier) verifySnapshotHashes(snapshots []VisualSnapshot) bool {
	for _, snap := range snapshots {
		if snap.Content != nil {
			computed := computeContentHash(snap.Content)
			if computed != snap.ContentHash {
				return false
			}
		}
	}
	return true
}

// verifyReasoningChain validates causal integrity.
func (v *VisualEvidenceVerifier) verifyReasoningChain(chain *ReasoningChain, snapshots []VisualSnapshot) bool {
	if len(chain.Steps) == 0 {
		return true // Empty chain is valid
	}

	snapshotMap := make(map[string]bool)
	for _, snap := range snapshots {
		snapshotMap[snap.SnapshotID] = true
	}

	// Verify snapshot references
	for _, step := range chain.Steps {
		if step.SnapshotBefore != "" && !snapshotMap[step.SnapshotBefore] {
			return false
		}
		if step.SnapshotAfter != "" && !snapshotMap[step.SnapshotAfter] {
			return false
		}
	}

	// Verify step sequence
	for i, step := range chain.Steps {
		if step.SequenceNum != i+1 {
			return false
		}
	}

	// Verify chain hash
	computedHash := computeChainHash(chain)
	return computedHash == chain.ChainHash
}

// verifyDiffChain validates diff references.
func (v *VisualEvidenceVerifier) verifyDiffChain(snapshots []VisualSnapshot) bool {
	for i := 1; i < len(snapshots); i++ {
		if snapshots[i].DiffFromPrev == nil {
			continue
		}
		if snapshots[i].DiffFromPrev.PreviousSnapshotID != snapshots[i-1].SnapshotID {
			return false
		}
	}
	return true
}

// updateMetrics updates verification statistics.
func (v *VisualEvidenceVerifier) updateMetrics(evidence *VisualEvidence, result *VerificationResult) {
	v.metrics.mu.Lock()
	defer v.metrics.mu.Unlock()

	v.metrics.TotalVerifications++
	v.metrics.TotalSnapshotsProcessed += len(evidence.Snapshots)

	if result.Verified {
		v.metrics.SuccessfulVerifications++
	} else {
		v.metrics.FailedVerifications++
	}

	// Update averages
	if v.metrics.TotalVerifications > 0 {
		v.metrics.AvgSnapshotsPerPack = float64(v.metrics.TotalSnapshotsProcessed) / float64(v.metrics.TotalVerifications)
	}

	if evidence.ReasoningChain != nil {
		steps := len(evidence.ReasoningChain.Steps)
		// Simple running average
		v.metrics.AvgReasoningSteps = (v.metrics.AvgReasoningSteps*float64(v.metrics.TotalVerifications-1) + float64(steps)) / float64(v.metrics.TotalVerifications)
	}
}

// GetMetrics returns verification statistics.
func (v *VisualEvidenceVerifier) GetMetrics() *VisualVerifierMetric {
	return v.metrics
}

// Helper functions

func computeSnapshotDiff(prev, curr *VisualSnapshot) *SnapshotDiff {
	diff := &SnapshotDiff{
		PreviousSnapshotID: prev.SnapshotID,
		AddedPaths:         make([]string, 0),
		RemovedPaths:       make([]string, 0),
		ModifiedPaths:      make([]string, 0),
	}

	if prev.Content == nil || curr.Content == nil {
		diff.DiffHash = computeContentHash(map[string]interface{}{"empty": true})
		return diff
	}

	prevPaths := flattenPaths(prev.Content, "")
	currPaths := flattenPaths(curr.Content, "")

	// Find added
	for path := range currPaths {
		if _, exists := prevPaths[path]; !exists {
			diff.AddedPaths = append(diff.AddedPaths, path)
		}
	}

	// Find removed
	for path := range prevPaths {
		if _, exists := currPaths[path]; !exists {
			diff.RemovedPaths = append(diff.RemovedPaths, path)
		}
	}

	// Find modified
	for path, currVal := range currPaths {
		if prevVal, exists := prevPaths[path]; exists && prevVal != currVal {
			diff.ModifiedPaths = append(diff.ModifiedPaths, path)
		}
	}

	sort.Strings(diff.AddedPaths)
	sort.Strings(diff.RemovedPaths)
	sort.Strings(diff.ModifiedPaths)

	diffData, err := json.Marshal(diff)
	if err != nil {
		diff.DiffHash = "marshal-error"
		return diff
	}
	h := sha256.Sum256(diffData)
	diff.DiffHash = hex.EncodeToString(h[:])[:16]

	return diff
}

func flattenPaths(m map[string]interface{}, prefix string) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]interface{}:
			for p, pv := range flattenPaths(val, path) {
				result[p] = pv
			}
		default:
			result[path] = fmt.Sprintf("%v", val)
		}
	}
	return result
}

func computeVisualHash(evidence *VisualEvidence) string {
	data, err := json.Marshal(struct {
		PackID    string
		Snapshots []VisualSnapshot
	}{
		PackID:    evidence.Pack.PackID,
		Snapshots: evidence.Snapshots,
	})
	if err != nil {
		return "marshal-error"
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func computeChainHash(chain *ReasoningChain) string {
	data, err := json.Marshal(struct {
		ChainID string
		PackID  string
		Steps   []ReasoningStep
	}{
		ChainID: chain.ChainID,
		PackID:  chain.PackID,
		Steps:   chain.Steps,
	})
	if err != nil {
		return "marshal-error"
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func computeContentHash(content map[string]interface{}) string {
	data, err := json.Marshal(content)
	if err != nil {
		return "marshal-error"
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// EncodeScreenshot encodes binary data as base64 for snapshot storage.
func EncodeScreenshot(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeScreenshot decodes base64 screenshot data.
func DecodeScreenshot(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
