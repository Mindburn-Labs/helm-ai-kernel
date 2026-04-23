// Package kernel — NondeterminismBound.
//
// Per HELM 2030 Spec §1.1:
//
//	Any unavoidable nondeterminism is explicitly captured, bound, and receipted.
//	Examples: LLM outputs, network timing, random seeds, external API responses.
package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// NondeterminismSource identifies the origin of nondeterminism.
type NondeterminismSource string

const (
	NDSourceLLM       NondeterminismSource = "LLM"
	NDSourceNetwork   NondeterminismSource = "NETWORK"
	NDSourceRandom    NondeterminismSource = "RANDOM"
	NDSourceExternal  NondeterminismSource = "EXTERNAL_API"
	NDSourceTiming    NondeterminismSource = "TIMING"
	NDSourceUserInput NondeterminismSource = "USER_INPUT"
)

// NondeterminismBound captures a single nondeterministic event with its binding.
type NondeterminismBound struct {
	BoundID     string               `json:"bound_id"`
	RunID       string               `json:"run_id"`
	Source      NondeterminismSource `json:"source"`
	Description string               `json:"description"`
	InputHash   string               `json:"input_hash"`  // hash of what went in
	OutputHash  string               `json:"output_hash"` // hash of what came out
	Seed        string               `json:"seed,omitempty"`
	CapturedAt  time.Time            `json:"captured_at"`
	ContentHash string               `json:"content_hash"`
}

// NondeterminismReceipt aggregates all nondeterminism for a run.
type NondeterminismReceipt struct {
	ReceiptID   string                `json:"receipt_id"`
	RunID       string                `json:"run_id"`
	Bounds      []NondeterminismBound `json:"bounds"`
	TotalBounds int                   `json:"total_bounds"`
	ContentHash string                `json:"content_hash"`
}

// NondeterminismTracker tracks and receipts nondeterminism per run.
type NondeterminismTracker struct {
	mu    sync.Mutex
	byRun map[string][]NondeterminismBound
	seq   int64
	clock func() time.Time
}

// NewNondeterminismTracker creates a new tracker.
func NewNondeterminismTracker() *NondeterminismTracker {
	return &NondeterminismTracker{
		byRun: make(map[string][]NondeterminismBound),
		clock: time.Now,
	}
}

// WithClock overrides clock for testing.
func (t *NondeterminismTracker) WithClock(clock func() time.Time) *NondeterminismTracker {
	t.clock = clock
	return t
}

// Capture records a nondeterministic event.
func (t *NondeterminismTracker) Capture(runID string, source NondeterminismSource, description, inputHash, outputHash, seed string) *NondeterminismBound {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.seq++
	boundID := fmt.Sprintf("nd-%d", t.seq)
	now := t.clock()

	hashInput := fmt.Sprintf("%s:%s:%s:%s:%s", boundID, source, inputHash, outputHash, now.String())
	h := sha256.Sum256([]byte(hashInput))

	bound := NondeterminismBound{
		BoundID:     boundID,
		RunID:       runID,
		Source:      source,
		Description: description,
		InputHash:   inputHash,
		OutputHash:  outputHash,
		Seed:        seed,
		CapturedAt:  now,
		ContentHash: "sha256:" + hex.EncodeToString(h[:]),
	}

	t.byRun[runID] = append(t.byRun[runID], bound)
	return &bound
}

// Receipt produces a sealed receipt for all nondeterminism in a run.
func (t *NondeterminismTracker) Receipt(runID string) (*NondeterminismReceipt, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	bounds, ok := t.byRun[runID]
	if !ok {
		return nil, fmt.Errorf("no nondeterminism tracked for run %q", runID)
	}

	hashInput := fmt.Sprintf("receipt:%s:%d", runID, len(bounds))
	h := sha256.Sum256([]byte(hashInput))

	return &NondeterminismReceipt{
		ReceiptID:   fmt.Sprintf("ndr-%s", runID),
		RunID:       runID,
		Bounds:      bounds,
		TotalBounds: len(bounds),
		ContentHash: "sha256:" + hex.EncodeToString(h[:]),
	}, nil
}

// BoundsForRun returns all captured bounds for a run.
func (t *NondeterminismTracker) BoundsForRun(runID string) []NondeterminismBound {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.byRun[runID]
}
