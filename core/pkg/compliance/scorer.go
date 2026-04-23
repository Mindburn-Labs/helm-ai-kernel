// Package compliance — Real-time Compliance Scoring Engine.
//
// Per HELM 2030 Spec:
//   - Real-time per-framework compliance scoring (sliding window)
//   - Thread-safe with sync.RWMutex
//   - Clock injection for deterministic testing
//   - Scoring formula: base = (controls_passed / controls_total) * 100,
//     penalty = min(violation_count * 5, 50), score = clamp(base - penalty, 0, 100)
//   - Supports all 7 HELM compliance frameworks:
//     eu_ai_act, hipaa, sox, sec, gdpr, mica, fca
package compliance

import (
	"sync"
	"time"
)

// ComplianceScore represents a real-time compliance score for a framework.
type ComplianceScore struct {
	Framework      string    `json:"framework"` // "eu_ai_act", "hipaa", "sox", "sec", "gdpr", "mica", "fca"
	Score          int       `json:"score"`     // 0-100
	ControlsPassed int       `json:"controls_passed"`
	ControlsTotal  int       `json:"controls_total"`
	ViolationCount int       `json:"violation_count"`
	LastViolation  time.Time `json:"last_violation,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
	WindowHours    int       `json:"window_hours"` // scoring window (default 24h)
}

// ComplianceEvent is a decision that affects compliance scoring.
type ComplianceEvent struct {
	Framework string    `json:"framework"`
	ControlID string    `json:"control_id"`
	Passed    bool      `json:"passed"`
	Reason    string    `json:"reason,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// defaultWindow is the default sliding window duration for scoring.
const defaultWindow = 24 * time.Hour

// ComplianceScorer tracks real-time compliance scores across frameworks.
type ComplianceScorer struct {
	mu     sync.RWMutex
	scores map[string]*ComplianceScore  // framework -> score
	events map[string][]ComplianceEvent // framework -> events (sliding window)
	clock  func() time.Time
	window time.Duration // default 24h
}

// NewComplianceScorer creates a new real-time compliance scorer.
func NewComplianceScorer() *ComplianceScorer {
	return &ComplianceScorer{
		scores: make(map[string]*ComplianceScore),
		events: make(map[string][]ComplianceEvent),
		clock:  time.Now,
		window: defaultWindow,
	}
}

// WithClock overrides the clock for deterministic testing.
func (s *ComplianceScorer) WithClock(clock func() time.Time) *ComplianceScorer {
	s.clock = clock
	return s
}

// WithWindow overrides the sliding window duration.
func (s *ComplianceScorer) WithWindow(d time.Duration) *ComplianceScorer {
	s.window = d
	return s
}

// InitFramework registers a framework with its total control count.
// The initial score is 100 (fully compliant with no events).
func (s *ComplianceScorer) InitFramework(framework string, totalControls int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock()
	windowHours := int(s.window.Hours())

	s.scores[framework] = &ComplianceScore{
		Framework:      framework,
		Score:          100,
		ControlsPassed: totalControls,
		ControlsTotal:  totalControls,
		ViolationCount: 0,
		UpdatedAt:      now,
		WindowHours:    windowHours,
	}
	// Initialize empty event slice for the framework.
	if s.events[framework] == nil {
		s.events[framework] = []ComplianceEvent{}
	}
}

// RecordEvent records a compliance-affecting event and recomputes the score.
//
// Scoring algorithm:
//  1. Append event to sliding window
//  2. Prune events outside window
//  3. Compute unique controls that passed (latest result per control wins)
//  4. Base score: (controls_passed / controls_total) * 100
//  5. Violation penalty: score -= min(violation_count * 5, 50)
//  6. Clamp to [0, 100]
func (s *ComplianceScorer) RecordEvent(event ComplianceEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock()

	// Set timestamp if not provided.
	if event.Timestamp.IsZero() {
		event.Timestamp = now
	}

	// Append event.
	s.events[event.Framework] = append(s.events[event.Framework], event)

	// Get or create score entry.
	score, ok := s.scores[event.Framework]
	if !ok {
		// Framework not initialized — auto-init with 0 total controls.
		score = &ComplianceScore{
			Framework:   event.Framework,
			WindowHours: int(s.window.Hours()),
		}
		s.scores[event.Framework] = score
	}

	s.recompute(event.Framework, now)
}

// recompute recalculates the score for a framework. Caller must hold s.mu.
func (s *ComplianceScorer) recompute(framework string, now time.Time) {
	score := s.scores[framework]
	if score == nil {
		return
	}

	windowStart := now.Add(-s.window)

	// Prune events outside the window.
	events := s.events[framework]
	pruned := events[:0]
	for _, e := range events {
		if !e.Timestamp.Before(windowStart) {
			pruned = append(pruned, e)
		}
	}
	s.events[framework] = pruned

	// Determine latest result per control and count unique failed controls.
	// Latest event per control wins (by timestamp order, last in slice wins for ties).
	controlResults := make(map[string]bool) // controlID -> passed
	failedControls := make(map[string]bool) // unique controls that failed
	var lastViolation time.Time

	for _, e := range pruned {
		controlResults[e.ControlID] = e.Passed
		if !e.Passed {
			failedControls[e.ControlID] = true
			if e.Timestamp.After(lastViolation) {
				lastViolation = e.Timestamp
			}
		}
	}
	violationCount := len(failedControls)

	// Count controls that passed.
	controlsPassed := 0
	for _, passed := range controlResults {
		if passed {
			controlsPassed++
		}
	}

	// Base score: (controls_passed / controls_total) * 100.
	totalControls := score.ControlsTotal
	if totalControls == 0 {
		totalControls = len(controlResults)
	}

	baseScore := 0
	if totalControls > 0 {
		baseScore = (controlsPassed * 100) / totalControls
	}

	// Violation penalty: min(violation_count * 5, 50).
	penalty := violationCount * 5
	if penalty > 50 {
		penalty = 50
	}

	// Final score with clamping.
	finalScore := baseScore - penalty
	if finalScore < 0 {
		finalScore = 0
	}
	if finalScore > 100 {
		finalScore = 100
	}

	// Update score.
	score.Score = finalScore
	score.ControlsPassed = controlsPassed
	score.ViolationCount = violationCount
	score.LastViolation = lastViolation
	score.UpdatedAt = now
}

// GetScore returns the current compliance score for a framework.
// Returns nil if the framework has not been initialized.
func (s *ComplianceScorer) GetScore(framework string) *ComplianceScore {
	s.mu.RLock()
	defer s.mu.RUnlock()

	score, ok := s.scores[framework]
	if !ok {
		return nil
	}

	// Return a copy to avoid data races on the returned value.
	cp := *score
	return &cp
}

// GetAllScores returns scores for all registered frameworks.
func (s *ComplianceScorer) GetAllScores() map[string]*ComplianceScore {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*ComplianceScore, len(s.scores))
	for k, v := range s.scores {
		cp := *v
		result[k] = &cp
	}
	return result
}

// IsCompliant returns true if all frameworks score >= threshold.
// Returns true if no frameworks are registered (vacuous truth).
func (s *ComplianceScorer) IsCompliant(threshold int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, score := range s.scores {
		if score.Score < threshold {
			return false
		}
	}
	return true
}
