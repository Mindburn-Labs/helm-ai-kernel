// Package trust — behavioral_scorer.go
// Runtime scorer that maintains per-agent behavioral trust scores.
//
// Thread-safe: a sync.RWMutex protects the scores map.
// Lazy initialization: GetScore creates a new entry at InitialScore if absent.
// Decay: exponential decay toward InitialScore using configurable half-lives
// (positive and negative deviations decay independently).

package trust

import (
	"math"
	"sync"
	"time"
)

// ── Clock ──────────────────────────────────────────────────────

// BehavioralClock is a time source for the behavioral scorer.
// Matches the Clock interface pattern in guardian.go.
type BehavioralClock interface {
	Now() time.Time
}

// wallClock implements BehavioralClock using time.Now.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// ── Config ─────────────────────────────────────────────────────

// ScorerConfig controls behavioral scoring parameters.
type ScorerConfig struct {
	// InitialScore is the starting score for new agents. Default: 500.
	InitialScore int
	// MaxHistorySize is the maximum number of recent events to keep (FIFO). Default: 100.
	MaxHistorySize int
	// PositiveHalfLife governs how fast scores above InitialScore decay down.
	// Default: 24h.
	PositiveHalfLife time.Duration
	// NegativeHalfLife governs how fast scores below InitialScore decay up.
	// Default: 72h.
	NegativeHalfLife time.Duration
}

// DefaultScorerConfig returns production defaults.
func DefaultScorerConfig() ScorerConfig {
	return ScorerConfig{
		InitialScore:     500,
		MaxHistorySize:   100,
		PositiveHalfLife: 24 * time.Hour,
		NegativeHalfLife: 72 * time.Hour,
	}
}

// ── Functional Options ─────────────────────────────────────────

// ScorerOption configures a BehavioralTrustScorer.
type ScorerOption func(*BehavioralTrustScorer)

// WithBehavioralClock injects a deterministic clock (useful for testing).
func WithBehavioralClock(c BehavioralClock) ScorerOption {
	return func(s *BehavioralTrustScorer) { s.clock = c }
}

// WithScorerConfig overrides the default scoring configuration.
func WithScorerConfig(c ScorerConfig) ScorerOption {
	return func(s *BehavioralTrustScorer) { s.config = c }
}

// ── Scorer ─────────────────────────────────────────────────────

// BehavioralTrustScorer maintains per-agent behavioral trust scores.
type BehavioralTrustScorer struct {
	mu     sync.RWMutex
	scores map[string]*BehavioralTrustScore
	clock  BehavioralClock
	config ScorerConfig
}

// NewBehavioralTrustScorer creates a scorer with the given options.
func NewBehavioralTrustScorer(opts ...ScorerOption) *BehavioralTrustScorer {
	s := &BehavioralTrustScorer{
		scores: make(map[string]*BehavioralTrustScore),
		clock:  wallClock{},
		config: DefaultScorerConfig(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// RecordEvent records a trust-affecting event for an agent.
// If event.Delta is 0 the default delta for the event type is used.
// If event.Timestamp is zero the current clock time is used.
func (s *BehavioralTrustScorer) RecordEvent(agentID string, event ScoreEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now()

	// Fill defaults.
	if event.Delta == 0 {
		if d, ok := DefaultDeltas[event.EventType]; ok {
			event.Delta = d
		}
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = now
	}

	score := s.getOrCreateLocked(agentID, now)

	// Apply decay before mutation so the delta is relative to the decayed value.
	s.applyDecayLocked(score, now)

	// Apply delta and clamp.
	score.Score = clampScore(score.Score + event.Delta)
	score.Tier = TierForScore(score.Score)
	score.UpdatedAt = now

	// Append to history (FIFO: oldest events are dropped, newest are kept).
	score.History = append(score.History, event)
	if len(score.History) > s.config.MaxHistorySize {
		// Drop oldest entries beyond capacity.
		excess := len(score.History) - s.config.MaxHistorySize
		score.History = score.History[excess:]
	}
}

// GetScore returns the current behavioral trust score for an agent.
// Returns a score at InitialScore if the agent has no history.
// Applies time-based decay before returning.
func (s *BehavioralTrustScorer) GetScore(agentID string) BehavioralTrustScore {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now()
	score := s.getOrCreateLocked(agentID, now)
	s.applyDecayLocked(score, now)

	// Return a copy to avoid data races on the caller side.
	out := *score
	if score.History != nil {
		out.History = make([]ScoreEvent, len(score.History))
		copy(out.History, score.History)
	}
	return out
}

// GetTier returns the current trust tier for an agent.
func (s *BehavioralTrustScorer) GetTier(agentID string) TrustTier {
	return s.GetScore(agentID).Tier
}

// ── Internal helpers ───────────────────────────────────────────

// getOrCreateLocked returns the score entry for agentID, creating one at
// InitialScore if absent. Caller MUST hold s.mu.
func (s *BehavioralTrustScorer) getOrCreateLocked(agentID string, now time.Time) *BehavioralTrustScore {
	if sc, ok := s.scores[agentID]; ok {
		return sc
	}
	sc := &BehavioralTrustScore{
		AgentID:   agentID,
		Score:     s.config.InitialScore,
		Tier:      TierForScore(s.config.InitialScore),
		UpdatedAt: now,
	}
	s.scores[agentID] = sc
	return sc
}

// applyDecayLocked applies exponential decay toward InitialScore.
//
// Scores above InitialScore decay down with PositiveHalfLife.
// Scores below InitialScore decay up with NegativeHalfLife.
// Formula: deviation *= exp(-ln(2)/halfLife * elapsed)
//
// Caller MUST hold s.mu.
func (s *BehavioralTrustScorer) applyDecayLocked(score *BehavioralTrustScore, now time.Time) {
	elapsed := now.Sub(score.UpdatedAt)
	if elapsed <= 0 {
		return
	}

	initial := s.config.InitialScore
	deviation := score.Score - initial
	if deviation == 0 {
		score.UpdatedAt = now
		return
	}

	var halfLife time.Duration
	if deviation > 0 {
		halfLife = s.config.PositiveHalfLife
	} else {
		halfLife = s.config.NegativeHalfLife
	}
	if halfLife <= 0 {
		score.UpdatedAt = now
		return
	}

	lambda := math.Ln2 / halfLife.Seconds()
	factor := math.Exp(-lambda * elapsed.Seconds())
	decayedDeviation := int(math.Round(float64(deviation) * factor))

	score.Score = clampScore(initial + decayedDeviation)
	score.Tier = TierForScore(score.Score)
	score.UpdatedAt = now
}

// clampScore clamps a score to [0, 1000].
func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 1000 {
		return 1000
	}
	return score
}
