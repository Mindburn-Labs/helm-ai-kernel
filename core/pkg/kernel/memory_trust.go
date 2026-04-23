// memory_trust.go implements trust-aware memory scoring for governed memory.
// Per arXiv 2601.05504 (MINJA defense), memory entries are scored by:
//   - Age: older entries decay in trust
//   - Source trust: entries from verified principals score higher
//   - Pattern analysis: entries matching injection patterns score lower
//
// Design invariants:
//   - Scores range 0.0-1.0 (1.0 = fully trusted)
//   - New entries from trusted sources start at 0.9
//   - Temporal decay: score *= decay_factor per hour (default 0.99)
//   - Injection pattern detection: score -= 0.5 if suspicious
//   - Thread-safe
package kernel

import (
	"math"
	"strings"
	"sync"
	"time"
)

// defaultDecayRate is the per-hour trust decay factor.
const defaultDecayRate = 0.99

// defaultBaseTrust is the trust score for unknown principals.
const defaultBaseTrust = 0.5

// injectionPatterns are simple string-contains checks for suspicious content.
// These are not comprehensive — they provide a lightweight first-pass signal.
var injectionPatterns = []string{
	"ignore previous",
	"disregard",
	"system:",
	"you are now",
	"override",
}

// MemoryTrustScore is the computed trust assessment for a single memory entry.
type MemoryTrustScore struct {
	Key          string    `json:"key"`
	Score        float64   `json:"score"`        // 0.0-1.0
	SourceTrust  float64   `json:"source_trust"` // Initial trust from source
	AgeHours     float64   `json:"age_hours"`
	DecayApplied float64   `json:"decay_applied"` // Cumulative decay factor
	Suspicious   bool      `json:"suspicious"`    // Injection pattern detected
	ComputedAt   time.Time `json:"computed_at"`
}

// MemoryTrustOption configures optional behavior for MemoryTrustScorer.
type MemoryTrustOption func(*MemoryTrustScorer)

// MemoryTrustScorer computes composite trust scores for memory entries
// using temporal decay, source reputation, and injection pattern detection.
type MemoryTrustScorer struct {
	mu        sync.RWMutex
	decayRate float64
	baseTrust map[string]float64 // principalID -> base trust (0.0-1.0)
	clock     func() time.Time
}

// NewMemoryTrustScorer creates a new scorer with the given options.
func NewMemoryTrustScorer(opts ...MemoryTrustOption) *MemoryTrustScorer {
	s := &MemoryTrustScorer{
		decayRate: defaultDecayRate,
		baseTrust: make(map[string]float64),
		clock:     time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithDecayRate sets the per-hour decay factor. Must be in (0.0, 1.0].
func WithDecayRate(rate float64) MemoryTrustOption {
	return func(s *MemoryTrustScorer) {
		if rate > 0 && rate <= 1.0 {
			s.decayRate = rate
		}
	}
}

// WithTrustScorerClock overrides the time source for deterministic testing.
func WithTrustScorerClock(clock func() time.Time) MemoryTrustOption {
	return func(s *MemoryTrustScorer) {
		s.clock = clock
	}
}

// SetPrincipalTrust sets the base trust score for a principal. The trust
// value is clamped to [0.0, 1.0].
func (s *MemoryTrustScorer) SetPrincipalTrust(principalID string, trust float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseTrust[principalID] = clamp(trust, 0.0, 1.0)
}

// ScoreEntry computes the trust score for a memory entry.
//
// Algorithm:
//
//	base = baseTrust[entry.WrittenBy] or 0.5 (unknown principal)
//	age_hours = time.Since(entry.WrittenAt).Hours()
//	decay = decayRate ^ age_hours
//	suspicious = containsInjectionPatterns(entry.Value)
//	penalty = if suspicious then 0.5 else 0.0
//	score = clamp(base * decay - penalty, 0.0, 1.0)
func (s *MemoryTrustScorer) ScoreEntry(entry *MemoryEntry) *MemoryTrustScore {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.clock()

	// Determine base trust from principal.
	base, ok := s.baseTrust[entry.WrittenBy]
	if !ok {
		base = defaultBaseTrust
	}

	// Compute temporal decay.
	ageHours := now.Sub(entry.WrittenAt).Hours()
	if ageHours < 0 {
		ageHours = 0
	}
	decay := math.Pow(s.decayRate, ageHours)

	// Check for injection patterns.
	suspicious := containsInjectionPatterns(string(entry.Value))
	penalty := 0.0
	if suspicious {
		penalty = 0.5
	}

	score := clamp(base*decay-penalty, 0.0, 1.0)

	return &MemoryTrustScore{
		Key:          entry.Key,
		Score:        score,
		SourceTrust:  base,
		AgeHours:     ageHours,
		DecayApplied: decay,
		Suspicious:   suspicious,
		ComputedAt:   now,
	}
}

// IsTrusted returns true if the entry's trust score meets or exceeds the threshold.
func (s *MemoryTrustScorer) IsTrusted(entry *MemoryEntry, threshold float64) bool {
	score := s.ScoreEntry(entry)
	return score.Score >= threshold
}

// containsInjectionPatterns checks if the value contains any known injection patterns.
func containsInjectionPatterns(value string) bool {
	lower := strings.ToLower(value)
	for _, pattern := range injectionPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// clamp restricts v to the range [min, max].
func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
