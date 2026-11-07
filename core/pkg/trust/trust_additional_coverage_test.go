package trust

import (
	"sync"
	"testing"
	"time"
)

// ─── 1: Behavioral scorer concurrent RecordEvent ──────────────

func TestExt_ScorerConcurrentRecordEvent(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.RecordEvent("agent-1", ScoreEvent{EventType: EventPolicyComply})
		}()
	}
	wg.Wait()
	score := s.GetScore("agent-1")
	if score.Score <= 500 {
		t.Fatal("score should be above initial after 100 comply events")
	}
}

// ─── 2: Behavioral scorer concurrent GetScore ─────────────────

func TestExt_ScorerConcurrentGetScore(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))
	s.RecordEvent("a", ScoreEvent{Delta: 100, EventType: EventManualBoost})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.GetScore("a")
		}()
	}
	wg.Wait()
}

// ─── 3: Decay precision — positive half-life ──────────────────

func TestExt_DecayPrecisionPositive(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(
		WithBehavioralClock(clock),
		WithScorerConfig(ScorerConfig{InitialScore: 500, MaxHistorySize: 100, PositiveHalfLife: 24 * time.Hour, NegativeHalfLife: 72 * time.Hour}),
	)
	s.RecordEvent("a", ScoreEvent{Delta: 200, EventType: EventManualBoost})
	// After one half-life, deviation should halve: 200 → ~100
	clock.Advance(24 * time.Hour)
	score := s.GetScore("a")
	if score.Score < 590 || score.Score > 610 {
		t.Fatalf("after 1 half-life, expected ~600, got %d", score.Score)
	}
}

// ─── 4: Decay precision — negative half-life ──────────────────

func TestExt_DecayPrecisionNegative(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(
		WithBehavioralClock(clock),
		WithScorerConfig(ScorerConfig{InitialScore: 500, MaxHistorySize: 100, PositiveHalfLife: 24 * time.Hour, NegativeHalfLife: 72 * time.Hour}),
	)
	s.RecordEvent("a", ScoreEvent{Delta: -200, EventType: EventManualPenalty})
	// After one negative half-life (72h), deviation should halve: -200 → ~-100
	clock.Advance(72 * time.Hour)
	score := s.GetScore("a")
	if score.Score < 390 || score.Score > 410 {
		t.Fatalf("after 1 negative half-life, expected ~400, got %d", score.Score)
	}
}

// ─── 5: Decay with zero half-life is no-op ───────────────────

func TestExt_DecayZeroHalfLifeNoOp(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(
		WithBehavioralClock(clock),
		WithScorerConfig(ScorerConfig{InitialScore: 500, MaxHistorySize: 100, PositiveHalfLife: 0, NegativeHalfLife: 0}),
	)
	s.RecordEvent("a", ScoreEvent{Delta: 100, EventType: EventManualBoost})
	clock.Advance(24 * time.Hour)
	score := s.GetScore("a")
	// Zero half-life means no decay applied
	if score.Score != 600 {
		t.Fatalf("zero half-life should not decay, expected 600, got %d", score.Score)
	}
}

// ─── 6: Score clamped at 1000 ─────────────────────────────────

func TestExt_ScoreClampedAt1000(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))
	s.RecordEvent("a", ScoreEvent{Delta: 9999, EventType: EventManualBoost})
	if s.GetScore("a").Score != 1000 {
		t.Fatalf("expected 1000, got %d", s.GetScore("a").Score)
	}
}

// ─── 7: Score clamped at 0 ────────────────────────────────────

func TestExt_ScoreClampedAt0(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))
	s.RecordEvent("a", ScoreEvent{Delta: -9999, EventType: EventManualPenalty})
	if s.GetScore("a").Score != 0 {
		t.Fatalf("expected 0, got %d", s.GetScore("a").Score)
	}
}

// ─── 8: History FIFO bounded ──────────────────────────────────

func TestExt_HistoryFIFOBounded(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(
		WithBehavioralClock(clock),
		WithScorerConfig(ScorerConfig{InitialScore: 500, MaxHistorySize: 5, PositiveHalfLife: 24 * time.Hour, NegativeHalfLife: 72 * time.Hour}),
	)
	for i := 0; i < 10; i++ {
		s.RecordEvent("a", ScoreEvent{Delta: 1, EventType: EventPolicyComply})
	}
	score := s.GetScore("a")
	if len(score.History) != 5 {
		t.Fatalf("expected max 5 history entries, got %d", len(score.History))
	}
}

// ─── 9: GetScore returns copy ─────────────────────────────────

func TestExt_GetScoreReturnsCopy(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))
	s.RecordEvent("a", ScoreEvent{Delta: 10, EventType: EventPolicyComply})
	s1 := s.GetScore("a")
	s2 := s.GetScore("a")
	s1.Score = 999
	if s2.Score == 999 {
		t.Fatal("GetScore should return copies, not references")
	}
}

// ─── 10: CompliancePipeline IngestMapping — unknown control ───

// ─── 11: CompliancePipeline IngestMapping — valid ─────────────

// ─── 12: CompliancePipeline ScanForStaleControls ──────────────

// ─── 13: CompliancePipeline invalid JSON ──────────────────────

// ─── 14: Leaderboard sort stability — equal scores ────────────

// ─── 15: Leaderboard re-rank after update ─────────────────────

// ─── 16: Leaderboard GetEntry not found ───────────────────────

// ─── 17: Leaderboard GetTopN larger than entries ──────────────

// ─── 18: Leaderboard badge levels ─────────────────────────────

// ─── 19: Leaderboard Export hash non-empty ────────────────────

// ─── 20: Leaderboard hash deterministic ───────────────────────

// ─── 21: Leaderboard GetByBadge filters correctly ────────────

// ─── 22: ComplianceMatrix hash deterministic ──────────────────

// ─── 23: ComplianceMatrix AddControl unknown framework ────────

// ─── 24: TrustScore Normalized range ──────────────────────────

func TestExt_BehavioralTrustScoreNormalized(t *testing.T) {
	score := &BehavioralTrustScore{Score: 750}
	n := score.Normalized()
	if n != 0.75 {
		t.Fatalf("expected 0.75, got %f", n)
	}
}

// ─── 25: Leaderboard Export JSON serializable ─────────────────
