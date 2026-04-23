package trust

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── TierForScore ───────────────────────────────────────────────

func TestTierForScore(t *testing.T) {
	cases := []struct {
		score int
		want  TrustTier
	}{
		{1000, TierPristine},
		{900, TierPristine},
		{899, TierTrusted},
		{700, TierTrusted},
		{699, TierNeutral},
		{500, TierNeutral},
		{400, TierNeutral},
		{399, TierSuspect},
		{200, TierSuspect},
		{199, TierHostile},
		{0, TierHostile},
		{-1, TierHostile}, // below zero (pre-clamp value)
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("score_%d", tc.score), func(t *testing.T) {
			got := TierForScore(tc.score)
			if got != tc.want {
				t.Errorf("TierForScore(%d) = %s, want %s", tc.score, got, tc.want)
			}
		})
	}
}

// ── Normalized ─────────────────────────────────────────────────

func TestNormalized(t *testing.T) {
	cases := []struct {
		score int
		want  float64
	}{
		{0, 0.0},
		{500, 0.5},
		{1000, 1.0},
		{250, 0.25},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("score_%d", tc.score), func(t *testing.T) {
			b := BehavioralTrustScore{Score: tc.score}
			got := b.Normalized()
			if got != tc.want {
				t.Errorf("Normalized() for score %d = %f, want %f", tc.score, got, tc.want)
			}
		})
	}
}

// ── DefaultDeltas coverage ─────────────────────────────────────

func TestDefaultDeltasCompleteness(t *testing.T) {
	allTypes := []ScoreEventType{
		EventPolicyComply,
		EventPolicyViolate,
		EventRateLimitHit,
		EventThreatDetected,
		EventDelegationValid,
		EventDelegationAbuse,
		EventEgressBlocked,
		EventManualBoost,
		EventManualPenalty,
	}
	for _, et := range allTypes {
		if _, ok := DefaultDeltas[et]; !ok {
			t.Errorf("DefaultDeltas missing entry for %s", et)
		}
	}
}

func TestDefaultDeltas_PolicyComplyIsPositive(t *testing.T) {
	d, ok := DefaultDeltas[EventPolicyComply]
	if !ok {
		t.Fatal("DefaultDeltas missing EventPolicyComply")
	}
	if d <= 0 {
		t.Errorf("EventPolicyComply delta should be positive, got %d", d)
	}
}

func TestDefaultDeltas_PolicyViolateIsNegative(t *testing.T) {
	d, ok := DefaultDeltas[EventPolicyViolate]
	if !ok {
		t.Fatal("DefaultDeltas missing EventPolicyViolate")
	}
	if d >= 0 {
		t.Errorf("EventPolicyViolate delta should be negative, got %d", d)
	}
}

// ── mockClock for deterministic tests ──────────────────────────

type mockClock struct {
	now time.Time
}

func (m *mockClock) Now() time.Time { return m.now }

func (m *mockClock) Advance(d time.Duration) { m.now = m.now.Add(d) }

// ── Scorer: construction ───────────────────────────────────────

func TestNewScorer_Defaults(t *testing.T) {
	s := NewBehavioralTrustScorer()
	if s.scores == nil {
		t.Fatal("scores map should be initialized, got nil")
	}
	if len(s.scores) != 0 {
		t.Errorf("new scorer should have empty scores map, got %d entries", len(s.scores))
	}
}

// ── Scorer: GetScore lazy init ─────────────────────────────────

func TestGetScore_LazyInit(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	score := s.GetScore("unknown-agent")
	if score.Score != 500 {
		t.Errorf("expected initial score 500, got %d", score.Score)
	}
	if score.Tier != TierNeutral {
		t.Errorf("expected TierNeutral, got %s", score.Tier)
	}
	if score.AgentID != "unknown-agent" {
		t.Errorf("expected agent ID 'unknown-agent', got %s", score.AgentID)
	}
	if len(score.History) != 0 {
		t.Errorf("expected empty history for new agent, got %d entries", len(score.History))
	}
}

// ── Scorer: RecordEvent with default delta ─────────────────────

func TestRecordEvent_DefaultDelta(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	s.RecordEvent("agent-1", ScoreEvent{EventType: EventPolicyComply, Reason: "passed check"})
	score := s.GetScore("agent-1")

	// Default delta for POLICY_COMPLY is +2
	if score.Score != 502 {
		t.Errorf("expected 502, got %d", score.Score)
	}
	if len(score.History) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(score.History))
	}
	if score.History[0].EventType != EventPolicyComply {
		t.Errorf("expected POLICY_COMPLY, got %s", score.History[0].EventType)
	}
	if score.History[0].Delta != 2 {
		t.Errorf("expected default delta 2 filled in, got %d", score.History[0].Delta)
	}
}

// ── Scorer: RecordEvent with explicit delta ────────────────────

func TestRecordEvent_ExplicitDelta(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	s.RecordEvent("agent-1", ScoreEvent{
		EventType: EventPolicyComply,
		Delta:     10,
		Reason:    "bonus compliance",
	})
	score := s.GetScore("agent-1")

	if score.Score != 510 {
		t.Errorf("expected 510 (explicit delta 10), got %d", score.Score)
	}
	if score.History[0].Delta != 10 {
		t.Errorf("expected explicit delta 10 preserved, got %d", score.History[0].Delta)
	}
}

// ── Scorer: RecordEvent negative ───────────────────────────────

func TestRecordEvent_NegativeDefault(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	s.RecordEvent("agent-1", ScoreEvent{EventType: EventThreatDetected, Reason: "injection attempt"})
	score := s.GetScore("agent-1")

	// Default delta for THREAT_DETECTED is -50
	if score.Score != 450 {
		t.Errorf("expected 450, got %d", score.Score)
	}
	if score.Tier != TierNeutral {
		t.Errorf("expected TierNeutral for 450, got %s", score.Tier)
	}
}

// ── Scorer: clamping ───────────────────────────────────────────

func TestRecordEvent_Clamping(t *testing.T) {
	t.Run("clamped_at_zero", func(t *testing.T) {
		clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

		// Drive score well below 0 with repeated large negative events
		for i := 0; i < 20; i++ {
			s.RecordEvent("bad-agent", ScoreEvent{EventType: EventDelegationAbuse, Reason: "abuse"})
		}
		score := s.GetScore("bad-agent")
		if score.Score != 0 {
			t.Errorf("expected score clamped at 0, got %d", score.Score)
		}
		if score.Tier != TierHostile {
			t.Errorf("expected TierHostile, got %s", score.Tier)
		}
	})

	t.Run("clamped_at_1000", func(t *testing.T) {
		clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

		// Drive score well above 1000 with repeated large positive events
		for i := 0; i < 30; i++ {
			s.RecordEvent("star-agent", ScoreEvent{EventType: EventManualBoost, Reason: "reward"})
		}
		score := s.GetScore("star-agent")
		if score.Score != 1000 {
			t.Errorf("expected score clamped at 1000, got %d", score.Score)
		}
		if score.Tier != TierPristine {
			t.Errorf("expected TierPristine, got %s", score.Tier)
		}
	})

	t.Run("single_large_negative_clamps", func(t *testing.T) {
		clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

		// Single event with delta far exceeding the score
		s.RecordEvent("agent-x", ScoreEvent{
			EventType: EventManualPenalty,
			Delta:     -9999,
			Reason:    "nuke",
		})
		score := s.GetScore("agent-x")
		if score.Score != 0 {
			t.Errorf("expected 0 after massive negative delta, got %d", score.Score)
		}
	})

	t.Run("single_large_positive_clamps", func(t *testing.T) {
		clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

		s.RecordEvent("agent-y", ScoreEvent{
			EventType: EventManualBoost,
			Delta:     9999,
			Reason:    "mega boost",
		})
		score := s.GetScore("agent-y")
		if score.Score != 1000 {
			t.Errorf("expected 1000 after massive positive delta, got %d", score.Score)
		}
	})
}

// ── Scorer: tier transitions ───────────────────────────────────

func TestRecordEvent_TierTransitions(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	// Start at NEUTRAL (500)
	score := s.GetScore("agent-1")
	if score.Tier != TierNeutral {
		t.Fatalf("expected TierNeutral at start, got %s", score.Tier)
	}

	// Boost to TRUSTED (500 + 200 = 700)
	s.RecordEvent("agent-1", ScoreEvent{EventType: EventManualBoost, Delta: 200, Reason: "promote"})
	score = s.GetScore("agent-1")
	if score.Tier != TierTrusted {
		t.Errorf("expected TierTrusted after +200 (score %d), got %s", score.Score, score.Tier)
	}

	// Boost to PRISTINE (700 + 200 = 900)
	s.RecordEvent("agent-1", ScoreEvent{EventType: EventManualBoost, Delta: 200, Reason: "promote again"})
	score = s.GetScore("agent-1")
	if score.Tier != TierPristine {
		t.Errorf("expected TierPristine after another +200 (score %d), got %s", score.Score, score.Tier)
	}

	// Drop to SUSPECT (900 - 550 = 350)
	s.RecordEvent("agent-1", ScoreEvent{EventType: EventManualPenalty, Delta: -550, Reason: "crash"})
	score = s.GetScore("agent-1")
	if score.Tier != TierSuspect {
		t.Errorf("expected TierSuspect after -550 (score %d), got %s", score.Score, score.Tier)
	}

	// Drop to HOSTILE (350 - 200 = 150)
	s.RecordEvent("agent-1", ScoreEvent{EventType: EventManualPenalty, Delta: -200, Reason: "fatal"})
	score = s.GetScore("agent-1")
	if score.Tier != TierHostile {
		t.Errorf("expected TierHostile after -200 (score %d), got %s", score.Score, score.Tier)
	}
}

// ── Decay: positive (above initial) ────────────────────────────

func TestDecay_PositiveAboveInitial(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	// Set score to 700 (200 above initial 500)
	s.RecordEvent("agent-1", ScoreEvent{EventType: EventManualBoost, Delta: 200, Reason: "boost"})
	score := s.GetScore("agent-1")
	if score.Score != 700 {
		t.Fatalf("expected 700 after boost, got %d", score.Score)
	}

	// Advance by exactly one PositiveHalfLife (24h).
	// Deviation 200 should halve to 100, so score = 500 + 100 = 600.
	clock.Advance(24 * time.Hour)
	score = s.GetScore("agent-1")

	if score.Score != 600 {
		t.Errorf("expected 600 after one positive half-life (deviation 200 -> 100), got %d", score.Score)
	}
}

func TestDecay_PositiveTwoHalfLives(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	// Set score to 900 (400 above initial)
	s.RecordEvent("agent-1", ScoreEvent{EventType: EventManualBoost, Delta: 400, Reason: "boost"})
	score := s.GetScore("agent-1")
	if score.Score != 900 {
		t.Fatalf("expected 900, got %d", score.Score)
	}

	// Advance by two positive half-lives (48h).
	// Deviation 400 -> 200 -> 100, so score = 500 + 100 = 600.
	clock.Advance(48 * time.Hour)
	score = s.GetScore("agent-1")

	if score.Score != 600 {
		t.Errorf("expected 600 after two positive half-lives, got %d", score.Score)
	}
}

// ── Decay: negative (below initial) ────────────────────────────

func TestDecay_NegativeBelowInitial(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	// Drop to 300 (200 below initial 500)
	s.RecordEvent("agent-1", ScoreEvent{EventType: EventManualPenalty, Delta: -200, Reason: "penalty"})
	score := s.GetScore("agent-1")
	if score.Score != 300 {
		t.Fatalf("expected 300 after penalty, got %d", score.Score)
	}

	// Advance by one negative half-life (72h).
	// Deviation -200 should halve to -100, so score = 500 - 100 = 400.
	clock.Advance(72 * time.Hour)
	score = s.GetScore("agent-1")

	if score.Score != 400 {
		t.Errorf("expected 400 after one negative half-life (deviation -200 -> -100), got %d", score.Score)
	}
}

// ── Decay: at initial — no change ──────────────────────────────

func TestDecay_AtInitial_NoChange(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	// Touch the agent to create the entry at initial score
	_ = s.GetScore("agent-1")

	// Advance significant time
	clock.Advance(168 * time.Hour) // 1 week
	score := s.GetScore("agent-1")

	if score.Score != 500 {
		t.Errorf("expected 500 (no decay at initial), got %d", score.Score)
	}
}

// ── Ring buffer bounded ────────────────────────────────────────

func TestRingBuffer_Bounded(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(
		WithBehavioralClock(clock),
		WithScorerConfig(ScorerConfig{
			InitialScore:     500,
			MaxHistorySize:   5,
			PositiveHalfLife: 24 * time.Hour,
			NegativeHalfLife: 72 * time.Hour,
		}),
	)

	for i := 0; i < 10; i++ {
		s.RecordEvent("agent-1", ScoreEvent{
			EventType: EventPolicyComply,
			Delta:     1,
			Reason:    fmt.Sprintf("event-%d", i),
		})
	}

	score := s.GetScore("agent-1")
	if len(score.History) != 5 {
		t.Errorf("expected 5 history entries (ring buffer capped), got %d", len(score.History))
	}

	// The oldest entries should have been dropped; the newest should remain.
	// Events 5-9 should be in the buffer (0-4 dropped).
	if score.History[0].Reason != "event-5" {
		t.Errorf("expected oldest retained event to be 'event-5', got %q", score.History[0].Reason)
	}
	if score.History[4].Reason != "event-9" {
		t.Errorf("expected newest event to be 'event-9', got %q", score.History[4].Reason)
	}
}

// ── Concurrency ────────────────────────────────────────────────

func TestConcurrency(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	var wg sync.WaitGroup
	wg.Add(100)

	for i := 0; i < 100; i++ {
		go func(idx int) {
			defer wg.Done()
			agentID := fmt.Sprintf("agent-%d", idx%10) // 10 agents, 10 goroutines each
			s.RecordEvent(agentID, ScoreEvent{
				EventType: EventPolicyComply,
				Delta:     1,
				Reason:    "concurrent",
			})
			_ = s.GetScore(agentID)
			_ = s.GetTier(agentID)
		}(i)
	}

	wg.Wait()

	// Verify all agents exist and scores are valid (in [0, 1000])
	for i := 0; i < 10; i++ {
		agentID := fmt.Sprintf("agent-%d", i)
		score := s.GetScore(agentID)
		if score.Score < 0 || score.Score > 1000 {
			t.Errorf("agent %s has out-of-range score %d", agentID, score.Score)
		}
		if score.AgentID != agentID {
			t.Errorf("expected agent ID %s, got %s", agentID, score.AgentID)
		}
	}
}

// ── GetScore returns a copy ────────────────────────────────────

func TestGetScore_ReturnsCopy(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	s.RecordEvent("agent-1", ScoreEvent{EventType: EventPolicyComply, Reason: "ok"})

	score1 := s.GetScore("agent-1")
	score2 := s.GetScore("agent-1")

	// Mutating the returned score should not affect the scorer's internal state.
	score1.Score = 9999
	score1.History[0].Reason = "mutated"

	if score2.Score == 9999 {
		t.Error("GetScore should return a copy, but Score mutation leaked")
	}
	if score2.History[0].Reason == "mutated" {
		t.Error("GetScore should return a copy, but History mutation leaked")
	}

	// Also verify the internal state wasn't affected
	score3 := s.GetScore("agent-1")
	if score3.Score == 9999 {
		t.Error("GetScore should return a copy, but internal state was modified")
	}
}

// ── Custom config ──────────────────────────────────────────────

func TestCustomConfig(t *testing.T) {
	t.Run("custom_initial_score", func(t *testing.T) {
		s := NewBehavioralTrustScorer(WithScorerConfig(ScorerConfig{
			InitialScore:     700,
			MaxHistorySize:   100,
			PositiveHalfLife: 24 * time.Hour,
			NegativeHalfLife: 72 * time.Hour,
		}))

		score := s.GetScore("agent-1")
		if score.Score != 700 {
			t.Errorf("expected custom initial 700, got %d", score.Score)
		}
		if score.Tier != TierTrusted {
			t.Errorf("expected TierTrusted for 700, got %s", score.Tier)
		}
	})

	t.Run("custom_half_lives", func(t *testing.T) {
		clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		s := NewBehavioralTrustScorer(
			WithBehavioralClock(clock),
			WithScorerConfig(ScorerConfig{
				InitialScore:     500,
				MaxHistorySize:   100,
				PositiveHalfLife: 1 * time.Hour, // fast decay
				NegativeHalfLife: 1 * time.Hour,
			}),
		)

		// Boost to 700
		s.RecordEvent("agent-1", ScoreEvent{EventType: EventManualBoost, Delta: 200, Reason: "boost"})

		// After 1h (one half-life), deviation should halve: 200 -> 100
		clock.Advance(1 * time.Hour)
		score := s.GetScore("agent-1")
		if score.Score != 600 {
			t.Errorf("expected 600 with 1h half-life, got %d", score.Score)
		}
	})

	t.Run("custom_max_history", func(t *testing.T) {
		clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		s := NewBehavioralTrustScorer(
			WithBehavioralClock(clock),
			WithScorerConfig(ScorerConfig{
				InitialScore:     500,
				MaxHistorySize:   3,
				PositiveHalfLife: 24 * time.Hour,
				NegativeHalfLife: 72 * time.Hour,
			}),
		)

		for i := 0; i < 10; i++ {
			s.RecordEvent("agent-1", ScoreEvent{
				EventType: EventPolicyComply,
				Delta:     1,
				Reason:    fmt.Sprintf("e%d", i),
			})
		}
		score := s.GetScore("agent-1")
		if len(score.History) != 3 {
			t.Errorf("expected 3 history entries with MaxHistorySize=3, got %d", len(score.History))
		}
	})
}

// ── Timestamp auto-fill ────────────────────────────────────────

func TestTimestampFill(t *testing.T) {
	t.Run("zero_timestamp_gets_clock_time", func(t *testing.T) {
		now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
		clock := &mockClock{now: now}
		s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

		s.RecordEvent("agent-1", ScoreEvent{EventType: EventPolicyComply, Reason: "ok"})
		score := s.GetScore("agent-1")

		if len(score.History) != 1 {
			t.Fatalf("expected 1 history entry, got %d", len(score.History))
		}
		if !score.History[0].Timestamp.Equal(now) {
			t.Errorf("expected auto-filled timestamp %v, got %v", now, score.History[0].Timestamp)
		}
	})

	t.Run("explicit_timestamp_preserved", func(t *testing.T) {
		clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

		explicit := time.Date(2025, 12, 25, 0, 0, 0, 0, time.UTC)
		s.RecordEvent("agent-1", ScoreEvent{
			EventType: EventPolicyComply,
			Reason:    "ok",
			Timestamp: explicit,
		})
		score := s.GetScore("agent-1")

		if !score.History[0].Timestamp.Equal(explicit) {
			t.Errorf("expected preserved timestamp %v, got %v", explicit, score.History[0].Timestamp)
		}
	})
}

// ── GetTier convenience ────────────────────────────────────────

func TestGetTier(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	tier := s.GetTier("new-agent")
	if tier != TierNeutral {
		t.Errorf("expected TierNeutral for new agent, got %s", tier)
	}

	// Boost and check tier via GetTier
	s.RecordEvent("new-agent", ScoreEvent{EventType: EventManualBoost, Delta: 500, Reason: "big boost"})
	tier = s.GetTier("new-agent")
	if tier != TierPristine {
		t.Errorf("expected TierPristine after +500, got %s", tier)
	}
}

// ── Decay applies before delta in RecordEvent ──────────────────

func TestDecay_AppliedBeforeDelta(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	// Boost to 700
	s.RecordEvent("agent-1", ScoreEvent{EventType: EventManualBoost, Delta: 200, Reason: "boost"})

	// Advance one positive half-life (24h) — decay should bring score from 700 to 600
	// Then the new event adds +10, so final score should be 610
	clock.Advance(24 * time.Hour)
	s.RecordEvent("agent-1", ScoreEvent{EventType: EventPolicyComply, Delta: 10, Reason: "comply"})
	score := s.GetScore("agent-1")

	if score.Score != 610 {
		t.Errorf("expected 610 (decayed 700->600 then +10), got %d", score.Score)
	}
}

// ── Multiple agents are independent ────────────────────────────

func TestMultipleAgentsIndependent(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))

	s.RecordEvent("agent-a", ScoreEvent{EventType: EventManualBoost, Delta: 400, Reason: "boost a"})
	s.RecordEvent("agent-b", ScoreEvent{EventType: EventManualPenalty, Delta: -300, Reason: "penalize b"})

	scoreA := s.GetScore("agent-a")
	scoreB := s.GetScore("agent-b")

	if scoreA.Score != 900 {
		t.Errorf("agent-a expected 900, got %d", scoreA.Score)
	}
	if scoreB.Score != 200 {
		t.Errorf("agent-b expected 200, got %d", scoreB.Score)
	}
	if scoreA.Tier != TierPristine {
		t.Errorf("agent-a expected TierPristine, got %s", scoreA.Tier)
	}
	if scoreB.Tier != TierSuspect {
		t.Errorf("agent-b expected TierSuspect, got %s", scoreB.Tier)
	}
}
