package trust

import (
	"testing"
	"time"
)

// ── Behavioral Scorer Edge Cases ──────────────────────────────

func TestScorer_ZeroDeltaUsesDefault(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))
	s.RecordEvent("a", ScoreEvent{EventType: EventEgressBlocked})
	got := s.GetScore("a")
	if got.Score != 500+DefaultDeltas[EventEgressBlocked] {
		t.Errorf("expected %d, got %d", 500+DefaultDeltas[EventEgressBlocked], got.Score)
	}
}

func TestScorer_UnknownEventTypeZeroDelta(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))
	s.RecordEvent("a", ScoreEvent{EventType: ScoreEventType("UNKNOWN")})
	if s.GetScore("a").Score != 500 {
		t.Errorf("unknown event with zero delta should leave score at 500, got %d", s.GetScore("a").Score)
	}
}

func TestScorer_NegativeClampAtZeroStaysHostile(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))
	s.RecordEvent("a", ScoreEvent{Delta: -999, EventType: EventManualPenalty})
	score := s.GetScore("a")
	if score.Score != 0 || score.Tier != TierHostile {
		t.Errorf("expected score=0/HOSTILE, got %d/%s", score.Score, score.Tier)
	}
}

// ── Tier Boundaries ──────────────────────────────────────────

func TestTierBoundary_899_700(t *testing.T) {
	if TierForScore(899) != TierTrusted || TierForScore(700) != TierTrusted {
		t.Error("both 899 and 700 should be TRUSTED")
	}
}

func TestTierBoundary_Exact900(t *testing.T) {
	if TierForScore(900) != TierPristine {
		t.Errorf("900 should be PRISTINE, got %s", TierForScore(900))
	}
}

func TestTierBoundary_Exact199(t *testing.T) {
	if TierForScore(199) != TierHostile {
		t.Errorf("199 should be HOSTILE, got %s", TierForScore(199))
	}
}

func TestTierBoundary_NegativeScore(t *testing.T) {
	if TierForScore(-100) != TierHostile {
		t.Errorf("negative score should be HOSTILE, got %s", TierForScore(-100))
	}
}

// ── Decay Math ───────────────────────────────────────────────

func TestDecay_ZeroHalfLifeNoDecay(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(
		WithBehavioralClock(clock),
		WithScorerConfig(ScorerConfig{InitialScore: 500, MaxHistorySize: 100, PositiveHalfLife: 0, NegativeHalfLife: 0}),
	)
	s.RecordEvent("a", ScoreEvent{EventType: EventManualBoost, Delta: 200})
	clock.Advance(100 * time.Hour)
	if s.GetScore("a").Score != 700 {
		t.Errorf("zero half-life should not decay, got %d", s.GetScore("a").Score)
	}
}

func TestDecay_NegativeDeviationDecaysUp(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))
	s.RecordEvent("a", ScoreEvent{EventType: EventManualPenalty, Delta: -400})
	clock.Advance(72 * time.Hour) // one negative half-life
	score := s.GetScore("a")
	// deviation -400 halves to -200, score = 500-200 = 300
	if score.Score != 300 {
		t.Errorf("expected 300 after one negative half-life, got %d", score.Score)
	}
}

func TestDecay_NoElapsedTimeNoDecay(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))
	s.RecordEvent("a", ScoreEvent{EventType: EventManualBoost, Delta: 300})
	// no time advance
	if s.GetScore("a").Score != 800 {
		t.Errorf("expected 800 with no elapsed time, got %d", s.GetScore("a").Score)
	}
}

func TestDecay_LargeTimeConvergesToInitial(t *testing.T) {
	clock := &mockClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clock))
	s.RecordEvent("a", ScoreEvent{EventType: EventManualBoost, Delta: 500})
	clock.Advance(240 * time.Hour) // 10 positive half-lives
	score := s.GetScore("a")
	// deviation 500 * 2^-10 ≈ 0.49, rounds to 0
	if score.Score != 500 {
		t.Errorf("after 10 half-lives expected convergence to 500, got %d", score.Score)
	}
}

// ── Registry Events ──────────────────────────────────────────

func TestRegistryKeyAddedAndRevoked(t *testing.T) {
	// Test re-exported via leaderboard-adjacent registry. Covers event count.
	// (Uses package-level types from behavioral.go)
	allEvents := []ScoreEventType{EventPolicyComply, EventPolicyViolate, EventRateLimitHit, EventThreatDetected, EventDelegationValid, EventDelegationAbuse, EventEgressBlocked, EventManualBoost, EventManualPenalty}
	for _, et := range allEvents {
		d := DefaultDeltas[et]
		if et == EventPolicyComply || et == EventDelegationValid || et == EventManualBoost {
			if d <= 0 {
				t.Errorf("%s should have positive delta, got %d", et, d)
			}
		} else {
			if d >= 0 {
				t.Errorf("%s should have negative delta, got %d", et, d)
			}
		}
	}
}

func TestDelegationAbuseHarsherThanViolation(t *testing.T) {
	abuse := DefaultDeltas[EventDelegationAbuse]
	violation := DefaultDeltas[EventPolicyViolate]
	if abuse >= violation {
		t.Errorf("DELEGATION_ABUSE (%d) should be harsher than POLICY_VIOLATE (%d)", abuse, violation)
	}
}

// ── Leaderboard Operations ───────────────────────────────────

func TestLeaderboard_EmptyGetTopN(t *testing.T) {
	lb := NewLeaderboard()
	top := lb.GetTopN(10)
	if len(top) != 0 {
		t.Errorf("empty leaderboard GetTopN should return 0, got %d", len(top))
	}
}

func TestLeaderboard_RankOrderByScore(t *testing.T) {
	scores := map[string]*TrustScore{
		"org-a": {OverallScore: 0.80, ComputedAt: time.Now()},
		"org-b": {OverallScore: 0.95, ComputedAt: time.Now()},
	}
	lb := NewLeaderboardFromScores(scores, map[string]string{"org-a": "Alpha", "org-b": "Beta"})
	if lb.Entries[0].OrgID != "org-b" {
		t.Errorf("expected org-b ranked first (0.95), got %s", lb.Entries[0].OrgID)
	}
}

func TestLeaderboard_GetEntryNotFound(t *testing.T) {
	lb := NewLeaderboard()
	_, found := lb.GetEntry("nonexistent")
	if found {
		t.Error("GetEntry should return false for nonexistent org")
	}
}

func TestLeaderboard_BadgeLevelBoundaries(t *testing.T) {
	cases := []struct {
		score float64
		want  BadgeLevel
	}{
		{0.96, BadgePlatinum}, {0.86, BadgeGold}, {0.71, BadgeSilver}, {0.51, BadgeBronze}, {0.50, BadgeNone},
	}
	for _, tc := range cases {
		if got := GetBadgeLevel(tc.score); got != tc.want {
			t.Errorf("GetBadgeLevel(%f) = %s, want %s", tc.score, got, tc.want)
		}
	}
}

func TestLeaderboard_CountAfterUpdate(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("org-1", "Org1", &TrustScore{OverallScore: 0.5, ComputedAt: time.Now()})
	lb.Rank()
	if lb.Count() != 1 {
		t.Errorf("expected count=1, got %d", lb.Count())
	}
}

func TestNormalized_MaxScore(t *testing.T) {
	b := BehavioralTrustScore{Score: 1000}
	if b.Normalized() != 1.0 {
		t.Errorf("Normalized(1000) should be 1.0, got %f", b.Normalized())
	}
}

func TestNormalized_ZeroScore(t *testing.T) {
	b := BehavioralTrustScore{Score: 0}
	if b.Normalized() != 0.0 {
		t.Errorf("Normalized(0) should be 0.0, got %f", b.Normalized())
	}
}
