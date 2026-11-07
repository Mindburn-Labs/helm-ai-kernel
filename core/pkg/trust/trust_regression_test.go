package trust

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1-5: TrustTier boundary coverage
// ---------------------------------------------------------------------------

func TestClosing_TrustTier_Boundaries(t *testing.T) {
	cases := []struct {
		score int
		tier  TrustTier
	}{
		{0, TierHostile},
		{199, TierHostile},
		{200, TierSuspect},
		{399, TierSuspect},
		{400, TierNeutral},
		{699, TierNeutral},
		{700, TierTrusted},
		{899, TierTrusted},
		{900, TierPristine},
		{1000, TierPristine},
	}
	for _, tc := range cases {
		t.Run(string(tc.tier)+"_at_"+itoa(tc.score), func(t *testing.T) {
			got := TierForScore(tc.score)
			if got != tc.tier {
				t.Fatalf("TierForScore(%d) = %q, want %q", tc.score, got, tc.tier)
			}
		})
	}
}

func TestClosing_TrustTier_ExtremeValues(t *testing.T) {
	t.Run("negative", func(t *testing.T) {
		if TierForScore(-1) != TierHostile {
			t.Fatal("negative should be HOSTILE")
		}
	})
	t.Run("very_high", func(t *testing.T) {
		if TierForScore(9999) != TierPristine {
			t.Fatal("9999 should be PRISTINE")
		}
	})
	t.Run("zero", func(t *testing.T) {
		if TierForScore(0) != TierHostile {
			t.Fatal("0 should be HOSTILE")
		}
	})
}

func TestClosing_TrustTier_StringValues(t *testing.T) {
	tiers := []struct {
		tier TrustTier
		name string
	}{
		{TierPristine, "PRISTINE"},
		{TierTrusted, "TRUSTED"},
		{TierNeutral, "NEUTRAL"},
		{TierSuspect, "SUSPECT"},
		{TierHostile, "HOSTILE"},
	}
	for _, tc := range tiers {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.tier) != tc.name {
				t.Fatalf("got %q", tc.tier)
			}
		})
	}
}

func TestClosing_TrustTier_TransitionBoundaries(t *testing.T) {
	t.Run("hostile_to_suspect", func(t *testing.T) {
		if TierForScore(199) == TierForScore(200) {
			t.Fatal("199 and 200 should be different tiers")
		}
	})
	t.Run("suspect_to_neutral", func(t *testing.T) {
		if TierForScore(399) == TierForScore(400) {
			t.Fatal("399 and 400 should be different tiers")
		}
	})
	t.Run("neutral_to_trusted", func(t *testing.T) {
		if TierForScore(699) == TierForScore(700) {
			t.Fatal("699 and 700 should be different tiers")
		}
	})
	t.Run("trusted_to_pristine", func(t *testing.T) {
		if TierForScore(899) == TierForScore(900) {
			t.Fatal("899 and 900 should be different tiers")
		}
	})
}

func TestClosing_TrustTier_AllFiveTiers(t *testing.T) {
	expectedTiers := map[TrustTier]bool{TierHostile: true, TierSuspect: true, TierNeutral: true, TierTrusted: true, TierPristine: true}
	foundTiers := make(map[TrustTier]bool)
	for score := 0; score <= 1000; score += 100 {
		foundTiers[TierForScore(score)] = true
	}
	for tier := range expectedTiers {
		t.Run(string(tier), func(t *testing.T) {
			if !foundTiers[tier] {
				t.Fatalf("tier %s not found in score range 0-1000", tier)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 6-10: ScoreEventType coverage
// ---------------------------------------------------------------------------

func TestClosing_ScoreEventType_AllTypes(t *testing.T) {
	types := []struct {
		event ScoreEventType
		name  string
	}{
		{EventPolicyComply, "POLICY_COMPLY"},
		{EventPolicyViolate, "POLICY_VIOLATE"},
		{EventRateLimitHit, "RATE_LIMIT_HIT"},
		{EventThreatDetected, "THREAT_DETECTED"},
		{EventDelegationValid, "DELEGATION_VALID"},
		{EventDelegationAbuse, "DELEGATION_ABUSE"},
		{EventEgressBlocked, "EGRESS_BLOCKED"},
		{EventManualBoost, "MANUAL_BOOST"},
		{EventManualPenalty, "MANUAL_PENALTY"},
	}
	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.event) != tc.name {
				t.Fatalf("got %q", tc.event)
			}
		})
	}
}

func TestClosing_ScoreEventType_GoodVsBad(t *testing.T) {
	goodEvents := []ScoreEventType{EventPolicyComply, EventDelegationValid, EventManualBoost}
	badEvents := []ScoreEventType{EventPolicyViolate, EventRateLimitHit, EventThreatDetected, EventDelegationAbuse, EventEgressBlocked, EventManualPenalty}
	t.Run("good_events_positive_delta", func(t *testing.T) {
		for _, evt := range goodEvents {
			if DefaultDeltas[evt] <= 0 {
				t.Fatalf("%s should have positive delta, got %d", evt, DefaultDeltas[evt])
			}
		}
	})
	t.Run("bad_events_negative_delta", func(t *testing.T) {
		for _, evt := range badEvents {
			if DefaultDeltas[evt] >= 0 {
				t.Fatalf("%s should have negative delta, got %d", evt, DefaultDeltas[evt])
			}
		}
	})
	t.Run("asymmetric_trust", func(t *testing.T) {
		// Negative deltas should be larger in magnitude than positive
		maxGood := 0
		for _, evt := range goodEvents {
			if DefaultDeltas[evt] > maxGood {
				maxGood = DefaultDeltas[evt]
			}
		}
		minBad := 0
		for _, evt := range badEvents {
			if DefaultDeltas[evt] < minBad {
				minBad = DefaultDeltas[evt]
			}
		}
		if maxGood >= -minBad {
			t.Fatal("bad deltas should be larger in magnitude than good deltas")
		}
	})
}

func TestClosing_ScoreEventType_Count(t *testing.T) {
	t.Run("nine_event_types", func(t *testing.T) {
		if len(DefaultDeltas) != 9 {
			t.Fatalf("got %d event types, want 9", len(DefaultDeltas))
		}
	})
	t.Run("all_in_map", func(t *testing.T) {
		allTypes := []ScoreEventType{EventPolicyComply, EventPolicyViolate, EventRateLimitHit, EventThreatDetected, EventDelegationValid, EventDelegationAbuse, EventEgressBlocked, EventManualBoost, EventManualPenalty}
		for _, evt := range allTypes {
			if _, ok := DefaultDeltas[evt]; !ok {
				t.Fatalf("%s not in DefaultDeltas", evt)
			}
		}
	})
	t.Run("no_zero_deltas", func(t *testing.T) {
		for evt, delta := range DefaultDeltas {
			if delta == 0 {
				t.Fatalf("%s has zero delta", evt)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 11-15: DefaultDelta subtests
// ---------------------------------------------------------------------------

func TestClosing_DefaultDeltas_Values(t *testing.T) {
	for evt, delta := range DefaultDeltas {
		t.Run(string(evt), func(t *testing.T) {
			if delta == 0 {
				t.Fatalf("delta for %s should not be zero", evt)
			}
		})
	}
}

func TestClosing_DefaultDeltas_SpecificValues(t *testing.T) {
	t.Run("policy_comply_is_2", func(t *testing.T) {
		if DefaultDeltas[EventPolicyComply] != 2 {
			t.Fatalf("got %d", DefaultDeltas[EventPolicyComply])
		}
	})
	t.Run("policy_violate_is_minus25", func(t *testing.T) {
		if DefaultDeltas[EventPolicyViolate] != -25 {
			t.Fatalf("got %d", DefaultDeltas[EventPolicyViolate])
		}
	})
	t.Run("threat_detected_is_minus50", func(t *testing.T) {
		if DefaultDeltas[EventThreatDetected] != -50 {
			t.Fatalf("got %d", DefaultDeltas[EventThreatDetected])
		}
	})
	t.Run("delegation_abuse_is_minus75", func(t *testing.T) {
		if DefaultDeltas[EventDelegationAbuse] != -75 {
			t.Fatalf("got %d", DefaultDeltas[EventDelegationAbuse])
		}
	})
}

func TestClosing_DefaultDeltas_ManualOps(t *testing.T) {
	t.Run("manual_boost", func(t *testing.T) {
		if DefaultDeltas[EventManualBoost] != 50 {
			t.Fatalf("got %d", DefaultDeltas[EventManualBoost])
		}
	})
	t.Run("manual_penalty", func(t *testing.T) {
		if DefaultDeltas[EventManualPenalty] != -50 {
			t.Fatalf("got %d", DefaultDeltas[EventManualPenalty])
		}
	})
	t.Run("symmetric_manual", func(t *testing.T) {
		if DefaultDeltas[EventManualBoost] != -DefaultDeltas[EventManualPenalty] {
			t.Fatal("manual boost and penalty should be symmetric")
		}
	})
}

func TestClosing_DefaultDeltas_SmallPositive(t *testing.T) {
	t.Run("comply_small", func(t *testing.T) {
		if DefaultDeltas[EventPolicyComply] > 10 {
			t.Fatal("good actions should have small deltas")
		}
	})
	t.Run("delegation_valid_small", func(t *testing.T) {
		if DefaultDeltas[EventDelegationValid] > 10 {
			t.Fatal("good actions should have small deltas")
		}
	})
	t.Run("both_positive", func(t *testing.T) {
		if DefaultDeltas[EventPolicyComply] <= 0 || DefaultDeltas[EventDelegationValid] <= 0 {
			t.Fatal("good events should be positive")
		}
	})
}

func TestClosing_DefaultDeltas_LargeNegative(t *testing.T) {
	largeBad := []ScoreEventType{EventThreatDetected, EventDelegationAbuse}
	for _, evt := range largeBad {
		t.Run(string(evt), func(t *testing.T) {
			if DefaultDeltas[evt] > -40 {
				t.Fatalf("expected large negative delta, got %d", DefaultDeltas[evt])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 16-22: Registry event types
// ---------------------------------------------------------------------------

func TestClosing_BehavioralTrustScorer_InitialScore(t *testing.T) {
	scorer := NewBehavioralTrustScorer()
	t.Run("default_500", func(t *testing.T) {
		s := scorer.GetScore("new-agent")
		if s.Score != 500 {
			t.Fatalf("got %d, want 500", s.Score)
		}
	})
	t.Run("tier_neutral", func(t *testing.T) {
		s := scorer.GetScore("new-agent")
		if s.Tier != TierNeutral {
			t.Fatalf("got %q", s.Tier)
		}
	})
	t.Run("empty_history", func(t *testing.T) {
		s := scorer.GetScore("new-agent")
		if len(s.History) != 0 {
			t.Fatalf("got %d history entries", len(s.History))
		}
	})
}

func TestClosing_BehavioralTrustScorer_RecordEvent(t *testing.T) {
	scorer := NewBehavioralTrustScorer()
	scorer.RecordEvent("agent-1", ScoreEvent{EventType: EventPolicyComply})
	t.Run("score_increased", func(t *testing.T) {
		s := scorer.GetScore("agent-1")
		if s.Score <= 500 {
			t.Fatalf("expected > 500, got %d", s.Score)
		}
	})
	scorer.RecordEvent("agent-1", ScoreEvent{EventType: EventPolicyViolate})
	t.Run("score_decreased", func(t *testing.T) {
		s := scorer.GetScore("agent-1")
		if s.Score >= 502 {
			t.Fatalf("expected decrease from violation, got %d", s.Score)
		}
	})
	t.Run("history_grows", func(t *testing.T) {
		s := scorer.GetScore("agent-1")
		if len(s.History) != 2 {
			t.Fatalf("got %d history entries, want 2", len(s.History))
		}
	})
}

func TestClosing_BehavioralTrustScorer_GetTier(t *testing.T) {
	scorer := NewBehavioralTrustScorer()
	t.Run("new_agent_neutral", func(t *testing.T) {
		if scorer.GetTier("agent-x") != TierNeutral {
			t.Fatalf("got %q", scorer.GetTier("agent-x"))
		}
	})
	// Drive score down
	for i := 0; i < 20; i++ {
		scorer.RecordEvent("bad-agent", ScoreEvent{EventType: EventThreatDetected})
	}
	t.Run("bad_agent_hostile", func(t *testing.T) {
		tier := scorer.GetTier("bad-agent")
		if tier != TierHostile {
			t.Fatalf("got %q, expected HOSTILE", tier)
		}
	})
	// Drive score up
	for i := 0; i < 200; i++ {
		scorer.RecordEvent("good-agent", ScoreEvent{EventType: EventManualBoost})
	}
	t.Run("good_agent_pristine", func(t *testing.T) {
		tier := scorer.GetTier("good-agent")
		if tier != TierPristine {
			t.Fatalf("got %q, expected PRISTINE", tier)
		}
	})
}

func TestClosing_BehavioralTrustScorer_CustomConfig(t *testing.T) {
	cfg := ScorerConfig{InitialScore: 800, MaxHistorySize: 5, PositiveHalfLife: time.Hour, NegativeHalfLife: time.Hour}
	scorer := NewBehavioralTrustScorer(WithScorerConfig(cfg))
	t.Run("custom_initial", func(t *testing.T) {
		s := scorer.GetScore("agent")
		if s.Score != 800 {
			t.Fatalf("got %d, want 800", s.Score)
		}
	})
	t.Run("custom_tier", func(t *testing.T) {
		s := scorer.GetScore("agent")
		if s.Tier != TierTrusted {
			t.Fatalf("got %q", s.Tier)
		}
	})
	t.Run("history_bounded", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			scorer.RecordEvent("agent", ScoreEvent{EventType: EventPolicyComply})
		}
		s := scorer.GetScore("agent")
		if len(s.History) > 5 {
			t.Fatalf("history should be bounded to 5, got %d", len(s.History))
		}
	})
}

func TestClosing_BehavioralTrustScorer_Normalized(t *testing.T) {
	scorer := NewBehavioralTrustScorer()
	s := scorer.GetScore("agent")
	t.Run("normalized_range", func(t *testing.T) {
		n := s.Normalized()
		if n < 0.0 || n > 1.0 {
			t.Fatalf("normalized %f out of range", n)
		}
	})
	t.Run("normalized_500_is_0.5", func(t *testing.T) {
		if s.Normalized() != 0.5 {
			t.Fatalf("got %f", s.Normalized())
		}
	})
	t.Run("zero_score_zero_normalized", func(t *testing.T) {
		zs := BehavioralTrustScore{Score: 0}
		if zs.Normalized() != 0.0 {
			t.Fatalf("got %f", zs.Normalized())
		}
	})
	t.Run("max_score_one_normalized", func(t *testing.T) {
		ms := BehavioralTrustScore{Score: 1000}
		if ms.Normalized() != 1.0 {
			t.Fatalf("got %f", ms.Normalized())
		}
	})
}

func TestClosing_BehavioralTrustScorer_DefaultConfig(t *testing.T) {
	cfg := DefaultScorerConfig()
	t.Run("initial_500", func(t *testing.T) {
		if cfg.InitialScore != 500 {
			t.Fatalf("got %d", cfg.InitialScore)
		}
	})
	t.Run("max_history_100", func(t *testing.T) {
		if cfg.MaxHistorySize != 100 {
			t.Fatalf("got %d", cfg.MaxHistorySize)
		}
	})
	t.Run("positive_half_life_24h", func(t *testing.T) {
		if cfg.PositiveHalfLife != 24*time.Hour {
			t.Fatalf("got %v", cfg.PositiveHalfLife)
		}
	})
	t.Run("negative_half_life_72h", func(t *testing.T) {
		if cfg.NegativeHalfLife != 72*time.Hour {
			t.Fatalf("got %v", cfg.NegativeHalfLife)
		}
	})
}

func TestClosing_BehavioralTrustScorer_ClampScore(t *testing.T) {
	t.Run("clamp_below_zero", func(t *testing.T) {
		if clampScore(-10) != 0 {
			t.Fatalf("got %d", clampScore(-10))
		}
	})
	t.Run("clamp_above_1000", func(t *testing.T) {
		if clampScore(1100) != 1000 {
			t.Fatalf("got %d", clampScore(1100))
		}
	})
	t.Run("no_clamp_500", func(t *testing.T) {
		if clampScore(500) != 500 {
			t.Fatalf("got %d", clampScore(500))
		}
	})
	t.Run("boundary_0", func(t *testing.T) {
		if clampScore(0) != 0 {
			t.Fatalf("got %d", clampScore(0))
		}
	})
	t.Run("boundary_1000", func(t *testing.T) {
		if clampScore(1000) != 1000 {
			t.Fatalf("got %d", clampScore(1000))
		}
	})
}

// ---------------------------------------------------------------------------
// 23-30: Leaderboard ops
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 31-37: Compliance stages
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 38-43: Certification gate
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 44-50: ComputeTrustScore, PackMetrics, AdversarialLab
// ---------------------------------------------------------------------------

// itoa is a simple int-to-string helper for test naming.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	result := ""
	n := i
	if n < 0 {
		n = -n
	}
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	if i < 0 {
		result = "-" + result
	}
	return result
}
