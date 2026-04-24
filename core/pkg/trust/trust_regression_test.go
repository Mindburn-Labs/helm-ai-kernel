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

func TestClosing_Leaderboard_Creation(t *testing.T) {
	lb := NewLeaderboard()
	t.Run("not_nil", func(t *testing.T) {
		if lb == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("id_set", func(t *testing.T) {
		if lb.LeaderboardID == "" {
			t.Fatal("ID should be set")
		}
	})
	t.Run("empty_entries", func(t *testing.T) {
		if len(lb.Entries) != 0 {
			t.Fatalf("got %d entries", len(lb.Entries))
		}
	})
}

func TestClosing_Leaderboard_UpdateAndRank(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("org-1", "Org One", &TrustScore{OverallScore: 0.9, ComputedAt: time.Now()})
	lb.UpdateScore("org-2", "Org Two", &TrustScore{OverallScore: 0.5, ComputedAt: time.Now()})
	lb.UpdateScore("org-3", "Org Three", &TrustScore{OverallScore: 0.95, ComputedAt: time.Now()})
	lb.Rank()
	t.Run("three_entries", func(t *testing.T) {
		if lb.Count() != 3 {
			t.Fatalf("got %d", lb.Count())
		}
	})
	t.Run("highest_first", func(t *testing.T) {
		e, ok := lb.GetEntry("org-3")
		if !ok || e.Rank != 1 {
			t.Fatalf("org-3 should be rank 1, got %d", e.Rank)
		}
	})
	t.Run("lowest_last", func(t *testing.T) {
		e, ok := lb.GetEntry("org-2")
		if !ok || e.Rank != 3 {
			t.Fatalf("org-2 should be rank 3, got %d", e.Rank)
		}
	})
}

func TestClosing_Leaderboard_GetTopN(t *testing.T) {
	lb := NewLeaderboard()
	for i := 0; i < 5; i++ {
		lb.UpdateScore(itoa(i), "Org"+itoa(i), &TrustScore{OverallScore: float64(i) * 0.2, ComputedAt: time.Now()})
	}
	lb.Rank()
	t.Run("top_3", func(t *testing.T) {
		top := lb.GetTopN(3)
		if len(top) != 3 {
			t.Fatalf("got %d", len(top))
		}
	})
	t.Run("top_exceeds_count", func(t *testing.T) {
		top := lb.GetTopN(100)
		if len(top) != 5 {
			t.Fatalf("got %d, want 5", len(top))
		}
	})
	t.Run("top_zero", func(t *testing.T) {
		top := lb.GetTopN(0)
		if len(top) != 0 {
			t.Fatalf("got %d", len(top))
		}
	})
}

func TestClosing_BadgeLevel_Values(t *testing.T) {
	cases := []struct {
		score float64
		badge BadgeLevel
	}{
		{0.96, BadgePlatinum},
		{0.90, BadgeGold},
		{0.75, BadgeSilver},
		{0.60, BadgeBronze},
		{0.30, BadgeNone},
	}
	for _, tc := range cases {
		t.Run(string(tc.badge), func(t *testing.T) {
			got := GetBadgeLevel(tc.score)
			if got != tc.badge {
				t.Fatalf("GetBadgeLevel(%f) = %q, want %q", tc.score, got, tc.badge)
			}
		})
	}
}

func TestClosing_Leaderboard_GetByBadge(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("platinum", "P", &TrustScore{OverallScore: 0.96, ComputedAt: time.Now()})
	lb.UpdateScore("gold", "G", &TrustScore{OverallScore: 0.90, ComputedAt: time.Now()})
	lb.UpdateScore("bronze", "B", &TrustScore{OverallScore: 0.55, ComputedAt: time.Now()})
	lb.Rank()
	t.Run("one_platinum", func(t *testing.T) {
		entries := lb.GetByBadge(BadgePlatinum)
		if len(entries) != 1 {
			t.Fatalf("got %d", len(entries))
		}
	})
	t.Run("no_silver", func(t *testing.T) {
		entries := lb.GetByBadge(BadgeSilver)
		if len(entries) != 0 {
			t.Fatalf("got %d", len(entries))
		}
	})
	t.Run("one_bronze", func(t *testing.T) {
		entries := lb.GetByBadge(BadgeBronze)
		if len(entries) != 1 {
			t.Fatalf("got %d", len(entries))
		}
	})
}

func TestClosing_Leaderboard_Export(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("org-1", "Org One", &TrustScore{OverallScore: 0.8, ComputedAt: time.Now()})
	lb.Rank()
	export := lb.Export()
	t.Run("export_not_nil", func(t *testing.T) {
		if export == nil {
			t.Fatal("export should not be nil")
		}
	})
	t.Run("total_orgs", func(t *testing.T) {
		if export.TotalOrgs != 1 {
			t.Fatalf("got %d", export.TotalOrgs)
		}
	})
	t.Run("hash_set", func(t *testing.T) {
		if export.Hash == "" {
			t.Fatal("hash should be set")
		}
	})
	t.Run("average_score", func(t *testing.T) {
		if export.AverageScore != 0.8 {
			t.Fatalf("got %f", export.AverageScore)
		}
	})
}

func TestClosing_Leaderboard_Hash(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("org-1", "O1", &TrustScore{OverallScore: 0.5, ComputedAt: time.Now()})
	lb.Rank()
	h1 := lb.Hash()
	t.Run("nonempty", func(t *testing.T) {
		if h1 == "" {
			t.Fatal("hash should not be empty")
		}
	})
	lb.UpdateScore("org-2", "O2", &TrustScore{OverallScore: 0.9, ComputedAt: time.Now()})
	lb.Rank()
	h2 := lb.Hash()
	t.Run("changes_on_update", func(t *testing.T) {
		if h1 == h2 {
			t.Fatal("hash should change after update")
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		h3 := lb.Hash()
		if h2 != h3 {
			t.Fatal("hash should be deterministic")
		}
	})
}

func TestClosing_Leaderboard_GetEntry(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("org-1", "O1", &TrustScore{OverallScore: 0.7, ComputedAt: time.Now()})
	lb.Rank()
	t.Run("found", func(t *testing.T) {
		e, ok := lb.GetEntry("org-1")
		if !ok || e == nil {
			t.Fatal("should find entry")
		}
	})
	t.Run("not_found", func(t *testing.T) {
		_, ok := lb.GetEntry("nonexistent")
		if ok {
			t.Fatal("should not find")
		}
	})
	t.Run("badge_level_set", func(t *testing.T) {
		e, _ := lb.GetEntry("org-1")
		if e.BadgeLevel == "" && e.TrustScore.OverallScore > 0.50 {
			t.Fatal("badge should be set for score > 0.50")
		}
	})
}

// ---------------------------------------------------------------------------
// 31-37: Compliance stages
// ---------------------------------------------------------------------------

func TestClosing_ComplianceMatrix_Creation(t *testing.T) {
	m := NewComplianceMatrix()
	t.Run("not_nil", func(t *testing.T) {
		if m == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("id_set", func(t *testing.T) {
		if m.MatrixID == "" {
			t.Fatal("ID should be set")
		}
	})
	t.Run("empty_frameworks", func(t *testing.T) {
		if len(m.Frameworks) != 0 {
			t.Fatalf("got %d", len(m.Frameworks))
		}
	})
}

func TestClosing_ComplianceMatrix_AddFramework(t *testing.T) {
	m := NewComplianceMatrix()
	fw := &Framework{FrameworkID: "gdpr", Name: "GDPR", Version: "1.0"}
	m.AddFramework(fw)
	t.Run("framework_added", func(t *testing.T) {
		if len(m.Frameworks) != 1 {
			t.Fatalf("got %d", len(m.Frameworks))
		}
	})
	t.Run("framework_by_id", func(t *testing.T) {
		if _, ok := m.Frameworks["gdpr"]; !ok {
			t.Fatal("should find by ID")
		}
	})
	t.Run("timestamp_set", func(t *testing.T) {
		if m.Frameworks["gdpr"].CreatedAt.IsZero() {
			t.Fatal("created_at should be set")
		}
	})
}

func TestClosing_ComplianceMatrix_AddControl(t *testing.T) {
	m := NewComplianceMatrix()
	m.AddFramework(&Framework{FrameworkID: "sox"})
	ctrl := &Control{ControlID: "c1", FrameworkID: "sox", Title: "Test Control", Severity: SeverityHigh}
	t.Run("add_succeeds", func(t *testing.T) {
		err := m.AddControl(ctrl)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("missing_framework_errors", func(t *testing.T) {
		err := m.AddControl(&Control{ControlID: "c2", FrameworkID: "missing"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("status_not_assessed", func(t *testing.T) {
		if m.Controls["c1"].Status != ControlNotAssessed {
			t.Fatalf("got %q", m.Controls["c1"].Status)
		}
	})
}

func TestClosing_Severity_Values(t *testing.T) {
	severities := []struct {
		s    Severity
		name string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
	}
	for _, tc := range severities {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.s) != tc.name {
				t.Fatalf("got %q", tc.s)
			}
		})
	}
}

func TestClosing_ControlStatus_Values(t *testing.T) {
	statuses := []struct {
		s    ControlStatus
		name string
	}{
		{ControlCompliant, "compliant"},
		{ControlNonCompliant, "non_compliant"},
		{ControlPartial, "partial"},
		{ControlNotAssessed, "not_assessed"},
	}
	for _, tc := range statuses {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.s) != tc.name {
				t.Fatalf("got %q", tc.s)
			}
		})
	}
}

func TestClosing_EvidenceType_Values(t *testing.T) {
	types := []struct {
		et   EvidenceType
		name string
	}{
		{EvidenceDocument, "document"},
		{EvidenceLog, "log"},
		{EvidenceScreenshot, "screenshot"},
		{EvidenceTestResult, "test_result"},
		{EvidenceConfig, "config"},
		{EvidenceAttestation, "attestation"},
	}
	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.et) != tc.name {
				t.Fatalf("got %q", tc.et)
			}
		})
	}
}

func TestClosing_ComplianceMatrix_AssessControl(t *testing.T) {
	m := NewComplianceMatrix()
	m.AddFramework(&Framework{FrameworkID: "hipaa"})
	m.AddControl(&Control{ControlID: "c1", FrameworkID: "hipaa"})
	t.Run("assess_compliant", func(t *testing.T) {
		err := m.AssessControl("c1", ControlCompliant)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m.Controls["c1"].Status != ControlCompliant {
			t.Fatalf("got %q", m.Controls["c1"].Status)
		}
	})
	t.Run("assess_unknown_errors", func(t *testing.T) {
		err := m.AssessControl("unknown", ControlCompliant)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("assess_noncompliant", func(t *testing.T) {
		m.AssessControl("c1", ControlNonCompliant)
		if m.Controls["c1"].Status != ControlNonCompliant {
			t.Fatalf("got %q", m.Controls["c1"].Status)
		}
	})
}

// ---------------------------------------------------------------------------
// 38-43: Certification gate
// ---------------------------------------------------------------------------

func TestClosing_CertificationLevel_Values(t *testing.T) {
	levels := []struct {
		l    CertificationLevel
		name string
	}{
		{CertNone, "NONE"},
		{CertBasic, "BASIC"},
		{CertVerified, "VERIFIED"},
		{CertProduction, "PRODUCTION"},
	}
	for _, tc := range levels {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.l) != tc.name {
				t.Fatalf("got %q", tc.l)
			}
		})
	}
}

func TestClosing_CertificationGate_CheckInstall(t *testing.T) {
	gate := NewCertificationGate()
	gate.SetRequirement("production", CertProduction)
	gate.RecordCertification(&CertificationRecord{PackName: "pack1", PackVersion: "1.0", Level: CertBasic})
	t.Run("basic_fails_production", func(t *testing.T) {
		err := gate.CheckInstall("pack1", "1.0", "production")
		if err == nil {
			t.Fatal("basic cert should fail production requirement")
		}
	})
	gate.RecordCertification(&CertificationRecord{PackName: "pack2", PackVersion: "1.0", Level: CertProduction})
	t.Run("production_passes", func(t *testing.T) {
		err := gate.CheckInstall("pack2", "1.0", "production")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("unknown_pack_errors", func(t *testing.T) {
		err := gate.CheckInstall("unknown", "1.0", "production")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("default_requires_basic", func(t *testing.T) {
		gate.RecordCertification(&CertificationRecord{PackName: "pack3", PackVersion: "1.0", Level: CertNone})
		err := gate.CheckInstall("pack3", "1.0", "unset-context")
		if err == nil {
			t.Fatal("NONE should fail default BASIC requirement")
		}
	})
}

func TestClosing_CertificationGate_GetCertification(t *testing.T) {
	gate := NewCertificationGate()
	gate.RecordCertification(&CertificationRecord{PackName: "p1", PackVersion: "2.0", Level: CertVerified})
	t.Run("found", func(t *testing.T) {
		r, err := gate.GetCertification("p1", "2.0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if r.Level != CertVerified {
			t.Fatalf("got %q", r.Level)
		}
	})
	t.Run("not_found", func(t *testing.T) {
		_, err := gate.GetCertification("missing", "1.0")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("wrong_version", func(t *testing.T) {
		_, err := gate.GetCertification("p1", "3.0")
		if err == nil {
			t.Fatal("expected error for wrong version")
		}
	})
}

// ---------------------------------------------------------------------------
// 44-50: ComputeTrustScore, PackMetrics, AdversarialLab
// ---------------------------------------------------------------------------

func TestClosing_ComputeTrustScore_EmptyInputs(t *testing.T) {
	m := NewComplianceMatrix()
	lab := NewAdversarialLab()
	score := ComputeTrustScore(m, lab)
	t.Run("not_nil", func(t *testing.T) {
		if score == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("zero_overall", func(t *testing.T) {
		if score.OverallScore != 0 {
			t.Fatalf("got %f", score.OverallScore)
		}
	})
	t.Run("id_set", func(t *testing.T) {
		if score.ScoreID == "" {
			t.Fatal("ID should be set")
		}
	})
}

func TestClosing_ComputePackTrustScore(t *testing.T) {
	metrics := PackMetrics{
		AttestationCompleteness: 1.0,
		ReplayDeterminism:       1.0,
		InjectionResilience:     1.0,
		SLOAdherence:            1.0,
	}
	score := ComputePackTrustScore(metrics)
	t.Run("perfect_score", func(t *testing.T) {
		if score.PackScore != 1.0 {
			t.Fatalf("got %f", score.PackScore)
		}
	})
	t.Run("overall_equals_pack", func(t *testing.T) {
		if score.OverallScore != score.PackScore {
			t.Fatalf("overall %f != pack %f", score.OverallScore, score.PackScore)
		}
	})
	t.Run("breakdown_set", func(t *testing.T) {
		if len(score.Breakdown) == 0 {
			t.Fatal("breakdown should have entries")
		}
	})
}

func TestClosing_ComputePackTrustScore_ZeroMetrics(t *testing.T) {
	metrics := PackMetrics{}
	score := ComputePackTrustScore(metrics)
	t.Run("zero_pack_score", func(t *testing.T) {
		if score.PackScore != 0.0 {
			t.Fatalf("got %f", score.PackScore)
		}
	})
	t.Run("zero_overall", func(t *testing.T) {
		if score.OverallScore != 0.0 {
			t.Fatalf("got %f", score.OverallScore)
		}
	})
	t.Run("breakdown_zeros", func(t *testing.T) {
		for key, val := range score.Breakdown {
			if key == "pack_score" && val != 0.0 {
				t.Fatalf("pack_score should be 0, got %f", val)
			}
		}
	})
}

func TestClosing_AdversarialLab_Creation(t *testing.T) {
	lab := NewAdversarialLab()
	t.Run("not_nil", func(t *testing.T) {
		if lab == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("id_set", func(t *testing.T) {
		if lab.LabID == "" {
			t.Fatal("ID should be set")
		}
	})
	t.Run("empty_suites", func(t *testing.T) {
		if len(lab.GetSuites()) != 0 {
			t.Fatalf("got %d suites", len(lab.GetSuites()))
		}
	})
}

func TestClosing_AdversarialLab_RunSuite(t *testing.T) {
	lab := NewAdversarialLab()
	suite := &TestSuite{
		SuiteID: "suite-1",
		Name:    "Basic Tests",
		Tests: []TestCase{
			{TestID: "t1", Name: "pass test", Runner: func() TestResult { return TestResult{Passed: true, Message: "ok"} }},
			{TestID: "t2", Name: "fail test", Runner: func() TestResult { return TestResult{Passed: false, Message: "fail"} }},
			{TestID: "t3", Name: "no runner"},
		},
	}
	lab.RegisterSuite(suite)
	run, err := lab.RunSuite("suite-1")
	t.Run("no_error", func(t *testing.T) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("pass_count", func(t *testing.T) {
		if run.PassCount != 2 {
			t.Fatalf("got %d, want 2", run.PassCount)
		}
	})
	t.Run("fail_count", func(t *testing.T) {
		if run.FailCount != 1 {
			t.Fatalf("got %d, want 1", run.FailCount)
		}
	})
	t.Run("status_failed", func(t *testing.T) {
		if run.Status != "failed" {
			t.Fatalf("got %q", run.Status)
		}
	})
}

func TestClosing_AdversarialLab_UnknownSuiteErrors(t *testing.T) {
	lab := NewAdversarialLab()
	t.Run("run_unknown_errors", func(t *testing.T) {
		_, err := lab.RunSuite("nonexistent")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("register_then_run", func(t *testing.T) {
		lab.RegisterSuite(&TestSuite{SuiteID: "s1", Tests: []TestCase{{TestID: "t1", Name: "test"}}})
		run, err := lab.RunSuite("s1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if run.Status != "passed" {
			t.Fatalf("got %q", run.Status)
		}
	})
	t.Run("results_accumulate", func(t *testing.T) {
		if len(lab.Results) != 1 {
			t.Fatalf("got %d results", len(lab.Results))
		}
	})
}

func TestClosing_ComplianceMatrix_Hash(t *testing.T) {
	m := NewComplianceMatrix()
	t.Run("nonempty_hash", func(t *testing.T) {
		h := m.Hash()
		if h == "" {
			t.Fatal("hash should not be empty")
		}
	})
	m.AddFramework(&Framework{FrameworkID: "gdpr"})
	t.Run("hash_changes", func(t *testing.T) {
		h1 := m.Hash()
		m.AddFramework(&Framework{FrameworkID: "hipaa"})
		h2 := m.Hash()
		if h1 == h2 {
			t.Fatal("hash should change after adding framework")
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		h1 := m.Hash()
		h2 := m.Hash()
		if h1 != h2 {
			t.Fatal("hash should be deterministic")
		}
	})
}

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
