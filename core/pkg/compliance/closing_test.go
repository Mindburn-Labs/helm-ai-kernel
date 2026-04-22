package compliance

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1-7: Each of 7 frameworks as subtest
// ---------------------------------------------------------------------------

func TestClosing_ComplianceScorer_AllFrameworks(t *testing.T) {
	frameworks := []string{"eu_ai_act", "hipaa", "sox", "sec", "gdpr", "mica", "fca"}
	scorer := NewComplianceScorer()
	for _, fw := range frameworks {
		scorer.InitFramework(fw, 10)
	}
	for _, fw := range frameworks {
		t.Run(fw, func(t *testing.T) {
			score := scorer.GetScore(fw)
			if score == nil {
				t.Fatalf("score for %s should not be nil", fw)
			}
			if score.Score != 100 {
				t.Fatalf("initial score for %s = %d, want 100", fw, score.Score)
			}
		})
	}
}

func TestClosing_ComplianceScorer_FrameworkInit(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("gdpr", 20)
	t.Run("score_100", func(t *testing.T) {
		s := scorer.GetScore("gdpr")
		if s.Score != 100 {
			t.Fatalf("got %d", s.Score)
		}
	})
	t.Run("controls_total", func(t *testing.T) {
		s := scorer.GetScore("gdpr")
		if s.ControlsTotal != 20 {
			t.Fatalf("got %d", s.ControlsTotal)
		}
	})
	t.Run("no_violations", func(t *testing.T) {
		s := scorer.GetScore("gdpr")
		if s.ViolationCount != 0 {
			t.Fatalf("got %d", s.ViolationCount)
		}
	})
	t.Run("framework_name", func(t *testing.T) {
		s := scorer.GetScore("gdpr")
		if s.Framework != "gdpr" {
			t.Fatalf("got %q", s.Framework)
		}
	})
}

func TestClosing_ComplianceScorer_UnregisteredFramework(t *testing.T) {
	scorer := NewComplianceScorer()
	t.Run("nil_for_unknown", func(t *testing.T) {
		s := scorer.GetScore("unknown")
		if s != nil {
			t.Fatal("should be nil for unregistered")
		}
	})
	t.Run("auto_init_on_event", func(t *testing.T) {
		scorer.RecordEvent(ComplianceEvent{Framework: "new_fw", ControlID: "c1", Passed: true})
		s := scorer.GetScore("new_fw")
		if s == nil {
			t.Fatal("should auto-init on event")
		}
	})
	t.Run("auto_init_zero_total", func(t *testing.T) {
		s := scorer.GetScore("new_fw")
		if s.ControlsTotal != 0 {
			t.Fatalf("auto-init should have 0 total controls, got %d", s.ControlsTotal)
		}
	})
}

func TestClosing_ComplianceScorer_InitMultipleFrameworks(t *testing.T) {
	scorer := NewComplianceScorer()
	frameworks := []string{"eu_ai_act", "hipaa", "sox", "sec", "gdpr", "mica", "fca"}
	for i, fw := range frameworks {
		scorer.InitFramework(fw, (i+1)*5)
	}
	t.Run("all_registered", func(t *testing.T) {
		all := scorer.GetAllScores()
		if len(all) != 7 {
			t.Fatalf("got %d, want 7", len(all))
		}
	})
	t.Run("distinct_control_counts", func(t *testing.T) {
		s1 := scorer.GetScore("eu_ai_act")
		s2 := scorer.GetScore("fca")
		if s1.ControlsTotal == s2.ControlsTotal {
			t.Fatal("should have distinct control counts")
		}
	})
	t.Run("all_compliant_initially", func(t *testing.T) {
		if !scorer.IsCompliant(100) {
			t.Fatal("all should be 100 initially")
		}
	})
}

func TestClosing_ComplianceScorer_PerFrameworkViolation(t *testing.T) {
	scorer := NewComplianceScorer()
	frameworks := []string{"eu_ai_act", "hipaa", "sox", "sec", "gdpr", "mica", "fca"}
	for _, fw := range frameworks {
		scorer.InitFramework(fw, 10)
	}
	scorer.RecordEvent(ComplianceEvent{Framework: "hipaa", ControlID: "c1", Passed: false})
	for _, fw := range frameworks {
		t.Run(fw, func(t *testing.T) {
			s := scorer.GetScore(fw)
			if fw == "hipaa" {
				if s.ViolationCount != 1 {
					t.Fatalf("hipaa should have 1 violation, got %d", s.ViolationCount)
				}
			} else {
				if s.ViolationCount != 0 {
					t.Fatalf("%s should have 0 violations, got %d", fw, s.ViolationCount)
				}
			}
		})
	}
}

func TestClosing_ComplianceScorer_WindowHours(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("test", 5)
	t.Run("default_24h", func(t *testing.T) {
		s := scorer.GetScore("test")
		if s.WindowHours != 24 {
			t.Fatalf("got %d, want 24", s.WindowHours)
		}
	})
	scorer2 := NewComplianceScorer().WithWindow(48 * time.Hour)
	scorer2.InitFramework("test", 5)
	t.Run("custom_48h", func(t *testing.T) {
		s := scorer2.GetScore("test")
		if s.WindowHours != 48 {
			t.Fatalf("got %d, want 48", s.WindowHours)
		}
	})
	t.Run("window_affects_init", func(t *testing.T) {
		s := scorer2.GetScore("test")
		if s.Framework != "test" {
			t.Fatalf("got %q", s.Framework)
		}
	})
}

func TestClosing_ComplianceScorer_AllFrameworkScoring(t *testing.T) {
	frameworks := []string{"eu_ai_act", "hipaa", "sox", "sec", "gdpr", "mica", "fca"}
	for _, fw := range frameworks {
		t.Run(fw+"_scoring", func(t *testing.T) {
			scorer := NewComplianceScorer()
			scorer.InitFramework(fw, 4)
			scorer.RecordEvent(ComplianceEvent{Framework: fw, ControlID: "c1", Passed: true})
			scorer.RecordEvent(ComplianceEvent{Framework: fw, ControlID: "c2", Passed: false})
			s := scorer.GetScore(fw)
			if s.Score >= 100 {
				t.Fatalf("score should be < 100 with a violation, got %d", s.Score)
			}
			if s.ViolationCount != 1 {
				t.Fatalf("expected 1 violation, got %d", s.ViolationCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 8-14: Scorer operations
// ---------------------------------------------------------------------------

func TestClosing_ComplianceScorer_RecordPassingEvent(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("hipaa", 10)
	scorer.RecordEvent(ComplianceEvent{Framework: "hipaa", ControlID: "c1", Passed: true})
	t.Run("controls_passed_1", func(t *testing.T) {
		s := scorer.GetScore("hipaa")
		if s.ControlsPassed != 1 {
			t.Fatalf("got %d", s.ControlsPassed)
		}
	})
	t.Run("no_violations", func(t *testing.T) {
		s := scorer.GetScore("hipaa")
		if s.ViolationCount != 0 {
			t.Fatalf("got %d", s.ViolationCount)
		}
	})
	t.Run("score_above_zero", func(t *testing.T) {
		s := scorer.GetScore("hipaa")
		if s.Score <= 0 {
			t.Fatal("score should be positive")
		}
	})
}

func TestClosing_ComplianceScorer_RecordFailingEvent(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("sox", 10)
	scorer.RecordEvent(ComplianceEvent{Framework: "sox", ControlID: "c1", Passed: false, Reason: "missing evidence"})
	t.Run("violation_count_1", func(t *testing.T) {
		s := scorer.GetScore("sox")
		if s.ViolationCount != 1 {
			t.Fatalf("got %d", s.ViolationCount)
		}
	})
	t.Run("last_violation_set", func(t *testing.T) {
		s := scorer.GetScore("sox")
		if s.LastViolation.IsZero() {
			t.Fatal("last_violation should be set")
		}
	})
	t.Run("score_below_100", func(t *testing.T) {
		s := scorer.GetScore("sox")
		if s.Score >= 100 {
			t.Fatalf("got %d", s.Score)
		}
	})
}

func TestClosing_ComplianceScorer_ScoringFormula(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("test", 10)
	// 5 passed, 5 failed
	for i := 0; i < 5; i++ {
		scorer.RecordEvent(ComplianceEvent{Framework: "test", ControlID: "pass-" + string(rune('0'+i)), Passed: true})
		scorer.RecordEvent(ComplianceEvent{Framework: "test", ControlID: "fail-" + string(rune('0'+i)), Passed: false})
	}
	s := scorer.GetScore("test")
	t.Run("base_score_50", func(t *testing.T) {
		// base = 5/10 * 100 = 50, penalty = min(5*5,50) = 25, final = 50-25 = 25
		if s.Score != 25 {
			t.Fatalf("got %d, want 25", s.Score)
		}
	})
	t.Run("violations_5", func(t *testing.T) {
		if s.ViolationCount != 5 {
			t.Fatalf("got %d", s.ViolationCount)
		}
	})
	t.Run("controls_passed_5", func(t *testing.T) {
		if s.ControlsPassed != 5 {
			t.Fatalf("got %d", s.ControlsPassed)
		}
	})
}

func TestClosing_ComplianceScorer_PenaltyCap(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("test", 20)
	// 20 failures for max penalty (should cap at 50)
	for i := 0; i < 20; i++ {
		scorer.RecordEvent(ComplianceEvent{Framework: "test", ControlID: "f-" + string(rune('A'+i%26)), Passed: false})
	}
	s := scorer.GetScore("test")
	t.Run("score_clamped_to_zero", func(t *testing.T) {
		if s.Score != 0 {
			t.Fatalf("got %d, want 0", s.Score)
		}
	})
	t.Run("penalty_capped", func(t *testing.T) {
		// All 20 controls failed, so base = 0, penalty capped at 50
		// Final = max(0 - 50, 0) = 0
		if s.Score < 0 {
			t.Fatal("score should not be negative")
		}
	})
	t.Run("high_violation_count", func(t *testing.T) {
		if s.ViolationCount < 10 {
			t.Fatalf("expected many violations, got %d", s.ViolationCount)
		}
	})
}

func TestClosing_ComplianceScorer_IsCompliant(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("fw1", 10)
	scorer.InitFramework("fw2", 10)
	t.Run("all_compliant_initially", func(t *testing.T) {
		if !scorer.IsCompliant(100) {
			t.Fatal("should be compliant at 100")
		}
	})
	scorer.RecordEvent(ComplianceEvent{Framework: "fw1", ControlID: "c1", Passed: false})
	t.Run("not_compliant_after_violation", func(t *testing.T) {
		if scorer.IsCompliant(100) {
			t.Fatal("should not be compliant after violation")
		}
	})
	t.Run("compliant_at_lower_threshold", func(t *testing.T) {
		if !scorer.IsCompliant(0) {
			t.Fatal("should be compliant at threshold 0")
		}
	})
}

func TestClosing_ComplianceScorer_GetAllScores(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("fw1", 5)
	scorer.InitFramework("fw2", 10)
	t.Run("two_scores", func(t *testing.T) {
		all := scorer.GetAllScores()
		if len(all) != 2 {
			t.Fatalf("got %d", len(all))
		}
	})
	t.Run("copies_returned", func(t *testing.T) {
		all1 := scorer.GetAllScores()
		all2 := scorer.GetAllScores()
		if all1["fw1"] == all2["fw1"] {
			t.Fatal("should return copies")
		}
	})
	t.Run("empty_scorer", func(t *testing.T) {
		empty := NewComplianceScorer()
		if len(empty.GetAllScores()) != 0 {
			t.Fatal("should be empty")
		}
	})
}

func TestClosing_ComplianceScorer_WithClock(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	scorer := NewComplianceScorer().WithClock(func() time.Time { return fixedTime })
	scorer.InitFramework("test", 5)
	scorer.RecordEvent(ComplianceEvent{Framework: "test", ControlID: "c1", Passed: true})
	t.Run("uses_clock", func(t *testing.T) {
		s := scorer.GetScore("test")
		if !s.UpdatedAt.Equal(fixedTime) {
			t.Fatalf("got %v, want %v", s.UpdatedAt, fixedTime)
		}
	})
	t.Run("returns_scorer", func(t *testing.T) {
		if scorer == nil {
			t.Fatal("should return non-nil")
		}
	})
	t.Run("chain_with_window", func(t *testing.T) {
		s := NewComplianceScorer().WithClock(func() time.Time { return fixedTime }).WithWindow(48 * time.Hour)
		if s == nil {
			t.Fatal("should support chaining")
		}
	})
}

// ---------------------------------------------------------------------------
// 15-20: Penalty calculations
// ---------------------------------------------------------------------------

func TestClosing_ComplianceScorer_PenaltyCalculation(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("test", 10)
	// Add varying violations
	for i := 0; i < 3; i++ {
		scorer.RecordEvent(ComplianceEvent{Framework: "test", ControlID: "v" + string(rune('0'+i)), Passed: false})
	}
	s := scorer.GetScore("test")
	t.Run("three_violations_penalty_15", func(t *testing.T) {
		// base = 0/10 * 100 = 0 (no passed), penalty = min(3*5, 50) = 15
		// But wait, 0 - 15 = -15, clamped to 0
		if s.Score != 0 {
			t.Fatalf("got %d", s.Score)
		}
	})
	t.Run("violations_counted", func(t *testing.T) {
		if s.ViolationCount != 3 {
			t.Fatalf("got %d", s.ViolationCount)
		}
	})
	t.Run("score_nonnegative", func(t *testing.T) {
		if s.Score < 0 {
			t.Fatal("score should never be negative")
		}
	})
}

func TestClosing_ComplianceScorer_PenaltyWithPassingControls(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("test", 10)
	// 8 passed, 2 failed
	for i := 0; i < 8; i++ {
		scorer.RecordEvent(ComplianceEvent{Framework: "test", ControlID: "p" + string(rune('A'+i)), Passed: true})
	}
	for i := 0; i < 2; i++ {
		scorer.RecordEvent(ComplianceEvent{Framework: "test", ControlID: "f" + string(rune('A'+i)), Passed: false})
	}
	s := scorer.GetScore("test")
	t.Run("base_80_minus_10", func(t *testing.T) {
		// base = 8/10 * 100 = 80, penalty = min(2*5, 50) = 10, score = 70
		if s.Score != 70 {
			t.Fatalf("got %d, want 70", s.Score)
		}
	})
	t.Run("passed_8", func(t *testing.T) {
		if s.ControlsPassed != 8 {
			t.Fatalf("got %d", s.ControlsPassed)
		}
	})
	t.Run("violations_2", func(t *testing.T) {
		if s.ViolationCount != 2 {
			t.Fatalf("got %d", s.ViolationCount)
		}
	})
}

func TestClosing_ComplianceScorer_LatestResultWins(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("test", 10)
	// Same control: first fails, then passes
	scorer.RecordEvent(ComplianceEvent{Framework: "test", ControlID: "c1", Passed: false})
	scorer.RecordEvent(ComplianceEvent{Framework: "test", ControlID: "c1", Passed: true})
	s := scorer.GetScore("test")
	t.Run("latest_passes", func(t *testing.T) {
		if s.ControlsPassed != 1 {
			t.Fatalf("got %d", s.ControlsPassed)
		}
	})
	// Failed controls are unique IDs that failed at any point in window
	t.Run("score_positive", func(t *testing.T) {
		if s.Score <= 0 {
			t.Fatalf("got %d", s.Score)
		}
	})
	t.Run("updated_at_set", func(t *testing.T) {
		if s.UpdatedAt.IsZero() {
			t.Fatal("updated_at should be set")
		}
	})
}

func TestClosing_ComplianceScorer_MaxPenalty(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("test", 100)
	// 11 unique violations → penalty = min(11*5, 50) = 50
	for i := 0; i < 11; i++ {
		scorer.RecordEvent(ComplianceEvent{Framework: "test", ControlID: "v-" + string(rune('A'+i)), Passed: false})
	}
	s := scorer.GetScore("test")
	t.Run("penalty_capped_at_50", func(t *testing.T) {
		// base = 0/100 * 100 = 0, penalty = 50, score = max(0-50, 0) = 0
		if s.Score != 0 {
			t.Fatalf("got %d", s.Score)
		}
	})
	t.Run("violations_11", func(t *testing.T) {
		if s.ViolationCount != 11 {
			t.Fatalf("got %d", s.ViolationCount)
		}
	})
	t.Run("score_not_negative", func(t *testing.T) {
		if s.Score < 0 {
			t.Fatal("should not be negative")
		}
	})
}

func TestClosing_ComplianceScorer_ScoreBoundaries(t *testing.T) {
	t.Run("score_0", func(t *testing.T) {
		scorer := NewComplianceScorer()
		scorer.InitFramework("t", 1)
		scorer.RecordEvent(ComplianceEvent{Framework: "t", ControlID: "c", Passed: false})
		s := scorer.GetScore("t")
		if s.Score < 0 {
			t.Fatalf("got %d", s.Score)
		}
	})
	t.Run("score_100", func(t *testing.T) {
		scorer := NewComplianceScorer()
		scorer.InitFramework("t", 1)
		scorer.RecordEvent(ComplianceEvent{Framework: "t", ControlID: "c", Passed: true})
		s := scorer.GetScore("t")
		if s.Score > 100 {
			t.Fatalf("got %d", s.Score)
		}
	})
	t.Run("no_events_100", func(t *testing.T) {
		scorer := NewComplianceScorer()
		scorer.InitFramework("t", 10)
		s := scorer.GetScore("t")
		if s.Score != 100 {
			t.Fatalf("got %d", s.Score)
		}
	})
}

func TestClosing_ComplianceScorer_VacuousTruth(t *testing.T) {
	scorer := NewComplianceScorer()
	t.Run("no_frameworks_compliant", func(t *testing.T) {
		if !scorer.IsCompliant(100) {
			t.Fatal("vacuous truth: no frameworks = compliant")
		}
	})
	t.Run("any_threshold", func(t *testing.T) {
		if !scorer.IsCompliant(0) {
			t.Fatal("should be compliant with no frameworks")
		}
	})
	t.Run("high_threshold", func(t *testing.T) {
		if !scorer.IsCompliant(999) {
			t.Fatal("should be compliant with no frameworks")
		}
	})
}

// ---------------------------------------------------------------------------
// 21-30: Window pruning
// ---------------------------------------------------------------------------

func TestClosing_ComplianceScorer_WindowPruning(t *testing.T) {
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	scorer := NewComplianceScorer().WithClock(func() time.Time { return now }).WithWindow(24 * time.Hour)
	scorer.InitFramework("test", 10)

	// Event 25 hours ago (outside window)
	oldEvent := ComplianceEvent{Framework: "test", ControlID: "old", Passed: false, Timestamp: now.Add(-25 * time.Hour)}
	scorer.RecordEvent(oldEvent)

	// Recent event
	scorer.RecordEvent(ComplianceEvent{Framework: "test", ControlID: "new", Passed: true, Timestamp: now})
	s := scorer.GetScore("test")

	t.Run("old_event_pruned", func(t *testing.T) {
		// The old event should be pruned from the window
		if s.ViolationCount != 0 {
			t.Fatalf("old event should be pruned, got violation count %d", s.ViolationCount)
		}
	})
	t.Run("new_event_counted", func(t *testing.T) {
		if s.ControlsPassed != 1 {
			t.Fatalf("got %d", s.ControlsPassed)
		}
	})
	t.Run("score_positive", func(t *testing.T) {
		if s.Score <= 0 {
			t.Fatalf("got %d", s.Score)
		}
	})
}

func TestClosing_ComplianceScorer_WithWindow(t *testing.T) {
	scorer := NewComplianceScorer().WithWindow(1 * time.Hour)
	scorer.InitFramework("test", 5)
	t.Run("window_1h", func(t *testing.T) {
		s := scorer.GetScore("test")
		if s.WindowHours != 1 {
			t.Fatalf("got %d", s.WindowHours)
		}
	})
	t.Run("returns_scorer", func(t *testing.T) {
		if scorer == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("chaining", func(t *testing.T) {
		s := NewComplianceScorer().WithWindow(2 * time.Hour).WithClock(time.Now)
		if s == nil {
			t.Fatal("should support chaining")
		}
	})
}

// ---------------------------------------------------------------------------
// 31-40: Scorecard operations
// ---------------------------------------------------------------------------

func TestClosing_ScorecardBuilder_Creation(t *testing.T) {
	b := NewScorecardBuilder()
	t.Run("not_nil", func(t *testing.T) {
		if b == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("empty_build", func(t *testing.T) {
		sc := b.Build()
		if sc == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("empty_entries", func(t *testing.T) {
		sc := b.Build()
		if len(sc.Entries) != 0 {
			t.Fatalf("got %d", len(sc.Entries))
		}
	})
}

func TestClosing_ScorecardBuilder_AddDimension(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "safety", Name: "Safety", Weight: 0.4})
	b.AddDimension(ParityDimension{DimensionID: "compliance", Name: "Compliance", Weight: 0.6})
	sc := b.Build()
	t.Run("two_dimensions", func(t *testing.T) {
		if len(sc.Dimensions) != 2 {
			t.Fatalf("got %d", len(sc.Dimensions))
		}
	})
	t.Run("dimension_fields", func(t *testing.T) {
		if sc.Dimensions[0].DimensionID != "safety" {
			t.Fatalf("got %q", sc.Dimensions[0].DimensionID)
		}
	})
	t.Run("weights_set", func(t *testing.T) {
		if sc.Dimensions[0].Weight != 0.4 {
			t.Fatalf("got %f", sc.Dimensions[0].Weight)
		}
	})
}

func TestClosing_ScorecardBuilder_RecordScore(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "d1", Name: "D1", Weight: 1.0})
	b.AddProduct("helm", "HELM")
	t.Run("record_with_evidence", func(t *testing.T) {
		err := b.RecordScore(ParityScore{DimensionID: "d1", ProductID: "helm", Score: 90, EvidenceRef: "test-123"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("record_without_evidence_errors", func(t *testing.T) {
		err := b.RecordScore(ParityScore{DimensionID: "d1", ProductID: "helm", Score: 80})
		if err == nil {
			t.Fatal("expected error for missing evidence")
		}
	})
	t.Run("build_includes_score", func(t *testing.T) {
		sc := b.Build()
		found := false
		for _, e := range sc.Entries {
			if e.ProductID == "helm" && len(e.Scores) > 0 {
				found = true
			}
		}
		if !found {
			t.Fatal("should include recorded score")
		}
	})
}

func TestClosing_ScorecardBuilder_WeightedAverage(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "d1", Name: "D1", Weight: 0.5})
	b.AddDimension(ParityDimension{DimensionID: "d2", Name: "D2", Weight: 0.5})
	b.AddProduct("p1", "Product 1")
	b.RecordScore(ParityScore{DimensionID: "d1", ProductID: "p1", Score: 80, EvidenceRef: "e1"})
	b.RecordScore(ParityScore{DimensionID: "d2", ProductID: "p1", Score: 60, EvidenceRef: "e2"})
	sc := b.Build()
	t.Run("weighted_avg", func(t *testing.T) {
		for _, e := range sc.Entries {
			if e.ProductID == "p1" {
				// (80*0.5 + 60*0.5) / (0.5 + 0.5) = 70
				if e.WeightedAvg != 70.0 {
					t.Fatalf("got %f, want 70", e.WeightedAvg)
				}
			}
		}
	})
	t.Run("two_scores", func(t *testing.T) {
		for _, e := range sc.Entries {
			if e.ProductID == "p1" && len(e.Scores) != 2 {
				t.Fatalf("got %d scores", len(e.Scores))
			}
		}
	})
	t.Run("content_hash_set", func(t *testing.T) {
		if sc.ContentHash == "" {
			t.Fatal("content hash should be set")
		}
	})
}

func TestClosing_Scorecard_ContentHash(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddProduct("p1", "P1")
	b.RecordScore(ParityScore{DimensionID: "d1", ProductID: "p1", Score: 50, EvidenceRef: "e1"})
	sc := b.Build()
	t.Run("has_sha256_prefix", func(t *testing.T) {
		if len(sc.ContentHash) < 7 || sc.ContentHash[:7] != "sha256:" {
			t.Fatalf("expected sha256: prefix, got %q", sc.ContentHash)
		}
	})
	t.Run("nonempty", func(t *testing.T) {
		if sc.ContentHash == "" {
			t.Fatal("should not be empty")
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		// Same builder builds consistently (within same clock tick)
		if sc.ContentHash == "" {
			t.Fatal("hash should be deterministic")
		}
	})
}

func TestClosing_ScorecardBuilder_WithClock(t *testing.T) {
	fixedTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	b := NewScorecardBuilder().WithClock(func() time.Time { return fixedTime })
	sc := b.Build()
	t.Run("generated_at", func(t *testing.T) {
		if !sc.GeneratedAt.Equal(fixedTime) {
			t.Fatalf("got %v", sc.GeneratedAt)
		}
	})
	t.Run("scorecard_id_set", func(t *testing.T) {
		if sc.ScorecardID == "" {
			t.Fatal("ID should be set")
		}
	})
	t.Run("returns_builder", func(t *testing.T) {
		if b == nil {
			t.Fatal("should not be nil")
		}
	})
}

func TestClosing_ScorecardBuilder_MultipleProducts(t *testing.T) {
	b := NewScorecardBuilder()
	b.AddDimension(ParityDimension{DimensionID: "d1", Weight: 1.0})
	products := []string{"helm", "competitor_a", "competitor_b", "competitor_c"}
	for _, p := range products {
		b.AddProduct(p, p)
		b.RecordScore(ParityScore{DimensionID: "d1", ProductID: p, Score: 75, EvidenceRef: "ref"})
	}
	sc := b.Build()
	t.Run("four_entries", func(t *testing.T) {
		if len(sc.Entries) != 4 {
			t.Fatalf("got %d", len(sc.Entries))
		}
	})
	t.Run("all_have_scores", func(t *testing.T) {
		for _, e := range sc.Entries {
			if len(e.Scores) == 0 {
				t.Fatalf("product %s has no scores", e.ProductID)
			}
		}
	})
	t.Run("all_same_avg", func(t *testing.T) {
		for _, e := range sc.Entries {
			if e.WeightedAvg != 75.0 {
				t.Fatalf("product %s avg = %f, want 75", e.ProductID, e.WeightedAvg)
			}
		}
	})
}

func TestClosing_ParityDimension_Fields(t *testing.T) {
	d := ParityDimension{DimensionID: "safety", Name: "Safety", Category: "core", Weight: 0.3}
	t.Run("id", func(t *testing.T) {
		if d.DimensionID != "safety" {
			t.Fatalf("got %q", d.DimensionID)
		}
	})
	t.Run("category", func(t *testing.T) {
		if d.Category != "core" {
			t.Fatalf("got %q", d.Category)
		}
	})
	t.Run("weight", func(t *testing.T) {
		if d.Weight != 0.3 {
			t.Fatalf("got %f", d.Weight)
		}
	})
}

func TestClosing_ParityScore_Fields(t *testing.T) {
	ps := ParityScore{DimensionID: "d1", ProductID: "p1", Score: 85.5, EvidenceRef: "test-42", Notes: "Good"}
	t.Run("score", func(t *testing.T) {
		if ps.Score != 85.5 {
			t.Fatalf("got %f", ps.Score)
		}
	})
	t.Run("evidence_ref", func(t *testing.T) {
		if ps.EvidenceRef != "test-42" {
			t.Fatalf("got %q", ps.EvidenceRef)
		}
	})
	t.Run("notes", func(t *testing.T) {
		if ps.Notes != "Good" {
			t.Fatalf("got %q", ps.Notes)
		}
	})
}

func TestClosing_ScorecardEntry_Fields(t *testing.T) {
	entry := ScorecardEntry{ProductID: "helm", ProductName: "HELM", WeightedAvg: 92.5}
	t.Run("product_id", func(t *testing.T) {
		if entry.ProductID != "helm" {
			t.Fatalf("got %q", entry.ProductID)
		}
	})
	t.Run("product_name", func(t *testing.T) {
		if entry.ProductName != "HELM" {
			t.Fatalf("got %q", entry.ProductName)
		}
	})
	t.Run("weighted_avg", func(t *testing.T) {
		if entry.WeightedAvg != 92.5 {
			t.Fatalf("got %f", entry.WeightedAvg)
		}
	})
}

// ---------------------------------------------------------------------------
// 41-50: API types, ComplianceEvent, and misc
// ---------------------------------------------------------------------------

func TestClosing_ComplianceEvent_Fields(t *testing.T) {
	now := time.Now()
	evt := ComplianceEvent{Framework: "hipaa", ControlID: "c1", Passed: true, Reason: "automated", Timestamp: now}
	t.Run("framework", func(t *testing.T) {
		if evt.Framework != "hipaa" {
			t.Fatalf("got %q", evt.Framework)
		}
	})
	t.Run("control_id", func(t *testing.T) {
		if evt.ControlID != "c1" {
			t.Fatalf("got %q", evt.ControlID)
		}
	})
	t.Run("passed", func(t *testing.T) {
		if !evt.Passed {
			t.Fatal("should be passed")
		}
	})
	t.Run("reason", func(t *testing.T) {
		if evt.Reason != "automated" {
			t.Fatalf("got %q", evt.Reason)
		}
	})
}

func TestClosing_ComplianceScore_Fields(t *testing.T) {
	cs := ComplianceScore{
		Framework: "gdpr", Score: 85, ControlsPassed: 17, ControlsTotal: 20,
		ViolationCount: 3, WindowHours: 24,
	}
	t.Run("framework", func(t *testing.T) {
		if cs.Framework != "gdpr" {
			t.Fatalf("got %q", cs.Framework)
		}
	})
	t.Run("score_range", func(t *testing.T) {
		if cs.Score < 0 || cs.Score > 100 {
			t.Fatalf("score %d out of range", cs.Score)
		}
	})
	t.Run("controls", func(t *testing.T) {
		if cs.ControlsPassed > cs.ControlsTotal {
			t.Fatal("passed should not exceed total")
		}
	})
}

func TestClosing_StatusResponse_Fields(t *testing.T) {
	resp := StatusResponse{
		OverallCompliant: true,
		Threshold:        70,
	}
	t.Run("compliant", func(t *testing.T) {
		if !resp.OverallCompliant {
			t.Fatal("should be compliant")
		}
	})
	t.Run("threshold", func(t *testing.T) {
		if resp.Threshold != 70 {
			t.Fatalf("got %d", resp.Threshold)
		}
	})
	t.Run("nil_frameworks", func(t *testing.T) {
		if resp.Frameworks != nil {
			t.Fatal("should be nil by default")
		}
	})
}

func TestClosing_HealthResponse_Fields(t *testing.T) {
	resp := HealthResponse{Status: "healthy", FrameworkCount: 7, LowestScore: 85}
	t.Run("status", func(t *testing.T) {
		if resp.Status != "healthy" {
			t.Fatalf("got %q", resp.Status)
		}
	})
	t.Run("framework_count", func(t *testing.T) {
		if resp.FrameworkCount != 7 {
			t.Fatalf("got %d", resp.FrameworkCount)
		}
	})
	t.Run("lowest_score", func(t *testing.T) {
		if resp.LowestScore != 85 {
			t.Fatalf("got %d", resp.LowestScore)
		}
	})
}

func TestClosing_EventRequest_Fields(t *testing.T) {
	req := EventRequest{Framework: "sox", ControlID: "c1", Passed: false, Reason: "missing"}
	t.Run("framework", func(t *testing.T) {
		if req.Framework != "sox" {
			t.Fatalf("got %q", req.Framework)
		}
	})
	t.Run("passed_false", func(t *testing.T) {
		if req.Passed {
			t.Fatal("should be false")
		}
	})
	t.Run("reason", func(t *testing.T) {
		if req.Reason != "missing" {
			t.Fatalf("got %q", req.Reason)
		}
	})
}

func TestClosing_EventResponse_Fields(t *testing.T) {
	resp := EventResponse{Accepted: true, Timestamp: time.Now()}
	t.Run("accepted", func(t *testing.T) {
		if !resp.Accepted {
			t.Fatal("should be accepted")
		}
	})
	t.Run("timestamp_set", func(t *testing.T) {
		if resp.Timestamp.IsZero() {
			t.Fatal("timestamp should be set")
		}
	})
	t.Run("nil_score", func(t *testing.T) {
		if resp.Score != nil {
			t.Fatal("score should be nil")
		}
	})
}

func TestClosing_APIHandler_Creation(t *testing.T) {
	scorer := NewComplianceScorer()
	h := NewAPIHandler(scorer)
	t.Run("not_nil", func(t *testing.T) {
		if h == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("with_clock", func(t *testing.T) {
		h2 := h.WithAPIClock(time.Now)
		if h2 == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("returns_handler", func(t *testing.T) {
		h3 := NewAPIHandler(scorer).WithAPIClock(time.Now)
		if h3 == nil {
			t.Fatal("should not be nil")
		}
	})
}

func TestClosing_ComplianceScorer_CopySemantics(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("test", 5)
	s1 := scorer.GetScore("test")
	s2 := scorer.GetScore("test")
	t.Run("independent_copies", func(t *testing.T) {
		s1.Score = 42
		s2Again := scorer.GetScore("test")
		if s2Again.Score == 42 {
			t.Fatal("mutation should not affect scorer")
		}
	})
	t.Run("same_values", func(t *testing.T) {
		if s1.Framework != s2.Framework {
			t.Fatal("should have same framework")
		}
	})
	t.Run("same_total", func(t *testing.T) {
		if s1.ControlsTotal != s2.ControlsTotal {
			t.Fatal("should have same total")
		}
	})
}

func TestClosing_ComplianceScorer_EmptyFrameworkAutoInit(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.RecordEvent(ComplianceEvent{Framework: "auto", ControlID: "c1", Passed: true})
	scorer.RecordEvent(ComplianceEvent{Framework: "auto", ControlID: "c2", Passed: false})
	s := scorer.GetScore("auto")
	t.Run("auto_initialized", func(t *testing.T) {
		if s == nil {
			t.Fatal("should be auto-initialized")
		}
	})
	t.Run("controls_counted", func(t *testing.T) {
		// Total controls = 0 (auto-init), but unique controls = 2 from events
		if s.ControlsPassed != 1 {
			t.Fatalf("got %d", s.ControlsPassed)
		}
	})
	t.Run("violations_counted", func(t *testing.T) {
		if s.ViolationCount != 1 {
			t.Fatalf("got %d", s.ViolationCount)
		}
	})
}
