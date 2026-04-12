package compliance

import (
	"testing"
	"time"
)

func TestComplianceScorer_InitFramework(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	s := NewComplianceScorer().WithClock(func() time.Time { return now })

	s.InitFramework("eu_ai_act", 6)

	score := s.GetScore("eu_ai_act")
	if score == nil {
		t.Fatal("expected score for eu_ai_act, got nil")
	}
	if score.Score != 100 {
		t.Errorf("new framework should start at 100, got %d", score.Score)
	}
	if score.ControlsPassed != 6 {
		t.Errorf("controls_passed should be 6, got %d", score.ControlsPassed)
	}
	if score.ControlsTotal != 6 {
		t.Errorf("controls_total should be 6, got %d", score.ControlsTotal)
	}
	if score.ViolationCount != 0 {
		t.Errorf("violation_count should be 0, got %d", score.ViolationCount)
	}
	if score.Framework != "eu_ai_act" {
		t.Errorf("framework should be eu_ai_act, got %s", score.Framework)
	}
	if score.WindowHours != 24 {
		t.Errorf("window_hours should be 24, got %d", score.WindowHours)
	}
}

func TestComplianceScorer_RecordPass(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	s := NewComplianceScorer().WithClock(func() time.Time { return now })

	s.InitFramework("hipaa", 4)

	// Record 4 passing controls.
	controls := []string{"hipaa-164.312a", "hipaa-164.312b", "hipaa-164.312c", "hipaa-164.312d"}
	for _, c := range controls {
		s.RecordEvent(ComplianceEvent{
			Framework: "hipaa",
			ControlID: c,
			Passed:    true,
			Timestamp: now,
		})
	}

	score := s.GetScore("hipaa")
	if score == nil {
		t.Fatal("expected score for hipaa, got nil")
	}
	if score.Score != 100 {
		t.Errorf("all controls passed, expected score 100, got %d", score.Score)
	}
	if score.ControlsPassed != 4 {
		t.Errorf("controls_passed should be 4, got %d", score.ControlsPassed)
	}
	if score.ViolationCount != 0 {
		t.Errorf("violation_count should be 0, got %d", score.ViolationCount)
	}
}

func TestComplianceScorer_RecordViolation(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	s := NewComplianceScorer().WithClock(func() time.Time { return now })

	s.InitFramework("sox", 4)

	// Record 3 passing, 1 failing.
	s.RecordEvent(ComplianceEvent{Framework: "sox", ControlID: "sox-302", Passed: true, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "sox", ControlID: "sox-404", Passed: true, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "sox", ControlID: "sox-906", Passed: true, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "sox", ControlID: "sox-802", Passed: false, Reason: "audit trail incomplete", Timestamp: now})

	score := s.GetScore("sox")
	if score == nil {
		t.Fatal("expected score for sox, got nil")
	}

	// Base: 3/4 * 100 = 75. Penalty: 1*5 = 5. Final: 70.
	if score.Score != 70 {
		t.Errorf("expected score 70 (75 base - 5 penalty), got %d", score.Score)
	}
	if score.ControlsPassed != 3 {
		t.Errorf("controls_passed should be 3, got %d", score.ControlsPassed)
	}
	if score.ViolationCount != 1 {
		t.Errorf("violation_count should be 1, got %d", score.ViolationCount)
	}
	if score.LastViolation.IsZero() {
		t.Error("last_violation should be set")
	}
}

func TestComplianceScorer_MultipleFrameworks(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	s := NewComplianceScorer().WithClock(func() time.Time { return now })

	s.InitFramework("gdpr", 3)
	s.InitFramework("fca", 5)

	// GDPR: all pass.
	s.RecordEvent(ComplianceEvent{Framework: "gdpr", ControlID: "gdpr-art5", Passed: true, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "gdpr", ControlID: "gdpr-art6", Passed: true, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "gdpr", ControlID: "gdpr-art7", Passed: true, Timestamp: now})

	// FCA: 3 pass, 2 fail.
	s.RecordEvent(ComplianceEvent{Framework: "fca", ControlID: "fca-sysc", Passed: true, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "fca", ControlID: "fca-cond", Passed: true, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "fca", ControlID: "fca-prin", Passed: true, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "fca", ControlID: "fca-cobs", Passed: false, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "fca", ControlID: "fca-sup", Passed: false, Timestamp: now})

	gdprScore := s.GetScore("gdpr")
	fcaScore := s.GetScore("fca")

	if gdprScore == nil || fcaScore == nil {
		t.Fatal("expected scores for both frameworks")
	}

	// GDPR: 3/3 = 100, no violations.
	if gdprScore.Score != 100 {
		t.Errorf("gdpr score should be 100, got %d", gdprScore.Score)
	}

	// FCA: 3/5 * 100 = 60 base. 2 violations * 5 = 10 penalty. Final: 50.
	if fcaScore.Score != 50 {
		t.Errorf("fca score should be 50 (60 - 10), got %d", fcaScore.Score)
	}

	// Verify independence.
	if gdprScore.ViolationCount != 0 {
		t.Errorf("gdpr violations should be 0, got %d", gdprScore.ViolationCount)
	}
	if fcaScore.ViolationCount != 2 {
		t.Errorf("fca violations should be 2, got %d", fcaScore.ViolationCount)
	}
}

func TestComplianceScorer_SlidingWindow(t *testing.T) {
	currentTime := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	s := NewComplianceScorer().
		WithClock(func() time.Time { return currentTime }).
		WithWindow(1 * time.Hour) // 1-hour window for easy testing.

	s.InitFramework("sec", 2)

	// Record a violation at T=0.
	s.RecordEvent(ComplianceEvent{
		Framework: "sec",
		ControlID: "sec-reg-sci",
		Passed:    false,
		Reason:    "latency spike",
		Timestamp: currentTime,
	})

	// Record a pass on the other control.
	s.RecordEvent(ComplianceEvent{
		Framework: "sec",
		ControlID: "sec-reg-ats",
		Passed:    true,
		Timestamp: currentTime,
	})

	score := s.GetScore("sec")
	if score == nil {
		t.Fatal("expected score for sec")
	}

	// Base: 1/2 = 50. Penalty: 1*5 = 5. Final: 45.
	if score.Score != 45 {
		t.Errorf("score should be 45, got %d", score.Score)
	}

	// Advance time past the window (1h + 1s).
	currentTime = currentTime.Add(1*time.Hour + 1*time.Second)

	// Record a new passing event for the previously-failed control.
	s.RecordEvent(ComplianceEvent{
		Framework: "sec",
		ControlID: "sec-reg-sci",
		Passed:    true,
		Timestamp: currentTime,
	})

	score = s.GetScore("sec")

	// Old events pruned. Only the new pass remains in window.
	// 1 control passed out of 2 total. No violations in window.
	// Base: 1/2 = 50. Penalty: 0. Final: 50.
	if score.Score != 50 {
		t.Errorf("after window expiry, score should be 50, got %d", score.Score)
	}
	if score.ViolationCount != 0 {
		t.Errorf("violations should be 0 after window expiry, got %d", score.ViolationCount)
	}
}

func TestComplianceScorer_IsCompliant(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	s := NewComplianceScorer().WithClock(func() time.Time { return now })

	// No frameworks = vacuously compliant.
	if !s.IsCompliant(80) {
		t.Error("empty scorer should be compliant")
	}

	s.InitFramework("gdpr", 2)
	s.InitFramework("hipaa", 2)

	// Both at 100 — compliant at threshold 80.
	if !s.IsCompliant(80) {
		t.Error("both frameworks at 100 should be compliant at threshold 80")
	}

	// Add a violation to GDPR.
	s.RecordEvent(ComplianceEvent{Framework: "gdpr", ControlID: "gdpr-art5", Passed: false, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "gdpr", ControlID: "gdpr-art6", Passed: true, Timestamp: now})

	// GDPR: 1/2 = 50 base. 1 violation * 5 = 5 penalty. Final: 45.
	if s.IsCompliant(80) {
		t.Error("should not be compliant at threshold 80 with GDPR at 45")
	}
	if !s.IsCompliant(40) {
		t.Error("should be compliant at threshold 40 with GDPR at 45")
	}
}

func TestComplianceScorer_GetAllScores(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	s := NewComplianceScorer().WithClock(func() time.Time { return now })

	frameworks := []string{"eu_ai_act", "hipaa", "sox", "sec", "gdpr", "mica", "fca"}
	for _, fw := range frameworks {
		s.InitFramework(fw, 5)
	}

	all := s.GetAllScores()
	if len(all) != 7 {
		t.Errorf("expected 7 frameworks, got %d", len(all))
	}

	for _, fw := range frameworks {
		score, ok := all[fw]
		if !ok {
			t.Errorf("missing framework %s in GetAllScores", fw)
			continue
		}
		if score.Score != 100 {
			t.Errorf("framework %s should be 100, got %d", fw, score.Score)
		}
	}
}

func TestComplianceScorer_ScoreClamping(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	s := NewComplianceScorer().WithClock(func() time.Time { return now })

	s.InitFramework("mica", 2)

	// Record many violations to push score below 0.
	// All controls fail, plus many repeated violations.
	for i := 0; i < 20; i++ {
		s.RecordEvent(ComplianceEvent{
			Framework: "mica",
			ControlID: "mica-ctrl-1",
			Passed:    false,
			Reason:    "repeated failure",
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}
	s.RecordEvent(ComplianceEvent{
		Framework: "mica",
		ControlID: "mica-ctrl-2",
		Passed:    false,
		Reason:    "also failed",
		Timestamp: now.Add(21 * time.Second),
	})

	score := s.GetScore("mica")
	if score == nil {
		t.Fatal("expected score for mica")
	}

	// 0 controls passed out of 2 → base = 0. 2 unique failed controls → penalty = 10.
	// 0 - 10 = -10 → clamped to 0.
	if score.Score != 0 {
		t.Errorf("score should be clamped to 0, got %d", score.Score)
	}

	// Verify score never exceeds 100 — init already starts at 100 and
	// there is no way to exceed it via the public API, but verify the
	// property holds after events.
	s2 := NewComplianceScorer().WithClock(func() time.Time { return now })
	s2.InitFramework("test_fw", 1)
	s2.RecordEvent(ComplianceEvent{Framework: "test_fw", ControlID: "c1", Passed: true, Timestamp: now})
	sc2 := s2.GetScore("test_fw")
	if sc2.Score > 100 {
		t.Errorf("score should never exceed 100, got %d", sc2.Score)
	}
}

func TestComplianceScorer_RepeatedViolationsSameControl(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	s := NewComplianceScorer().WithClock(func() time.Time { return now })

	s.InitFramework("sox", 4)

	// Record 3 passing controls.
	s.RecordEvent(ComplianceEvent{Framework: "sox", ControlID: "sox-302", Passed: true, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "sox", ControlID: "sox-404", Passed: true, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "sox", ControlID: "sox-906", Passed: true, Timestamp: now})

	// Record the SAME control failing 5 times — should count as 1 unique violation.
	for i := 0; i < 5; i++ {
		s.RecordEvent(ComplianceEvent{
			Framework: "sox",
			ControlID: "sox-802",
			Passed:    false,
			Reason:    "audit trail incomplete",
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}

	score := s.GetScore("sox")
	if score == nil {
		t.Fatal("expected score for sox, got nil")
	}

	// violation_count should be 1 (one unique failed control), not 5.
	if score.ViolationCount != 1 {
		t.Errorf("violation_count should be 1 (unique failed controls), got %d", score.ViolationCount)
	}

	// Base: 3/4 * 100 = 75. Penalty: 1*5 = 5. Final: 70.
	if score.Score != 70 {
		t.Errorf("expected score 70 (75 base - 5 penalty), got %d", score.Score)
	}
}

func TestComplianceScorer_LatestControlResultWins(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	s := NewComplianceScorer().WithClock(func() time.Time { return now })

	s.InitFramework("gdpr", 2)

	// Control fails first, then passes — latest result (pass) should win
	// for control status, but the violation event still counts for penalty.
	s.RecordEvent(ComplianceEvent{Framework: "gdpr", ControlID: "gdpr-art5", Passed: false, Timestamp: now})
	s.RecordEvent(ComplianceEvent{Framework: "gdpr", ControlID: "gdpr-art5", Passed: true, Timestamp: now.Add(time.Minute)})
	s.RecordEvent(ComplianceEvent{Framework: "gdpr", ControlID: "gdpr-art6", Passed: true, Timestamp: now})

	score := s.GetScore("gdpr")
	if score == nil {
		t.Fatal("expected score for gdpr")
	}

	// Both controls now pass (latest for art5 is pass).
	if score.ControlsPassed != 2 {
		t.Errorf("controls_passed should be 2, got %d", score.ControlsPassed)
	}

	// 1 violation event still in window — penalty = 5.
	// Base: 2/2 * 100 = 100. Final: 100 - 5 = 95.
	if score.Score != 95 {
		t.Errorf("score should be 95 (100 base - 5 penalty), got %d", score.Score)
	}
}

func TestComplianceScorer_GetScore_Unknown(t *testing.T) {
	s := NewComplianceScorer()

	score := s.GetScore("nonexistent")
	if score != nil {
		t.Error("expected nil for unknown framework")
	}
}

func TestComplianceScorer_ConcurrentAccess(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	s := NewComplianceScorer().WithClock(func() time.Time { return now })

	s.InitFramework("eu_ai_act", 10)

	// Concurrent reads and writes should not panic.
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			s.RecordEvent(ComplianceEvent{
				Framework: "eu_ai_act",
				ControlID: "ctrl-" + string(rune('a'+id)),
				Passed:    id%2 == 0,
				Timestamp: now,
			})
			s.GetScore("eu_ai_act")
			s.GetAllScores()
			s.IsCompliant(80)
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}
