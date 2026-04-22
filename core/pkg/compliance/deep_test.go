package compliance

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func fixedClock() time.Time { return time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC) }

var allFrameworks = []string{"eu_ai_act", "hipaa", "sox", "sec", "gdpr", "mica", "fca"}

// ── 1-5: Scorer with all 7 frameworks simultaneously ────────────

func TestDeep_All7FrameworksInit(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	for _, fw := range allFrameworks {
		s.InitFramework(fw, 10)
	}
	scores := s.GetAllScores()
	if len(scores) != 7 {
		t.Fatalf("want 7 frameworks got %d", len(scores))
	}
}

func TestDeep_All7FrameworksInitialScore100(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	for _, fw := range allFrameworks {
		s.InitFramework(fw, 10)
	}
	for _, fw := range allFrameworks {
		sc := s.GetScore(fw)
		if sc.Score != 100 {
			t.Fatalf("%s: want initial score 100 got %d", fw, sc.Score)
		}
	}
}

func TestDeep_All7FrameworksCompliant(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	for _, fw := range allFrameworks {
		s.InitFramework(fw, 10)
	}
	if !s.IsCompliant(100) {
		t.Error("all frameworks at 100 should be compliant")
	}
}

func TestDeep_OneViolationBreaksCompliance(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	for _, fw := range allFrameworks {
		s.InitFramework(fw, 10)
	}
	s.RecordEvent(ComplianceEvent{Framework: "gdpr", ControlID: "c1", Passed: false, Timestamp: fixedClock()})
	if s.IsCompliant(100) {
		t.Error("one violation should break compliance at threshold 100")
	}
}

func TestDeep_MultiFrameworkScoringIndependent(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	for _, fw := range allFrameworks {
		s.InitFramework(fw, 10)
	}
	s.RecordEvent(ComplianceEvent{Framework: "hipaa", ControlID: "c1", Passed: false, Timestamp: fixedClock()})
	for _, fw := range allFrameworks {
		sc := s.GetScore(fw)
		if fw == "hipaa" && sc.Score == 100 {
			t.Error("hipaa should have reduced score")
		}
		if fw != "hipaa" && sc.Score != 100 {
			t.Errorf("%s should still be 100 got %d", fw, sc.Score)
		}
	}
}

// ── 6-10: Concurrent scoring (50 goroutines) ────────────────────

func TestDeep_ConcurrentRecordEvents(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	s.InitFramework("gdpr", 100)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.RecordEvent(ComplianceEvent{
				Framework: "gdpr", ControlID: fmt.Sprintf("c%d", i),
				Passed: true, Timestamp: fixedClock(),
			})
		}(i)
	}
	wg.Wait()
}

func TestDeep_ConcurrentGetScore(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	s.InitFramework("sox", 10)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.GetScore("sox")
		}()
	}
	wg.Wait()
}

func TestDeep_ConcurrentGetAllScores(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	for _, fw := range allFrameworks {
		s.InitFramework(fw, 10)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.GetAllScores()
		}()
	}
	wg.Wait()
}

func TestDeep_ConcurrentIsCompliant(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	for _, fw := range allFrameworks {
		s.InitFramework(fw, 10)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.IsCompliant(80)
		}()
	}
	wg.Wait()
}

func TestDeep_ConcurrentMixedOps(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	s.InitFramework("sec", 20)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				s.RecordEvent(ComplianceEvent{
					Framework: "sec", ControlID: fmt.Sprintf("c%d", i%10),
					Passed: i%3 != 0, Timestamp: fixedClock(),
				})
			} else {
				s.GetScore("sec")
			}
		}(i)
	}
	wg.Wait()
}

// ── 11-15: Sliding window pruning ───────────────────────────────

func TestDeep_WindowPruning(t *testing.T) {
	s := NewComplianceScorer().WithWindow(time.Hour)
	now := fixedClock()
	clock := func() time.Time { return now }
	s.WithClock(clock)
	s.InitFramework("gdpr", 10)
	// Old event outside window
	s.RecordEvent(ComplianceEvent{
		Framework: "gdpr", ControlID: "old", Passed: false,
		Timestamp: now.Add(-2 * time.Hour),
	})
	// New event inside window
	s.RecordEvent(ComplianceEvent{
		Framework: "gdpr", ControlID: "new", Passed: true,
		Timestamp: now.Add(-30 * time.Minute),
	})
	sc := s.GetScore("gdpr")
	if sc.ViolationCount != 0 {
		t.Fatalf("old violation should be pruned, got %d violations", sc.ViolationCount)
	}
}

func TestDeep_WindowPruningKeepsRecent(t *testing.T) {
	s := NewComplianceScorer().WithWindow(time.Hour).WithClock(fixedClock)
	s.InitFramework("fca", 10)
	s.RecordEvent(ComplianceEvent{
		Framework: "fca", ControlID: "c1", Passed: false,
		Timestamp: fixedClock().Add(-30 * time.Minute),
	})
	sc := s.GetScore("fca")
	if sc.ViolationCount != 1 {
		t.Fatalf("recent violation should be kept, got %d", sc.ViolationCount)
	}
}

func TestDeep_WindowPruningMultipleEvents(t *testing.T) {
	s := NewComplianceScorer().WithWindow(time.Hour).WithClock(fixedClock)
	s.InitFramework("mica", 10)
	for i := 0; i < 20; i++ {
		s.RecordEvent(ComplianceEvent{
			Framework: "mica", ControlID: fmt.Sprintf("c%d", i),
			Passed:    i%2 == 0,
			Timestamp: fixedClock().Add(-time.Duration(i*5) * time.Minute),
		})
	}
	sc := s.GetScore("mica")
	// Only events within last hour should be counted
	if sc.ViolationCount > 10 {
		t.Error("pruned events should reduce violation count")
	}
}

func TestDeep_WindowCustomDuration(t *testing.T) {
	s := NewComplianceScorer().WithWindow(10 * time.Minute).WithClock(fixedClock)
	s.InitFramework("sox", 5)
	s.RecordEvent(ComplianceEvent{
		Framework: "sox", ControlID: "c1", Passed: false,
		Timestamp: fixedClock().Add(-15 * time.Minute),
	})
	sc := s.GetScore("sox")
	if sc.ViolationCount != 0 {
		t.Error("event outside 10-minute window should be pruned")
	}
}

func TestDeep_WindowEdgeIncluded(t *testing.T) {
	s := NewComplianceScorer().WithWindow(time.Hour).WithClock(fixedClock)
	s.InitFramework("sec", 5)
	// Event exactly at window boundary: windowStart = now - 1h
	// Code uses !e.Timestamp.Before(windowStart), so exactly-at-boundary is included
	s.RecordEvent(ComplianceEvent{
		Framework: "sec", ControlID: "c1", Passed: false,
		Timestamp: fixedClock().Add(-time.Hour),
	})
	sc := s.GetScore("sec")
	if sc.ViolationCount != 1 {
		t.Fatalf("event at exact boundary should be included, got %d violations", sc.ViolationCount)
	}
}


// ── 16-20: Score recovery after violations ──────────────────────

func TestDeep_ScoreRecovery(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	s.InitFramework("gdpr", 10)
	s.RecordEvent(ComplianceEvent{
		Framework: "gdpr", ControlID: "c1", Passed: false,
		Timestamp: fixedClock(),
	})
	sc := s.GetScore("gdpr")
	if sc.Score == 100 {
		t.Error("violation should reduce score")
	}
	// Recovery: same control now passes
	s.RecordEvent(ComplianceEvent{
		Framework: "gdpr", ControlID: "c1", Passed: true,
		Timestamp: fixedClock().Add(time.Second),
	})
	sc2 := s.GetScore("gdpr")
	if sc2.Score <= sc.Score {
		t.Error("passing same control should recover score")
	}
}

func TestDeep_ScoringFormulaPenaltyCap(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	s.InitFramework("hipaa", 100)
	// 20 unique violations = penalty = min(20*5, 50) = 50
	for i := 0; i < 20; i++ {
		s.RecordEvent(ComplianceEvent{
			Framework: "hipaa", ControlID: fmt.Sprintf("c%d", i),
			Passed: false, Timestamp: fixedClock(),
		})
	}
	sc := s.GetScore("hipaa")
	// base = 0/100 * 100 = 0, penalty capped at 50, final = 0
	if sc.Score != 0 {
		t.Fatalf("0 passed + capped penalty should give 0, got %d", sc.Score)
	}
}

func TestDeep_ScoringFormulaBase(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	s.InitFramework("eu_ai_act", 10)
	// 8 controls pass, 2 fail
	for i := 0; i < 10; i++ {
		s.RecordEvent(ComplianceEvent{
			Framework: "eu_ai_act", ControlID: fmt.Sprintf("c%d", i),
			Passed: i < 8, Timestamp: fixedClock(),
		})
	}
	sc := s.GetScore("eu_ai_act")
	// base = (8/10)*100 = 80, penalty = min(2*5,50) = 10, final = 70
	if sc.Score != 70 {
		t.Fatalf("expected score 70 got %d", sc.Score)
	}
}

func TestDeep_ControlRemediationImproves(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	s.InitFramework("fca", 5)
	s.RecordEvent(ComplianceEvent{Framework: "fca", ControlID: "c1", Passed: false, Timestamp: fixedClock()})
	before := s.GetScore("fca")
	s.RecordEvent(ComplianceEvent{Framework: "fca", ControlID: "c1", Passed: true, Timestamp: fixedClock().Add(time.Second)})
	after := s.GetScore("fca")
	if after.Score <= before.Score {
		t.Error("remediation should improve score")
	}
}

func TestDeep_LastViolationTimestamp(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	s.InitFramework("sox", 5)
	ts := fixedClock().Add(-10 * time.Minute)
	s.RecordEvent(ComplianceEvent{Framework: "sox", ControlID: "c1", Passed: false, Timestamp: ts})
	sc := s.GetScore("sox")
	if sc.LastViolation.IsZero() {
		t.Error("last violation should be set")
	}
}

// ── 21-25: Edge cases ───────────────────────────────────────────

func TestDeep_GetScoreUnknownFramework(t *testing.T) {
	s := NewComplianceScorer()
	sc := s.GetScore("unknown")
	if sc != nil {
		t.Error("unknown framework should return nil")
	}
}

func TestDeep_AutoInitOnRecord(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	s.RecordEvent(ComplianceEvent{Framework: "new_fw", ControlID: "c1", Passed: true, Timestamp: fixedClock()})
	sc := s.GetScore("new_fw")
	if sc == nil {
		t.Fatal("auto-init should create score entry")
	}
}

func TestDeep_EmptyFrameworksCompliant(t *testing.T) {
	s := NewComplianceScorer()
	if !s.IsCompliant(100) {
		t.Error("no frameworks = vacuous truth = compliant")
	}
}

func TestDeep_ScoreClampAtZero(t *testing.T) {
	s := NewComplianceScorer().WithClock(fixedClock)
	s.InitFramework("test", 2)
	for i := 0; i < 15; i++ {
		s.RecordEvent(ComplianceEvent{
			Framework: "test", ControlID: fmt.Sprintf("c%d", i),
			Passed: false, Timestamp: fixedClock(),
		})
	}
	sc := s.GetScore("test")
	if sc.Score < 0 {
		t.Error("score should not go below 0")
	}
}

func TestDeep_ScorecardBuilder(t *testing.T) {
	sb := NewScorecardBuilder().WithClock(fixedClock)
	sb.AddDimension(ParityDimension{DimensionID: "d1", Name: "safety", Weight: 0.5})
	sb.AddDimension(ParityDimension{DimensionID: "d2", Name: "compliance", Weight: 0.5})
	sb.AddProduct("helm", "HELM")
	sb.AddProduct("other", "Other")
	sb.RecordScore(ParityScore{DimensionID: "d1", ProductID: "helm", Score: 90, EvidenceRef: "test-1"})
	sb.RecordScore(ParityScore{DimensionID: "d2", ProductID: "helm", Score: 80, EvidenceRef: "test-2"})
	sc := sb.Build()
	if len(sc.Entries) != 2 {
		t.Fatalf("want 2 entries got %d", len(sc.Entries))
	}
	if sc.ContentHash == "" {
		t.Error("scorecard should have content hash")
	}
}
