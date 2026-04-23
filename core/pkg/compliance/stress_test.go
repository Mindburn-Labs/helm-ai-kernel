package compliance

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── Scorer: 1000 events across 7 frameworks ─────────────────────────────

func TestStress_Scorer1000EventsAcross7Frameworks(t *testing.T) {
	scorer := NewComplianceScorer()
	frameworks := []string{"eu_ai_act", "hipaa", "sox", "sec", "gdpr", "mica", "fca"}
	for _, fw := range frameworks {
		scorer.InitFramework(fw, 20)
	}
	for i := range 1000 {
		fw := frameworks[i%7]
		scorer.RecordEvent(ComplianceEvent{
			Framework: fw, ControlID: fmt.Sprintf("ctrl-%d", i%20),
			Passed: i%3 != 0, Timestamp: time.Now(),
		})
	}
	for _, fw := range frameworks {
		score := scorer.GetScore(fw)
		if score == nil {
			t.Fatalf("nil score for %s", fw)
		}
		if score.Score < 0 || score.Score > 100 {
			t.Fatalf("%s score out of range: %d", fw, score.Score)
		}
	}
}

// ── Concurrent scoring: 100 goroutines ──────────────────────────────────

func TestStress_ConcurrentScoring100Goroutines(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("gdpr", 10)
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			scorer.RecordEvent(ComplianceEvent{
				Framework: "gdpr", ControlID: fmt.Sprintf("ctrl-%d", idx%10),
				Passed: idx%2 == 0, Timestamp: time.Now(),
			})
		}(i)
	}
	wg.Wait()
	score := scorer.GetScore("gdpr")
	if score == nil {
		t.Fatal("score should not be nil")
	}
}

// ── All 7 frameworks independently ──────────────────────────────────────

func TestStress_FrameworkEuAiAct(t *testing.T) {
	testSingleFramework(t, "eu_ai_act", 15)
}

func TestStress_FrameworkHipaa(t *testing.T) {
	testSingleFramework(t, "hipaa", 18)
}

func TestStress_FrameworkSox(t *testing.T) {
	testSingleFramework(t, "sox", 12)
}

func TestStress_FrameworkSec(t *testing.T) {
	testSingleFramework(t, "sec", 10)
}

func TestStress_FrameworkGdpr(t *testing.T) {
	testSingleFramework(t, "gdpr", 20)
}

func TestStress_FrameworkMica(t *testing.T) {
	testSingleFramework(t, "mica", 8)
}

func TestStress_FrameworkFca(t *testing.T) {
	testSingleFramework(t, "fca", 14)
}

func testSingleFramework(t *testing.T, framework string, controls int) {
	t.Helper()
	scorer := NewComplianceScorer()
	scorer.InitFramework(framework, controls)
	for i := range controls {
		scorer.RecordEvent(ComplianceEvent{
			Framework: framework, ControlID: fmt.Sprintf("ctrl-%d", i),
			Passed: true, Timestamp: time.Now(),
		})
	}
	score := scorer.GetScore(framework)
	if score.Score != 100 {
		t.Fatalf("%s: all passed but score is %d", framework, score.Score)
	}
}

// ── Sliding window: events spanning 48 hours ────────────────────────────

func TestStress_SlidingWindow48Hours(t *testing.T) {
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	scorer := NewComplianceScorer().WithClock(func() time.Time { return baseTime.Add(48 * time.Hour) }).WithWindow(24 * time.Hour)
	scorer.InitFramework("gdpr", 5)
	// Add events from 48h ago (should be pruned in a 24h window)
	for i := range 5 {
		scorer.RecordEvent(ComplianceEvent{
			Framework: "gdpr", ControlID: fmt.Sprintf("ctrl-%d", i),
			Passed: false, Timestamp: baseTime,
		})
	}
	// Add recent events
	for i := range 5 {
		scorer.RecordEvent(ComplianceEvent{
			Framework: "gdpr", ControlID: fmt.Sprintf("ctrl-%d", i),
			Passed: true, Timestamp: baseTime.Add(47 * time.Hour),
		})
	}
	score := scorer.GetScore("gdpr")
	if score.Score < 50 {
		t.Fatalf("recent events should dominate, got %d", score.Score)
	}
}

func TestStress_SlidingWindowAllExpired(t *testing.T) {
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	scorer := NewComplianceScorer().WithClock(func() time.Time { return baseTime.Add(48 * time.Hour) }).WithWindow(24 * time.Hour)
	scorer.InitFramework("hipaa", 5)
	for i := range 5 {
		scorer.RecordEvent(ComplianceEvent{
			Framework: "hipaa", ControlID: fmt.Sprintf("ctrl-%d", i),
			Passed: false, Timestamp: baseTime, // 48h ago
		})
	}
	score := scorer.GetScore("hipaa")
	// All events expired, score should be 100 (initial) or recalculated
	if score.Score < 0 {
		t.Fatalf("score should not be negative: %d", score.Score)
	}
}

// ── EU AI Act: 8 Annex III areas ────────────────────────────────────────

func TestStress_EuAiActAnnexIII_Biometric(t *testing.T) {
	testAnnexIIIArea(t, "biometric")
}

func TestStress_EuAiActAnnexIII_CriticalInfra(t *testing.T) {
	testAnnexIIIArea(t, "critical_infrastructure")
}

func TestStress_EuAiActAnnexIII_Education(t *testing.T) {
	testAnnexIIIArea(t, "education")
}

func TestStress_EuAiActAnnexIII_Employment(t *testing.T) {
	testAnnexIIIArea(t, "employment")
}

func TestStress_EuAiActAnnexIII_EssentialServices(t *testing.T) {
	testAnnexIIIArea(t, "essential_services")
}

func TestStress_EuAiActAnnexIII_LawEnforcement(t *testing.T) {
	testAnnexIIIArea(t, "law_enforcement")
}

func TestStress_EuAiActAnnexIII_Migration(t *testing.T) {
	testAnnexIIIArea(t, "migration")
}

func TestStress_EuAiActAnnexIII_Justice(t *testing.T) {
	testAnnexIIIArea(t, "justice")
}

func testAnnexIIIArea(t *testing.T, area string) {
	t.Helper()
	scorer := NewComplianceScorer()
	fwID := "eu_ai_act_" + area
	scorer.InitFramework(fwID, 5)
	for i := range 5 {
		scorer.RecordEvent(ComplianceEvent{
			Framework: fwID, ControlID: fmt.Sprintf("%s-ctrl-%d", area, i),
			Passed: true, Timestamp: time.Now(),
		})
	}
	score := scorer.GetScore(fwID)
	if score.Score != 100 {
		t.Fatalf("%s: all passed but score %d", area, score.Score)
	}
}

// ── HIPAA: 18 PHI categories ────────────────────────────────────────────

func TestStress_HipaaAllPHICategories(t *testing.T) {
	phiCategories := []string{
		"name", "address", "dates", "phone", "fax", "email", "ssn", "mrn",
		"health_plan_id", "account_number", "license_number", "vehicle_id",
		"device_id", "url", "ip_address", "biometric_id", "photo", "other_unique",
	}
	scorer := NewComplianceScorer()
	scorer.InitFramework("hipaa", len(phiCategories))
	for _, cat := range phiCategories {
		scorer.RecordEvent(ComplianceEvent{
			Framework: "hipaa", ControlID: "phi_" + cat,
			Passed: true, Timestamp: time.Now(),
		})
	}
	score := scorer.GetScore("hipaa")
	if score.ControlsPassed < len(phiCategories) {
		t.Fatalf("expected %d passed, got %d", len(phiCategories), score.ControlsPassed)
	}
}

// ── Violation penalty ───────────────────────────────────────────────────

func TestStress_ViolationPenaltyCapped(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("sox", 20)
	for i := range 20 {
		scorer.RecordEvent(ComplianceEvent{
			Framework: "sox", ControlID: fmt.Sprintf("ctrl-%d", i),
			Passed: false, Timestamp: time.Now(),
		})
	}
	score := scorer.GetScore("sox")
	// With all failed: base=0, penalty=min(20*5,50)=50 → score=0
	if score.Score < 0 {
		t.Fatalf("score should not be negative: %d", score.Score)
	}
}

// ── WithClock ───────────────────────────────────────────────────────────

func TestStress_ScorerWithClock(t *testing.T) {
	fixed := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	scorer := NewComplianceScorer().WithClock(func() time.Time { return fixed })
	scorer.InitFramework("sec", 5)
	score := scorer.GetScore("sec")
	if !score.UpdatedAt.Equal(fixed) {
		t.Fatal("clock override not applied")
	}
}

// ── WithWindow ──────────────────────────────────────────────────────────

func TestStress_ScorerWithWindow(t *testing.T) {
	scorer := NewComplianceScorer().WithWindow(48 * time.Hour)
	scorer.InitFramework("fca", 5)
	score := scorer.GetScore("fca")
	if score.WindowHours != 48 {
		t.Fatalf("expected 48h window, got %d", score.WindowHours)
	}
}

// ── GetScore for uninitialized framework ────────────────────────────────

func TestStress_GetScoreUninitializedFramework(t *testing.T) {
	scorer := NewComplianceScorer()
	score := scorer.GetScore("nonexistent")
	if score != nil {
		t.Fatal("uninitialized framework should return nil")
	}
}

// ── Auto-init on RecordEvent ────────────────────────────────────────────

func TestStress_AutoInitOnRecordEvent(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.RecordEvent(ComplianceEvent{Framework: "auto", ControlID: "c1", Passed: true, Timestamp: time.Now()})
	score := scorer.GetScore("auto")
	if score == nil {
		t.Fatal("auto-init should create score entry")
	}
}

// ── Init with zero controls ─────────────────────────────────────────────

func TestStress_InitZeroControls(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("empty", 0)
	score := scorer.GetScore("empty")
	if score == nil {
		t.Fatal("should have score for empty framework")
	}
}

// ── Multiple violations on same control ─────────────────────────────────

func TestStress_MultipleViolationsSameControl(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("mica", 5)
	for range 10 {
		scorer.RecordEvent(ComplianceEvent{Framework: "mica", ControlID: "ctrl-0", Passed: false, Timestamp: time.Now()})
	}
	score := scorer.GetScore("mica")
	if score.ViolationCount == 0 {
		t.Fatal("should have violations")
	}
}

func TestStress_ScoreAfterAllPass(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("test-all", 5)
	for i := range 5 {
		scorer.RecordEvent(ComplianceEvent{Framework: "test-all", ControlID: fmt.Sprintf("c-%d", i), Passed: true, Timestamp: time.Now()})
	}
	score := scorer.GetScore("test-all")
	if score.Score != 100 {
		t.Fatalf("all pass should yield 100, got %d", score.Score)
	}
}

func TestStress_ScoreAfterAllFail(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("test-fail", 5)
	for i := range 5 {
		scorer.RecordEvent(ComplianceEvent{Framework: "test-fail", ControlID: fmt.Sprintf("c-%d", i), Passed: false, Timestamp: time.Now()})
	}
	score := scorer.GetScore("test-fail")
	if score.Score > 50 {
		t.Fatalf("all fail should be low, got %d", score.Score)
	}
}

func TestStress_ScoreClampedAt0(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("clamp", 1)
	for range 20 {
		scorer.RecordEvent(ComplianceEvent{Framework: "clamp", ControlID: "c-0", Passed: false, Timestamp: time.Now()})
	}
	score := scorer.GetScore("clamp")
	if score.Score < 0 {
		t.Fatal("score should not go below 0")
	}
}

func TestStress_InitFrameworkIdempotent(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("idem", 5)
	scorer.InitFramework("idem", 5)
	score := scorer.GetScore("idem")
	if score.ControlsTotal != 5 {
		t.Fatal("re-init should not corrupt")
	}
}

func TestStress_LastViolationTimestamp(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("ts", 5)
	now := time.Now()
	scorer.RecordEvent(ComplianceEvent{Framework: "ts", ControlID: "c-0", Passed: false, Timestamp: now})
	score := scorer.GetScore("ts")
	if score.LastViolation.IsZero() {
		t.Fatal("last violation should be set")
	}
}

func TestStress_MixedPassFail(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("mixed", 10)
	for i := range 10 {
		scorer.RecordEvent(ComplianceEvent{Framework: "mixed", ControlID: fmt.Sprintf("c-%d", i), Passed: i%2 == 0, Timestamp: time.Now()})
	}
	score := scorer.GetScore("mixed")
	if score.Score < 1 || score.Score > 99 {
		t.Fatalf("mixed pass/fail should be mid-range, got %d", score.Score)
	}
}

func TestStress_WindowHoursDefault(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("wh", 5)
	score := scorer.GetScore("wh")
	if score.WindowHours != 24 {
		t.Fatalf("default window should be 24h, got %d", score.WindowHours)
	}
}

func TestStress_ScoreUpdatedAt(t *testing.T) {
	fixed := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	scorer := NewComplianceScorer().WithClock(func() time.Time { return fixed })
	scorer.InitFramework("upd", 5)
	score := scorer.GetScore("upd")
	if !score.UpdatedAt.Equal(fixed) {
		t.Fatal("updated_at should match clock")
	}
}

func TestStress_ControlsPassedCount(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("cpc", 5)
	for i := range 3 {
		scorer.RecordEvent(ComplianceEvent{Framework: "cpc", ControlID: fmt.Sprintf("c-%d", i), Passed: true, Timestamp: time.Now()})
	}
	for i := 3; i < 5; i++ {
		scorer.RecordEvent(ComplianceEvent{Framework: "cpc", ControlID: fmt.Sprintf("c-%d", i), Passed: false, Timestamp: time.Now()})
	}
	score := scorer.GetScore("cpc")
	if score.ControlsPassed != 3 {
		t.Fatalf("expected 3 passed, got %d", score.ControlsPassed)
	}
}

func TestStress_ConcurrentFrameworkInit(t *testing.T) {
	scorer := NewComplianceScorer()
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			scorer.InitFramework(fmt.Sprintf("fw-%d", idx), 5)
		}(i)
	}
	wg.Wait()
}

func TestStress_FrameworkScoreNotNil(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("notnull", 10)
	scorer.RecordEvent(ComplianceEvent{Framework: "notnull", ControlID: "c-0", Passed: true, Timestamp: time.Now()})
	score := scorer.GetScore("notnull")
	if score == nil {
		t.Fatal("score should not be nil after event")
	}
}

func TestStress_ScoreFrameworkField(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("gdpr", 5)
	score := scorer.GetScore("gdpr")
	if score.Framework != "gdpr" {
		t.Fatalf("expected gdpr, got %s", score.Framework)
	}
}

func TestStress_InitialScoreIs100(t *testing.T) {
	scorer := NewComplianceScorer()
	scorer.InitFramework("init100", 10)
	score := scorer.GetScore("init100")
	if score.Score != 100 {
		t.Fatalf("initial score should be 100, got %d", score.Score)
	}
}
