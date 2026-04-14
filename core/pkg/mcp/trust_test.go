package mcp

import (
	"sync"
	"testing"
	"time"
)

func TestNewToolStartsAtNeutral(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	scorer.RecordSuccess("srv1", "tool_a")

	ts, ok := scorer.GetScore("srv1", "tool_a")
	if !ok {
		t.Fatal("expected score to exist")
	}

	// With 1 success, 0 failures, 0 schema changes, 0 days age:
	// base=500, success_rate_bonus=300, stability_penalty=0, age_bonus=0, error_penalty=0
	// = 800
	if ts.Score != 800 {
		t.Errorf("expected score 800 after first success, got %d", ts.Score)
	}
	if ts.Tier != TrustTierVerified {
		t.Errorf("expected VERIFIED tier, got %s", ts.Tier)
	}
	if ts.TotalCalls != 1 {
		t.Errorf("expected 1 total call, got %d", ts.TotalCalls)
	}
	if ts.SuccessfulCalls != 1 {
		t.Errorf("expected 1 successful call, got %d", ts.SuccessfulCalls)
	}
}

func TestUnobservedToolReturnsNotFound(t *testing.T) {
	scorer := NewTrustScorer()

	_, ok := scorer.GetScore("srv1", "nonexistent")
	if ok {
		t.Error("expected not found for unobserved tool")
	}
}

func TestSuccessIncreasesScore(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	// Record a failure first, then successes
	scorer.RecordFailure("srv1", "tool_a")
	ts1, _ := scorer.GetScore("srv1", "tool_a")
	score1 := ts1.Score

	scorer.RecordSuccess("srv1", "tool_a")
	ts2, _ := scorer.GetScore("srv1", "tool_a")
	score2 := ts2.Score

	if score2 <= score1 {
		t.Errorf("expected score to increase after success: %d -> %d", score1, score2)
	}
}

func TestFailureDecreasesScore(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	scorer.RecordSuccess("srv1", "tool_a")
	ts1, _ := scorer.GetScore("srv1", "tool_a")
	score1 := ts1.Score

	scorer.RecordFailure("srv1", "tool_a")
	ts2, _ := scorer.GetScore("srv1", "tool_a")
	score2 := ts2.Score

	if score2 >= score1 {
		t.Errorf("expected score to decrease after failure: %d -> %d", score1, score2)
	}
}

func TestSchemaChangePenalizesScore(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	// Start with a success to establish a score
	scorer.RecordSuccess("srv1", "tool_a")
	ts1, _ := scorer.GetScore("srv1", "tool_a")
	score1 := ts1.Score

	scorer.RecordSchemaChange("srv1", "tool_a")
	ts2, _ := scorer.GetScore("srv1", "tool_a")
	score2 := ts2.Score

	if score2 >= score1 {
		t.Errorf("expected schema change to penalize score: %d -> %d", score1, score2)
	}
	if ts2.SchemaChanges != 1 {
		t.Errorf("expected 1 schema change, got %d", ts2.SchemaChanges)
	}
}

func TestSchemaChangePenaltyCapsAt250(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	// Record many schema changes
	for i := 0; i < 10; i++ {
		scorer.RecordSchemaChange("srv1", "tool_a")
	}

	ts, _ := scorer.GetScore("srv1", "tool_a")

	// base=500, no calls so no success/error adjustments, 0 age, stability_penalty=-250 (capped)
	// = 250
	if ts.Score != 250 {
		t.Errorf("expected score 250 with capped penalty, got %d", ts.Score)
	}
	if ts.SchemaChanges != 10 {
		t.Errorf("expected 10 schema changes, got %d", ts.SchemaChanges)
	}
}

func TestAgeBonusAccrues(t *testing.T) {
	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	current := start
	clock := func() time.Time { return current }

	scorer := NewTrustScorer(WithTrustClock(clock))

	// First call at day 0
	scorer.RecordSuccess("srv1", "tool_a")
	ts1, _ := scorer.GetScore("srv1", "tool_a")
	score1 := ts1.Score

	// Advance 10 days and record another call
	current = start.Add(10 * 24 * time.Hour)
	scorer.RecordSuccess("srv1", "tool_a")
	ts2, _ := scorer.GetScore("srv1", "tool_a")
	score2 := ts2.Score

	if score2 <= score1 {
		t.Errorf("expected age bonus to increase score: %d -> %d", score1, score2)
	}

	// Expected: base=500, success_rate=300 (100%), age_bonus=10*5=50, no penalties
	// = 850
	if score2 != 850 {
		t.Errorf("expected 850 after 10 days with perfect record, got %d", score2)
	}
}

func TestAgeBonusCapsAt30Days(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	current := start
	clock := func() time.Time { return current }

	scorer := NewTrustScorer(WithTrustClock(clock))
	scorer.RecordSuccess("srv1", "tool_a")

	// Advance 60 days
	current = start.Add(60 * 24 * time.Hour)
	scorer.RecordSuccess("srv1", "tool_a")
	ts60, _ := scorer.GetScore("srv1", "tool_a")

	// Advance 30 days
	current = start.Add(30 * 24 * time.Hour)
	currentB := start
	scorer2 := NewTrustScorer(WithTrustClock(func() time.Time { return currentB }))
	scorer2.RecordSuccess("srv1", "tool_a")
	// Move to 30 days
	currentB = start.Add(30 * 24 * time.Hour)
	scorer2.RecordSuccess("srv1", "tool_a")
	ts30, _ := scorer2.GetScore("srv1", "tool_a")

	// Both should have the same age bonus (capped at 150)
	if ts60.Score != ts30.Score {
		t.Errorf("expected same score at 30 and 60 days, got %d vs %d", ts30.Score, ts60.Score)
	}

	// Expected: base=500, success=300, age=150 = 950
	if ts60.Score != 950 {
		t.Errorf("expected 950 with max age bonus, got %d", ts60.Score)
	}
}

func TestScoreClampedTo0(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	// Max schema penalty + all failures
	for i := 0; i < 10; i++ {
		scorer.RecordSchemaChange("srv1", "tool_a")
	}
	for i := 0; i < 100; i++ {
		scorer.RecordFailure("srv1", "tool_a")
	}

	ts, _ := scorer.GetScore("srv1", "tool_a")
	if ts.Score < 0 {
		t.Errorf("score should not go below 0, got %d", ts.Score)
	}
	if ts.Score != 50 {
		// base=500, success=0, stability_penalty=-250, age=0, error_penalty=-200
		// = 50
		t.Errorf("expected 50, got %d", ts.Score)
	}
	if ts.Tier != TrustTierUntrusted {
		t.Errorf("expected UNTRUSTED tier, got %s", ts.Tier)
	}
}

func TestScoreClampedTo1000(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	current := start
	clock := func() time.Time { return current }

	scorer := NewTrustScorer(WithTrustClock(clock))

	// Record many successes over 60 days
	for i := 0; i < 1000; i++ {
		scorer.RecordSuccess("srv1", "tool_a")
	}
	current = start.Add(60 * 24 * time.Hour)
	scorer.RecordSuccess("srv1", "tool_a")

	ts, _ := scorer.GetScore("srv1", "tool_a")
	// base=500, success=300, age=150 = 950 (under 1000, but check clamping)
	if ts.Score > 1000 {
		t.Errorf("score should not exceed 1000, got %d", ts.Score)
	}
	if ts.Score != 950 {
		t.Errorf("expected 950, got %d", ts.Score)
	}
}

func TestTierClassification(t *testing.T) {
	tests := []struct {
		score int
		tier  TrustTier
	}{
		{0, TrustTierUntrusted},
		{100, TrustTierUntrusted},
		{199, TrustTierUntrusted},
		{200, TrustTierProbationary},
		{350, TrustTierProbationary},
		{399, TrustTierProbationary},
		{400, TrustTierStandard},
		{500, TrustTierStandard},
		{599, TrustTierStandard},
		{600, TrustTierTrusted},
		{750, TrustTierTrusted},
		{799, TrustTierTrusted},
		{800, TrustTierVerified},
		{900, TrustTierVerified},
		{1000, TrustTierVerified},
	}

	for _, tt := range tests {
		got := tierFromScore(tt.score)
		if got != tt.tier {
			t.Errorf("tierFromScore(%d) = %s, want %s", tt.score, got, tt.tier)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	scorer := NewTrustScorer()
	var wg sync.WaitGroup

	// Spawn many goroutines doing concurrent operations
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			scorer.RecordSuccess("srv1", "tool_a")
		}()
		go func() {
			defer wg.Done()
			scorer.RecordFailure("srv1", "tool_a")
		}()
		go func() {
			defer wg.Done()
			scorer.GetScore("srv1", "tool_a")
		}()
	}

	wg.Add(50)
	for i := 0; i < 50; i++ {
		go func() {
			defer wg.Done()
			scorer.AllScores()
		}()
	}

	wg.Wait()

	ts, ok := scorer.GetScore("srv1", "tool_a")
	if !ok {
		t.Fatal("expected score to exist after concurrent writes")
	}
	if ts.TotalCalls != 200 {
		t.Errorf("expected 200 total calls, got %d", ts.TotalCalls)
	}
	if ts.SuccessfulCalls != 100 {
		t.Errorf("expected 100 successful calls, got %d", ts.SuccessfulCalls)
	}
	if ts.FailedCalls != 100 {
		t.Errorf("expected 100 failed calls, got %d", ts.FailedCalls)
	}
}

func TestMultipleToolsIndependent(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	// tool_a: all successes
	for i := 0; i < 10; i++ {
		scorer.RecordSuccess("srv1", "tool_a")
	}

	// tool_b: all failures
	for i := 0; i < 10; i++ {
		scorer.RecordFailure("srv1", "tool_b")
	}

	tsA, ok := scorer.GetScore("srv1", "tool_a")
	if !ok {
		t.Fatal("expected tool_a score")
	}
	tsB, ok := scorer.GetScore("srv1", "tool_b")
	if !ok {
		t.Fatal("expected tool_b score")
	}

	if tsA.Score <= tsB.Score {
		t.Errorf("tool_a (all success) should score higher than tool_b (all failure): %d vs %d",
			tsA.Score, tsB.Score)
	}

	// tool_a: base=500, success=300, age=0, error=0 = 800
	if tsA.Score != 800 {
		t.Errorf("expected tool_a score 800, got %d", tsA.Score)
	}
	// tool_b: base=500, success=0, age=0, error=-200 = 300
	if tsB.Score != 300 {
		t.Errorf("expected tool_b score 300, got %d", tsB.Score)
	}
}

func TestMultipleServersIndependent(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	scorer.RecordSuccess("srv1", "tool_a")
	scorer.RecordFailure("srv2", "tool_a")

	ts1, _ := scorer.GetScore("srv1", "tool_a")
	ts2, _ := scorer.GetScore("srv2", "tool_a")

	if ts1.Score == ts2.Score {
		t.Error("same tool on different servers should have independent scores")
	}
	if ts1.ServerID != "srv1" || ts2.ServerID != "srv2" {
		t.Error("server IDs should be preserved")
	}
}

func TestAllScoresReturnsSnapshot(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	scorer.RecordSuccess("srv1", "tool_a")
	scorer.RecordSuccess("srv1", "tool_b")
	scorer.RecordSuccess("srv2", "tool_a")

	scores := scorer.AllScores()
	if len(scores) != 3 {
		t.Fatalf("expected 3 scores, got %d", len(scores))
	}

	// Should be sorted by serverID then toolName
	if scores[0].ServerID != "srv1" || scores[0].ToolName != "tool_a" {
		t.Errorf("expected first entry srv1:tool_a, got %s:%s", scores[0].ServerID, scores[0].ToolName)
	}
	if scores[1].ServerID != "srv1" || scores[1].ToolName != "tool_b" {
		t.Errorf("expected second entry srv1:tool_b, got %s:%s", scores[1].ServerID, scores[1].ToolName)
	}
	if scores[2].ServerID != "srv2" || scores[2].ToolName != "tool_a" {
		t.Errorf("expected third entry srv2:tool_a, got %s:%s", scores[2].ServerID, scores[2].ToolName)
	}

	// Mutating the returned slice should not affect internal state
	scores[0].Score = 9999
	ts, _ := scorer.GetScore("srv1", "tool_a")
	if ts.Score == 9999 {
		t.Error("AllScores should return copies, not references")
	}
}

func TestGetScoreReturnsCopy(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	scorer.RecordSuccess("srv1", "tool_a")

	ts1, _ := scorer.GetScore("srv1", "tool_a")
	ts1.Score = 9999

	ts2, _ := scorer.GetScore("srv1", "tool_a")
	if ts2.Score == 9999 {
		t.Error("GetScore should return a copy, not a reference")
	}
}

func TestLastScoreChangeTracking(t *testing.T) {
	t1 := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 4, 3, 0, 0, 0, 0, time.UTC)

	current := t1
	clock := func() time.Time { return current }
	scorer := NewTrustScorer(WithTrustClock(clock))

	scorer.RecordSuccess("srv1", "tool_a")
	ts1, _ := scorer.GetScore("srv1", "tool_a")
	change1 := ts1.LastScoreChange

	// Same operation at different time — score changes because of age bonus
	current = t2
	scorer.RecordSuccess("srv1", "tool_a")
	ts2, _ := scorer.GetScore("srv1", "tool_a")
	change2 := ts2.LastScoreChange

	if !change2.After(change1) {
		t.Error("expected LastScoreChange to update when score changes")
	}

	// Record at t3 — score changes again due to age bonus
	current = t3
	scorer.RecordSuccess("srv1", "tool_a")
	ts3, _ := scorer.GetScore("srv1", "tool_a")

	if ts3.LastSeen != t3 {
		t.Errorf("expected LastSeen to be %v, got %v", t3, ts3.LastSeen)
	}
}

func TestMixedSuccessAndFailure(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	// 50% success rate
	scorer.RecordSuccess("srv1", "tool_a")
	scorer.RecordFailure("srv1", "tool_a")

	ts, _ := scorer.GetScore("srv1", "tool_a")

	// base=500, success_rate_bonus=0.5*300=150, age=0, error_penalty=0.5*200=100
	// = 500+150-100 = 550
	if ts.Score != 550 {
		t.Errorf("expected 550 for 50%% success rate, got %d", ts.Score)
	}
	if ts.Tier != TrustTierStandard {
		t.Errorf("expected STANDARD tier, got %s", ts.Tier)
	}
}

func TestFirstSeenPreserved(t *testing.T) {
	t1 := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)

	current := t1
	clock := func() time.Time { return current }
	scorer := NewTrustScorer(WithTrustClock(clock))

	scorer.RecordSuccess("srv1", "tool_a")

	current = t2
	scorer.RecordSuccess("srv1", "tool_a")

	ts, _ := scorer.GetScore("srv1", "tool_a")
	if !ts.FirstSeen.Equal(t1) {
		t.Errorf("FirstSeen should remain %v, got %v", t1, ts.FirstSeen)
	}
	if !ts.LastSeen.Equal(t2) {
		t.Errorf("LastSeen should be %v, got %v", t2, ts.LastSeen)
	}
}
