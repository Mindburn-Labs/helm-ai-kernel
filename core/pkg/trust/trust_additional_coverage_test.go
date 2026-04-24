package trust

import (
	"encoding/json"
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

func TestExt_CompliancePipelineUnknownControl(t *testing.T) {
	matrix := NewComplianceMatrix()
	pipeline := NewCompliancePipeline(matrix)
	mapping := `{"mapping_id":"m1","target_ref":"test","controls":[{"control_id":"nonexistent","status":"compliant"}],"mapped_by":"ci","mapped_at":"2026-01-01T00:00:00Z"}`
	err := pipeline.IngestMapping([]byte(mapping))
	if err == nil {
		t.Fatal("expected error for unknown control")
	}
}

// ─── 11: CompliancePipeline IngestMapping — valid ─────────────

func TestExt_CompliancePipelineValidIngest(t *testing.T) {
	matrix := NewComplianceMatrix()
	matrix.AddFramework(&Framework{FrameworkID: "fw1", Name: "Test"})
	matrix.AddControl(&Control{ControlID: "c1", FrameworkID: "fw1", Title: "C1"})
	pipeline := NewCompliancePipeline(matrix)
	mapping := `{"mapping_id":"m1","target_ref":"test","controls":[{"control_id":"c1","status":"compliant","evidence_refs":["ev1"]}],"mapped_by":"ci","mapped_at":"2026-01-01T00:00:00Z"}`
	if err := pipeline.IngestMapping([]byte(mapping)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─── 12: CompliancePipeline ScanForStaleControls ──────────────

func TestExt_CompliancePipelineScanStale(t *testing.T) {
	matrix := NewComplianceMatrix()
	matrix.AddFramework(&Framework{FrameworkID: "fw1", Name: "Test"})
	matrix.AddControl(&Control{ControlID: "c1", FrameworkID: "fw1", Title: "C1"})
	pipeline := NewCompliancePipeline(matrix)
	stale := pipeline.ScanForStaleControls(0)
	if len(stale) != 1 {
		t.Fatalf("expected 1 stale control, got %d", len(stale))
	}
}

// ─── 13: CompliancePipeline invalid JSON ──────────────────────

func TestExt_CompliancePipelineInvalidJSON(t *testing.T) {
	pipeline := NewCompliancePipeline(NewComplianceMatrix())
	if err := pipeline.IngestMapping([]byte("not json")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ─── 14: Leaderboard sort stability — equal scores ────────────

func TestExt_LeaderboardSortStabilityEqualScores(t *testing.T) {
	scores := map[string]*TrustScore{
		"org-b": {OverallScore: 0.8, ComputedAt: time.Now()},
		"org-a": {OverallScore: 0.8, ComputedAt: time.Now()},
		"org-c": {OverallScore: 0.8, ComputedAt: time.Now()},
	}
	lb := NewLeaderboardFromScores(scores, nil)
	// Equal scores should be sorted by OrgID ascending
	if lb.Entries[0].OrgID != "org-a" || lb.Entries[1].OrgID != "org-b" || lb.Entries[2].OrgID != "org-c" {
		t.Fatalf("expected alphabetical order for equal scores, got %s/%s/%s", lb.Entries[0].OrgID, lb.Entries[1].OrgID, lb.Entries[2].OrgID)
	}
}

// ─── 15: Leaderboard re-rank after update ─────────────────────

func TestExt_LeaderboardReRankAfterUpdate(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("org-a", "A", &TrustScore{OverallScore: 0.5, ComputedAt: time.Now()})
	lb.UpdateScore("org-b", "B", &TrustScore{OverallScore: 0.9, ComputedAt: time.Now()})
	lb.Rank()
	if lb.Entries[0].OrgID != "org-b" {
		t.Fatalf("expected org-b first, got %s", lb.Entries[0].OrgID)
	}
}

// ─── 16: Leaderboard GetEntry not found ───────────────────────

func TestExt_LeaderboardGetEntryNotFound(t *testing.T) {
	lb := NewLeaderboard()
	_, found := lb.GetEntry("nonexistent")
	if found {
		t.Fatal("should not find nonexistent org")
	}
}

// ─── 17: Leaderboard GetTopN larger than entries ──────────────

func TestExt_LeaderboardGetTopNLargerThanEntries(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("org-a", "A", &TrustScore{OverallScore: 0.5, ComputedAt: time.Now()})
	lb.Rank()
	top := lb.GetTopN(100)
	if len(top) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(top))
	}
}

// ─── 18: Leaderboard badge levels ─────────────────────────────

func TestExt_LeaderboardBadgeLevels(t *testing.T) {
	tests := []struct {
		score float64
		badge BadgeLevel
	}{
		{0.96, BadgePlatinum}, {0.86, BadgeGold}, {0.71, BadgeSilver},
		{0.51, BadgeBronze}, {0.50, BadgeNone}, {0.0, BadgeNone},
	}
	for _, tt := range tests {
		if got := GetBadgeLevel(tt.score); got != tt.badge {
			t.Errorf("GetBadgeLevel(%f) = %s, want %s", tt.score, got, tt.badge)
		}
	}
}

// ─── 19: Leaderboard Export hash non-empty ────────────────────

func TestExt_LeaderboardExportHash(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("org-a", "A", &TrustScore{OverallScore: 0.8, ComputedAt: time.Now()})
	lb.Rank()
	export := lb.Export()
	if export.Hash == "" {
		t.Fatal("export hash should be non-empty")
	}
}

// ─── 20: Leaderboard hash deterministic ───────────────────────

func TestExt_LeaderboardHashDeterministic(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("org-a", "A", &TrustScore{OverallScore: 0.8, ComputedAt: time.Now()})
	lb.Rank()
	h1 := lb.Hash()
	h2 := lb.Hash()
	if h1 != h2 {
		t.Fatal("hash should be deterministic")
	}
}

// ─── 21: Leaderboard GetByBadge filters correctly ────────────

func TestExt_LeaderboardGetByBadge(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("gold-org", "Gold", &TrustScore{OverallScore: 0.90, ComputedAt: time.Now()})
	lb.UpdateScore("bronze-org", "Bronze", &TrustScore{OverallScore: 0.55, ComputedAt: time.Now()})
	lb.Rank()
	golds := lb.GetByBadge(BadgeGold)
	if len(golds) != 1 || golds[0].OrgID != "gold-org" {
		t.Fatalf("expected 1 gold, got %d", len(golds))
	}
}

// ─── 22: ComplianceMatrix hash deterministic ──────────────────

func TestExt_ComplianceMatrixHashDeterministic(t *testing.T) {
	m := NewComplianceMatrix()
	m.AddFramework(&Framework{FrameworkID: "fw1", Name: "Test"})
	h1 := m.Hash()
	h2 := m.Hash()
	if h1 != h2 {
		t.Fatal("matrix hash should be deterministic")
	}
}

// ─── 23: ComplianceMatrix AddControl unknown framework ────────

func TestExt_ComplianceMatrixAddControlUnknownFramework(t *testing.T) {
	m := NewComplianceMatrix()
	err := m.AddControl(&Control{ControlID: "c1", FrameworkID: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown framework")
	}
}

// ─── 24: TrustScore Normalized range ──────────────────────────

func TestExt_BehavioralTrustScoreNormalized(t *testing.T) {
	score := &BehavioralTrustScore{Score: 750}
	n := score.Normalized()
	if n != 0.75 {
		t.Fatalf("expected 0.75, got %f", n)
	}
}

// ─── 25: Leaderboard Export JSON serializable ─────────────────

func TestExt_LeaderboardExportSerializable(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("org-a", "A", &TrustScore{OverallScore: 0.8, ComputedAt: time.Now()})
	lb.Rank()
	export := lb.Export()
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("export should be JSON serializable: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("serialized export should be non-empty")
	}
}
