package trust

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── fixedClock ───────────────────────────────────────────────────

type fixedBehavioralClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fixedBehavioralClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedBehavioralClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ── TierForScore Boundary Tests ──────────────────────────────────

func TestDeepTierForScore0(t *testing.T) {
	if TierForScore(0) != TierHostile {
		t.Fatal("0 should be HOSTILE")
	}
}

func TestDeepTierForScore199(t *testing.T) {
	if TierForScore(199) != TierHostile {
		t.Fatal("199 should be HOSTILE")
	}
}

func TestDeepTierForScore200(t *testing.T) {
	if TierForScore(200) != TierSuspect {
		t.Fatal("200 should be SUSPECT")
	}
}

func TestDeepTierForScore399(t *testing.T) {
	if TierForScore(399) != TierSuspect {
		t.Fatal("399 should be SUSPECT")
	}
}

func TestDeepTierForScore400(t *testing.T) {
	if TierForScore(400) != TierNeutral {
		t.Fatal("400 should be NEUTRAL")
	}
}

func TestDeepTierForScore699(t *testing.T) {
	if TierForScore(699) != TierNeutral {
		t.Fatal("699 should be NEUTRAL")
	}
}

func TestDeepTierForScore700(t *testing.T) {
	if TierForScore(700) != TierTrusted {
		t.Fatal("700 should be TRUSTED")
	}
}

func TestDeepTierForScore899(t *testing.T) {
	if TierForScore(899) != TierTrusted {
		t.Fatal("899 should be TRUSTED")
	}
}

func TestDeepTierForScore900(t *testing.T) {
	if TierForScore(900) != TierPristine {
		t.Fatal("900 should be PRISTINE")
	}
}

func TestDeepTierForScore1000(t *testing.T) {
	if TierForScore(1000) != TierPristine {
		t.Fatal("1000 should be PRISTINE")
	}
}

// ── Behavioral Scorer Tests ──────────────────────────────────────

func TestDeepScorerInitialScore(t *testing.T) {
	clk := &fixedBehavioralClock{t: time.Now()}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clk))
	score := s.GetScore("new-agent")
	if score.Score != 500 {
		t.Fatalf("expected 500, got %d", score.Score)
	}
}

func TestDeepScorerRecordPositiveEvent(t *testing.T) {
	clk := &fixedBehavioralClock{t: time.Now()}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clk))
	s.RecordEvent("a", ScoreEvent{EventType: EventPolicyComply})
	score := s.GetScore("a")
	if score.Score <= 500 {
		t.Fatal("positive event should increase score")
	}
}

func TestDeepScorerRecordNegativeEvent(t *testing.T) {
	clk := &fixedBehavioralClock{t: time.Now()}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clk))
	s.RecordEvent("a", ScoreEvent{EventType: EventPolicyViolate})
	score := s.GetScore("a")
	if score.Score >= 500 {
		t.Fatal("negative event should decrease score")
	}
}

func TestDeepScorerClampAtZero(t *testing.T) {
	clk := &fixedBehavioralClock{t: time.Now()}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clk))
	for i := 0; i < 100; i++ {
		s.RecordEvent("a", ScoreEvent{EventType: EventDelegationAbuse})
	}
	score := s.GetScore("a")
	if score.Score < 0 {
		t.Fatal("score should not go below 0")
	}
}

func TestDeepScorerClampAt1000(t *testing.T) {
	clk := &fixedBehavioralClock{t: time.Now()}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clk))
	for i := 0; i < 500; i++ {
		s.RecordEvent("a", ScoreEvent{EventType: EventManualBoost})
	}
	score := s.GetScore("a")
	if score.Score > 1000 {
		t.Fatal("score should not exceed 1000")
	}
}

func TestDeepScorerDecayAfterMultipleHalfLives(t *testing.T) {
	clk := &fixedBehavioralClock{t: time.Now()}
	cfg := DefaultScorerConfig()
	cfg.PositiveHalfLife = 1 * time.Hour
	s := NewBehavioralTrustScorer(WithBehavioralClock(clk), WithScorerConfig(cfg))
	// Boost to max
	for i := 0; i < 50; i++ {
		s.RecordEvent("a", ScoreEvent{EventType: EventManualBoost})
	}
	boosted := s.GetScore("a").Score
	// Advance 10 half-lives
	clk.Advance(10 * time.Hour)
	decayed := s.GetScore("a").Score
	if decayed >= boosted {
		t.Fatal("score should decay after 10 half-lives")
	}
	// After 10 half-lives, deviation should be ~1/1024 of original
	if decayed > 510 {
		t.Fatalf("expected nearly at initial score after 10 half-lives, got %d", decayed)
	}
}

func TestDeepScorerNegativeDecay(t *testing.T) {
	clk := &fixedBehavioralClock{t: time.Now()}
	cfg := DefaultScorerConfig()
	cfg.NegativeHalfLife = 1 * time.Hour
	s := NewBehavioralTrustScorer(WithBehavioralClock(clk), WithScorerConfig(cfg))
	s.RecordEvent("a", ScoreEvent{EventType: EventDelegationAbuse})
	penalized := s.GetScore("a").Score
	clk.Advance(10 * time.Hour)
	recovered := s.GetScore("a").Score
	if recovered <= penalized {
		t.Fatal("negative score should decay toward initial after time")
	}
}

func TestDeepScorerRapidFireEvents(t *testing.T) {
	clk := &fixedBehavioralClock{t: time.Now()}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clk))
	for i := 0; i < 10000; i++ {
		s.RecordEvent("rapid-agent", ScoreEvent{EventType: EventPolicyComply})
	}
	score := s.GetScore("rapid-agent")
	if score.Score <= 500 || score.Score > 1000 {
		t.Fatalf("unexpected score after 10000 events: %d", score.Score)
	}
}

func TestDeepScorerHistoryBounded(t *testing.T) {
	clk := &fixedBehavioralClock{t: time.Now()}
	cfg := DefaultScorerConfig()
	cfg.MaxHistorySize = 10
	s := NewBehavioralTrustScorer(WithBehavioralClock(clk), WithScorerConfig(cfg))
	for i := 0; i < 100; i++ {
		s.RecordEvent("a", ScoreEvent{EventType: EventPolicyComply})
	}
	score := s.GetScore("a")
	if len(score.History) > 10 {
		t.Fatalf("history should be bounded to 10, got %d", len(score.History))
	}
}

func TestDeepScorerAllEventTypes(t *testing.T) {
	clk := &fixedBehavioralClock{t: time.Now()}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clk))
	events := []ScoreEventType{
		EventPolicyComply, EventPolicyViolate, EventRateLimitHit,
		EventThreatDetected, EventDelegationValid, EventDelegationAbuse,
		EventEgressBlocked, EventManualBoost, EventManualPenalty,
	}
	for _, et := range events {
		s.RecordEvent("multi-agent", ScoreEvent{EventType: et})
	}
	score := s.GetScore("multi-agent")
	if len(score.History) != len(events) {
		t.Fatalf("expected %d history entries, got %d", len(events), len(score.History))
	}
}

func TestDeepScorerNormalized(t *testing.T) {
	score := BehavioralTrustScore{Score: 750}
	if score.Normalized() != 0.75 {
		t.Fatalf("expected 0.75, got %f", score.Normalized())
	}
}

func TestDeepScorerConcurrentAccess(t *testing.T) {
	clk := &fixedBehavioralClock{t: time.Now()}
	s := NewBehavioralTrustScorer(WithBehavioralClock(clk))
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			agent := fmt.Sprintf("agent-%d", idx%10)
			if idx%2 == 0 {
				s.RecordEvent(agent, ScoreEvent{EventType: EventPolicyComply})
			} else {
				s.GetScore(agent)
			}
		}(i)
	}
	wg.Wait()
}

// ── Leaderboard Tests ────────────────────────────────────────────

func TestDeepLeaderboard100Agents(t *testing.T) {
	scores := map[string]*TrustScore{}
	names := map[string]string{}
	for i := 0; i < 100; i++ {
		orgID := fmt.Sprintf("org-%03d", i)
		scores[orgID] = &TrustScore{
			OverallScore: float64(i) / 100.0,
			ComputedAt:   time.Now(),
		}
		names[orgID] = fmt.Sprintf("Org %d", i)
	}
	lb := NewLeaderboardFromScores(scores, names)
	if lb.Count() != 100 {
		t.Fatalf("expected 100 entries, got %d", lb.Count())
	}
	top := lb.GetTopN(5)
	if len(top) != 5 {
		t.Fatal("GetTopN(5) should return 5")
	}
	if top[0].Rank != 1 || top[0].TrustScore.OverallScore < top[1].TrustScore.OverallScore {
		t.Fatal("top entries should be sorted descending")
	}
}

func TestDeepLeaderboardHashDeterministic(t *testing.T) {
	scores := map[string]*TrustScore{
		"org-a": {OverallScore: 0.9, ComputedAt: time.Now()},
		"org-b": {OverallScore: 0.8, ComputedAt: time.Now()},
	}
	lb := NewLeaderboardFromScores(scores, nil)
	h1 := lb.Hash()
	h2 := lb.Hash()
	if h1 != h2 || h1 == "" {
		t.Fatal("hash should be deterministic and non-empty")
	}
}

func TestDeepLeaderboardBadgeLevels(t *testing.T) {
	cases := map[float64]BadgeLevel{
		0.96: BadgePlatinum, 0.86: BadgeGold, 0.71: BadgeSilver,
		0.51: BadgeBronze, 0.49: BadgeNone, 0.0: BadgeNone,
	}
	for score, expected := range cases {
		if GetBadgeLevel(score) != expected {
			t.Fatalf("score %.2f: expected %s", score, expected)
		}
	}
}

// ── Compliance Matrix Tests ──────────────────────────────────────

func TestDeepComplianceMatrixAddFramework(t *testing.T) {
	m := NewComplianceMatrix()
	m.AddFramework(&Framework{FrameworkID: "gdpr", Name: "GDPR"})
	m.AddFramework(&Framework{FrameworkID: "hipaa", Name: "HIPAA"})
	m.AddFramework(&Framework{FrameworkID: "sox", Name: "SOX"})
	m.AddFramework(&Framework{FrameworkID: "sec", Name: "SEC"})
	m.AddFramework(&Framework{FrameworkID: "mica", Name: "MiCA"})
	m.AddFramework(&Framework{FrameworkID: "dora", Name: "DORA"})
	m.AddFramework(&Framework{FrameworkID: "fca", Name: "FCA"})
	if len(m.Frameworks) != 7 {
		t.Fatalf("expected 7 frameworks, got %d", len(m.Frameworks))
	}
}

func TestDeepComplianceMatrixAddControlMissingFramework(t *testing.T) {
	m := NewComplianceMatrix()
	err := m.AddControl(&Control{ControlID: "c1", FrameworkID: "nonexistent"})
	if err == nil {
		t.Fatal("adding control to missing framework should error")
	}
}

func TestDeepComplianceMatrixAddEvidence(t *testing.T) {
	m := NewComplianceMatrix()
	m.AddFramework(&Framework{FrameworkID: "gdpr", Name: "GDPR"})
	m.AddControl(&Control{ControlID: "c1", FrameworkID: "gdpr", Title: "Data Access"})
	err := m.AddEvidence(&EvidenceItem{ControlID: "c1", Title: "Log", Type: EvidenceLog})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeepComplianceMatrixAddEvidenceMissingControl(t *testing.T) {
	m := NewComplianceMatrix()
	err := m.AddEvidence(&EvidenceItem{ControlID: "c999"})
	if err == nil {
		t.Fatal("adding evidence to missing control should error")
	}
}

func TestDeepComplianceMatrixHash(t *testing.T) {
	m := NewComplianceMatrix()
	m.AddFramework(&Framework{FrameworkID: "f1", Name: "F1"})
	h1 := m.Hash()
	h2 := m.Hash()
	if h1 != h2 || h1 == "" {
		t.Fatal("hash should be deterministic")
	}
}

func TestDeepComplianceMatrixGetFrameworkCompliance(t *testing.T) {
	m := NewComplianceMatrix()
	m.AddFramework(&Framework{FrameworkID: "f1", Name: "F1"})
	m.AddControl(&Control{ControlID: "c1", FrameworkID: "f1"})
	m.AddControl(&Control{ControlID: "c2", FrameworkID: "f1"})
	m.AssessControl("c1", ControlCompliant)
	fc, err := m.GetFrameworkCompliance("f1")
	if err != nil {
		t.Fatal(err)
	}
	if fc.CompliantControls != 1 || fc.TotalControls != 2 {
		t.Fatal("compliance counts mismatch")
	}
	if fc.ComplianceScore != 0.5 {
		t.Fatalf("expected 0.5, got %f", fc.ComplianceScore)
	}
}

func TestDeepComplianceMatrixAssessControlMissing(t *testing.T) {
	m := NewComplianceMatrix()
	err := m.AssessControl("nonexistent", ControlCompliant)
	if err == nil {
		t.Fatal("assessing missing control should error")
	}
}
