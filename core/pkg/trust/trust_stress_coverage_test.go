package trust

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// stressBehavioralClock implements BehavioralClock for tests.
type stressBehavioralClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stressBehavioralClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *stressBehavioralClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newStressClock() *stressBehavioralClock {
	return &stressBehavioralClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// ── Behavioral scorer: 5000 rapid events ────────────────────────────────

func TestStress_BehavioralScorer5000Events(t *testing.T) {
	scorer := NewBehavioralTrustScorer()
	for i := range 5000 {
		scorer.RecordEvent("agent-rapid", ScoreEvent{
			EventType: EventPolicyComply, Reason: fmt.Sprintf("evt-%d", i),
		})
	}
	score := scorer.GetScore("agent-rapid")
	if score.Score < 500 { // many positive events should push above initial
		t.Fatalf("score too low after 5000 positive events: %d", score.Score)
	}
}

// ── All 5 tier transitions individually ─────────────────────────────────

func TestStress_TierPristine(t *testing.T) {
	if TierForScore(950) != TierPristine {
		t.Fatal("950 should be PRISTINE")
	}
}

func TestStress_TierTrusted(t *testing.T) {
	if TierForScore(750) != TierTrusted {
		t.Fatal("750 should be TRUSTED")
	}
}

func TestStress_TierNeutral(t *testing.T) {
	if TierForScore(500) != TierNeutral {
		t.Fatal("500 should be NEUTRAL")
	}
}

func TestStress_TierSuspect(t *testing.T) {
	if TierForScore(300) != TierSuspect {
		t.Fatal("300 should be SUSPECT")
	}
}

func TestStress_TierHostile(t *testing.T) {
	if TierForScore(100) != TierHostile {
		t.Fatal("100 should be HOSTILE")
	}
}

// ── Decay at different half-lives ───────────────────────────────────────

func TestStress_DecayHalfLife0_5(t *testing.T) {
	testDecay(t, 500*time.Millisecond, 800, 500)
}

func TestStress_DecayHalfLife1_0(t *testing.T) {
	testDecay(t, 1*time.Second, 800, 500)
}

func TestStress_DecayHalfLife2_0(t *testing.T) {
	testDecay(t, 2*time.Second, 800, 500)
}

func TestStress_DecayHalfLife5_0(t *testing.T) {
	testDecay(t, 5*time.Second, 800, 500)
}

func TestStress_DecayHalfLife10_0(t *testing.T) {
	testDecay(t, 10*time.Second, 800, 500)
}

func testDecay(t *testing.T, halfLife time.Duration, initial, target int) {
	t.Helper()
	clk := newStressClock()
	scorer := NewBehavioralTrustScorer(
		WithBehavioralClock(clk),
		WithScorerConfig(ScorerConfig{
			InitialScore: target, MaxHistorySize: 100,
			PositiveHalfLife: halfLife, NegativeHalfLife: halfLife,
		}),
	)
	// Set score above initial
	scorer.RecordEvent("agent-decay", ScoreEvent{Delta: initial - target})
	clk.Advance(halfLife)
	score := scorer.GetScore("agent-decay")
	// After one half-life, deviation should be halved
	expectedApprox := target + (initial-target)/2
	if score.Score < expectedApprox-20 || score.Score > expectedApprox+20 {
		t.Fatalf("after 1 half-life (%.1fs): expected ~%d, got %d", halfLife.Seconds(), expectedApprox, score.Score)
	}
}

// ── Registry with every event type ──────────────────────────────────────

func TestStress_AllEventTypes(t *testing.T) {
	scorer := NewBehavioralTrustScorer()
	events := []ScoreEventType{
		EventPolicyComply, EventPolicyViolate, EventRateLimitHit,
		EventThreatDetected, EventDelegationValid, EventDelegationAbuse,
		EventEgressBlocked, EventManualBoost, EventManualPenalty,
	}
	for _, et := range events {
		scorer.RecordEvent("agent-all", ScoreEvent{EventType: et})
	}
	score := scorer.GetScore("agent-all")
	if len(score.History) != len(events) {
		t.Fatalf("expected %d events in history, got %d", len(events), len(score.History))
	}
}

func TestStress_DefaultDeltaForEachEventType(t *testing.T) {
	for et, delta := range DefaultDeltas {
		if delta == 0 {
			t.Fatalf("default delta for %s should not be 0", et)
		}
	}
}

func TestStress_NormalizedScore(t *testing.T) {
	score := BehavioralTrustScore{Score: 500}
	if score.Normalized() != 0.5 {
		t.Fatalf("500/1000 should be 0.5, got %f", score.Normalized())
	}
}

func TestStress_NormalizedScoreZero(t *testing.T) {
	score := BehavioralTrustScore{Score: 0}
	if score.Normalized() != 0.0 {
		t.Fatal("0 should normalize to 0.0")
	}
}

func TestStress_NormalizedScoreMax(t *testing.T) {
	score := BehavioralTrustScore{Score: 1000}
	if score.Normalized() != 1.0 {
		t.Fatal("1000 should normalize to 1.0")
	}
}

// ── Leaderboard with 200 agents ─────────────────────────────────────────

func TestStress_Leaderboard200Agents(t *testing.T) {
	scores := make(map[string]*TrustScore, 200)
	names := make(map[string]string, 200)
	for i := range 200 {
		id := fmt.Sprintf("org-%d", i)
		scores[id] = &TrustScore{
			OverallScore: float64(i) / 200.0,
			ComputedAt:   time.Now(),
		}
		names[id] = fmt.Sprintf("Org %d", i)
	}
	lb := NewLeaderboardFromScores(scores, names)
	if len(lb.Entries) != 200 {
		t.Fatalf("expected 200, got %d", len(lb.Entries))
	}
	// Should be sorted descending
	for i := 1; i < len(lb.Entries); i++ {
		if lb.Entries[i].TrustScore.OverallScore > lb.Entries[i-1].TrustScore.OverallScore {
			t.Fatal("leaderboard should be sorted descending")
		}
	}
}

func TestStress_LeaderboardUpdateAndReRank(t *testing.T) {
	lb := NewLeaderboard()
	lb.UpdateScore("org-1", "Org 1", &TrustScore{OverallScore: 0.5, ComputedAt: time.Now()})
	lb.UpdateScore("org-2", "Org 2", &TrustScore{OverallScore: 0.9, ComputedAt: time.Now()})
	lb.Rank()
	if lb.Entries[0].OrgID != "org-2" {
		t.Fatal("highest scorer should be first")
	}
}

// ── Compliance Matrix: 7 frameworks x 10 controls ───────────────────────

func TestStress_ComplianceMatrix7x10(t *testing.T) {
	matrix := NewComplianceMatrix()
	frameworks := []string{"eu_ai_act", "hipaa", "sox", "sec", "gdpr", "mica", "fca"}
	for _, fw := range frameworks {
		matrix.AddFramework(&Framework{FrameworkID: fw, Name: fw, Version: "1.0"})
		for j := range 10 {
			ctrl := &Control{
				ControlID: fmt.Sprintf("%s-ctrl-%d", fw, j), FrameworkID: fw,
				Title: fmt.Sprintf("Control %d", j), Severity: SeverityMedium,
			}
			if err := matrix.AddControl(ctrl); err != nil {
				t.Fatalf("add control %s-%d: %v", fw, j, err)
			}
		}
	}
	if len(matrix.Controls) != 70 {
		t.Fatalf("expected 70, got %d", len(matrix.Controls))
	}
	if len(matrix.Frameworks) != 7 {
		t.Fatalf("expected 7, got %d", len(matrix.Frameworks))
	}
}

// ── Badge levels ────────────────────────────────────────────────────────

func TestStress_BadgePlatinum(t *testing.T) {
	if GetBadgeLevel(0.96) != BadgePlatinum {
		t.Fatal("0.96 should be PLATINUM")
	}
}

func TestStress_BadgeGold(t *testing.T) {
	if GetBadgeLevel(0.86) != BadgeGold {
		t.Fatal("0.86 should be GOLD")
	}
}

func TestStress_BadgeSilver(t *testing.T) {
	if GetBadgeLevel(0.71) != BadgeSilver {
		t.Fatal("0.71 should be SILVER")
	}
}

func TestStress_BadgeBronze(t *testing.T) {
	if GetBadgeLevel(0.51) != BadgeBronze {
		t.Fatal("0.51 should be BRONZE")
	}
}

func TestStress_BadgeNone(t *testing.T) {
	if GetBadgeLevel(0.50) != BadgeNone {
		t.Fatal("0.50 should be NONE")
	}
}

// ── Clamping ────────────────────────────────────────────────────────────

func TestStress_ClampScoreAboveMax(t *testing.T) {
	scorer := NewBehavioralTrustScorer()
	scorer.RecordEvent("clamp-agent", ScoreEvent{Delta: 2000})
	score := scorer.GetScore("clamp-agent")
	if score.Score > 1000 {
		t.Fatal("score should be clamped to 1000")
	}
}

func TestStress_ClampScoreBelowMin(t *testing.T) {
	scorer := NewBehavioralTrustScorer()
	scorer.RecordEvent("clamp-low", ScoreEvent{Delta: -2000})
	score := scorer.GetScore("clamp-low")
	if score.Score < 0 {
		t.Fatal("score should be clamped to 0")
	}
}

// ── Concurrent scoring ──────────────────────────────────────────────────

func TestStress_ConcurrentScoring(t *testing.T) {
	scorer := NewBehavioralTrustScorer()
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			scorer.RecordEvent(fmt.Sprintf("agent-%d", idx%10), ScoreEvent{EventType: EventPolicyComply})
		}(i)
	}
	wg.Wait()
}

// ── History FIFO ────────────────────────────────────────────────────────

func TestStress_HistoryFIFO(t *testing.T) {
	scorer := NewBehavioralTrustScorer(WithScorerConfig(ScorerConfig{
		InitialScore: 500, MaxHistorySize: 10, PositiveHalfLife: 24 * time.Hour, NegativeHalfLife: 72 * time.Hour,
	}))
	for i := range 50 {
		scorer.RecordEvent("fifo-agent", ScoreEvent{Delta: 1, Reason: fmt.Sprintf("r-%d", i)})
	}
	score := scorer.GetScore("fifo-agent")
	if len(score.History) > 10 {
		t.Fatalf("history should be capped at 10, got %d", len(score.History))
	}
}

// ── Evidence types ──────────────────────────────────────────────────────

func TestStress_EvidenceTypes(t *testing.T) {
	types := []EvidenceType{EvidenceDocument, EvidenceLog, EvidenceScreenshot, EvidenceTestResult, EvidenceConfig, EvidenceAttestation}
	for _, et := range types {
		if string(et) == "" {
			t.Fatal("evidence type should not be empty")
		}
	}
}

func TestStress_SeverityConstants(t *testing.T) {
	if SeverityCritical != "critical" || SeverityHigh != "high" || SeverityMedium != "medium" || SeverityLow != "low" {
		t.Fatal("severity constant mismatch")
	}
}

func TestStress_ControlStatusConstants(t *testing.T) {
	if ControlCompliant != "compliant" || ControlNonCompliant != "non_compliant" || ControlPartial != "partial" || ControlNotAssessed != "not_assessed" {
		t.Fatal("control status constant mismatch")
	}
}

func TestStress_ScoreEventDefaultDeltaAsymmetry(t *testing.T) {
	if DefaultDeltas[EventPolicyComply] >= -DefaultDeltas[EventPolicyViolate] {
		t.Fatal("positive deltas should be smaller than negative (fail-closed asymmetry)")
	}
}

func TestStress_TierBoundary899(t *testing.T) {
	if TierForScore(899) != TierTrusted {
		t.Fatal("899 should be TRUSTED")
	}
}

func TestStress_TierBoundary900(t *testing.T) {
	if TierForScore(900) != TierPristine {
		t.Fatal("900 should be PRISTINE")
	}
}

func TestStress_TierBoundary699(t *testing.T) {
	if TierForScore(699) != TierNeutral {
		t.Fatal("699 should be NEUTRAL")
	}
}

func TestStress_TierBoundary700(t *testing.T) {
	if TierForScore(700) != TierTrusted {
		t.Fatal("700 should be TRUSTED")
	}
}

func TestStress_TierBoundary199(t *testing.T) {
	if TierForScore(199) != TierHostile {
		t.Fatal("199 should be HOSTILE")
	}
}

func TestStress_TierBoundary200(t *testing.T) {
	if TierForScore(200) != TierSuspect {
		t.Fatal("200 should be SUSPECT")
	}
}

func TestStress_GetTier(t *testing.T) {
	scorer := NewBehavioralTrustScorer()
	tier := scorer.GetTier("new-agent")
	if tier != TierNeutral {
		t.Fatalf("new agent should be NEUTRAL, got %s", tier)
	}
}

func TestStress_DefaultScorerConfig(t *testing.T) {
	cfg := DefaultScorerConfig()
	if cfg.InitialScore != 500 || cfg.MaxHistorySize != 100 {
		t.Fatal("default config mismatch")
	}
}
