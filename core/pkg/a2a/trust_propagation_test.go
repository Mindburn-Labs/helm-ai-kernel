package a2a

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
)

func setupPropagation(t *testing.T) (*trust.BehavioralTrustScorer, *VouchingEngine, crypto.Signer) {
	t.Helper()
	clk := &fixedClock{t: time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)}
	scorer := newTestScorer(clk)
	engine := NewVouchingEngine(scorer).WithClock(clk.Now)

	signer, err := crypto.NewEd25519Signer("prop-key")
	if err != nil {
		t.Fatal(err)
	}
	return scorer, engine, signer
}

func TestTrustPropagator_DirectScore(t *testing.T) {
	scorer, engine, _ := setupPropagation(t)

	// Give agent-beta a known score.
	scorer.RecordEvent("agent-beta", trust.ScoreEvent{
		EventType: trust.EventManualBoost,
		Delta:     200,
		Reason:    "test boost",
	})

	prop := NewTrustPropagator(scorer, engine)

	score, paths, err := prop.PropagatedScore("agent-alpha", "agent-beta")
	if err != nil {
		t.Fatal(err)
	}

	expectedDirect := scorer.GetScore("agent-beta").Score
	if score != expectedDirect {
		t.Fatalf("expected direct score %d, got %d", expectedDirect, score)
	}
	if len(paths) != 0 {
		t.Fatalf("expected no vouch paths without vouching, got %d", len(paths))
	}
}

func TestTrustPropagator_SingleHop(t *testing.T) {
	scorer, engine, signer := setupPropagation(t)

	// Boost agent-beta so it's above MinScore.
	scorer.RecordEvent("agent-beta", trust.ScoreEvent{
		EventType: trust.EventManualBoost,
		Delta:     200,
		Reason:    "test boost",
	})

	// A vouches for B.
	_, err := engine.Vouch("agent-alpha", "agent-beta", []string{"x"}, 30, time.Hour, signer)
	if err != nil {
		t.Fatal(err)
	}

	prop := NewTrustPropagator(scorer, engine)
	score, paths, err := prop.PropagatedScore("agent-alpha", "agent-beta")
	if err != nil {
		t.Fatal(err)
	}

	betaScore := scorer.GetScore("agent-beta").Score
	expectedDecayed := int(float64(betaScore) * 0.7)

	// Score should be max(direct, decayed). Direct = betaScore, decayed = betaScore * 0.7.
	// Direct should win here since direct > decayed.
	if score != betaScore {
		t.Fatalf("expected score %d (direct > decayed %d), got %d", betaScore, expectedDecayed, score)
	}

	if len(paths) != 1 {
		t.Fatalf("expected 1 vouch path, got %d", len(paths))
	}
	if paths[0].FinalScore != expectedDecayed {
		t.Fatalf("expected path final score %d, got %d", expectedDecayed, paths[0].FinalScore)
	}
}

func TestTrustPropagator_MultiHop(t *testing.T) {
	scorer, engine, signer := setupPropagation(t)

	// Boost all agents.
	for _, agent := range []string{"agent-alpha", "agent-beta", "agent-gamma"} {
		scorer.RecordEvent(agent, trust.ScoreEvent{
			EventType: trust.EventManualBoost,
			Delta:     200,
			Reason:    "test boost",
		})
	}

	// Chain: A → B → C
	_, err := engine.Vouch("agent-alpha", "agent-beta", []string{"x"}, 30, time.Hour, signer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Vouch("agent-beta", "agent-gamma", []string{"x"}, 30, time.Hour, signer)
	if err != nil {
		t.Fatal(err)
	}

	prop := NewTrustPropagator(scorer, engine)
	score, paths, err := prop.PropagatedScore("agent-alpha", "agent-gamma")
	if err != nil {
		t.Fatal(err)
	}

	gammaScore := scorer.GetScore("agent-gamma").Score
	expectedDecayed := int(float64(gammaScore) * 0.7 * 0.7)

	// Direct score of gamma is the baseline. Propagated = gamma * 0.7^2.
	// Direct should still win since it's higher.
	if score != gammaScore {
		t.Fatalf("expected score %d (direct wins), got %d", gammaScore, score)
	}

	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if paths[0].FinalScore != expectedDecayed {
		t.Fatalf("expected path final score %d (double decay), got %d", expectedDecayed, paths[0].FinalScore)
	}
	if len(paths[0].Hops) != 3 {
		t.Fatalf("expected 3 hops in path, got %d", len(paths[0].Hops))
	}
}

func TestTrustPropagator_MaxHops(t *testing.T) {
	scorer, engine, signer := setupPropagation(t)

	agents := []string{"a", "b", "c", "d", "e"}
	for _, agent := range agents {
		scorer.RecordEvent(agent, trust.ScoreEvent{
			EventType: trust.EventManualBoost,
			Delta:     200,
			Reason:    "test boost",
		})
	}

	// Create a chain: a → b → c → d → e (4 hops, exceeds MaxHops=3).
	for i := 0; i < len(agents)-1; i++ {
		_, err := engine.Vouch(agents[i], agents[i+1], []string{"x"}, 10, time.Hour, signer)
		if err != nil {
			t.Fatal(err)
		}
	}

	prop := NewTrustPropagator(scorer, engine, PropagationConfig{
		DecayPerHop: 0.7,
		MaxHops:     3,
		MinScore:    400,
	})

	_, paths, err := prop.PropagatedScore("a", "e")
	if err != nil {
		t.Fatal(err)
	}

	// 4-hop path (a→b→c→d→e) should NOT be found because MaxHops=3.
	if len(paths) != 0 {
		t.Fatalf("expected 0 paths (exceeds max hops), got %d", len(paths))
	}
}

func TestTrustPropagator_CycleDetection(t *testing.T) {
	scorer, engine, signer := setupPropagation(t)

	for _, agent := range []string{"agent-alpha", "agent-beta"} {
		scorer.RecordEvent(agent, trust.ScoreEvent{
			EventType: trust.EventManualBoost,
			Delta:     200,
			Reason:    "test boost",
		})
	}

	// Create cycle: A → B → A.
	_, err := engine.Vouch("agent-alpha", "agent-beta", []string{"x"}, 30, time.Hour, signer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Vouch("agent-beta", "agent-alpha", []string{"x"}, 30, time.Hour, signer)
	if err != nil {
		t.Fatal(err)
	}

	prop := NewTrustPropagator(scorer, engine)

	// This should NOT infinite loop.
	score, _, err := prop.PropagatedScore("agent-alpha", "agent-beta")
	if err != nil {
		t.Fatal(err)
	}

	// Should return at least the direct score.
	betaScore := scorer.GetScore("agent-beta").Score
	if score < betaScore {
		t.Fatalf("expected at least direct score %d, got %d", betaScore, score)
	}
}

func TestTrustPropagator_MinScoreFilter(t *testing.T) {
	scorer, engine, signer := setupPropagation(t)

	// Boost A, but penalize B heavily so it's below MinScore.
	scorer.RecordEvent("agent-alpha", trust.ScoreEvent{
		EventType: trust.EventManualBoost,
		Delta:     200,
		Reason:    "test boost",
	})
	scorer.RecordEvent("agent-beta", trust.ScoreEvent{
		EventType: trust.EventManualPenalty,
		Delta:     -200, // score = 300, below MinScore of 400
		Reason:    "test penalty",
	})
	scorer.RecordEvent("agent-gamma", trust.ScoreEvent{
		EventType: trust.EventManualBoost,
		Delta:     200,
		Reason:    "test boost",
	})

	// A → B → C, but B has low trust.
	_, err := engine.Vouch("agent-alpha", "agent-beta", []string{"x"}, 30, time.Hour, signer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Vouch("agent-beta", "agent-gamma", []string{"x"}, 30, time.Hour, signer)
	if err != nil {
		t.Fatal(err)
	}

	prop := NewTrustPropagator(scorer, engine, PropagationConfig{
		DecayPerHop: 0.7,
		MaxHops:     3,
		MinScore:    400,
	})

	_, paths, err := prop.PropagatedScore("agent-alpha", "agent-gamma")
	if err != nil {
		t.Fatal(err)
	}

	// B is below MinScore, so the A→B→C path should be blocked.
	if len(paths) != 0 {
		t.Fatalf("expected 0 paths (intermediary below MinScore), got %d", len(paths))
	}
}

func TestTrustPropagator_SameAgent(t *testing.T) {
	scorer, engine, _ := setupPropagation(t)

	prop := NewTrustPropagator(scorer, engine)

	score, paths, err := prop.PropagatedScore("agent-alpha", "agent-alpha")
	if err != nil {
		t.Fatal(err)
	}

	expected := scorer.GetScore("agent-alpha").Score
	if score != expected {
		t.Fatalf("expected self-score %d, got %d", expected, score)
	}
	if paths != nil {
		t.Fatalf("expected nil paths for self-query, got %d", len(paths))
	}
}
