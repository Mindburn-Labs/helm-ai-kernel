package arc

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Receipt hashing
// ---------------------------------------------------------------------------

func TestHashFrame_Deterministic(t *testing.T) {
	f := Frame{Grid: [][]int{{0, 1, 2}, {3, 4, 5}}, Width: 3, Height: 2}
	h1, err := HashFrame(f)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashFrame(f)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("frame hash not deterministic: %s != %s", h1, h2)
	}
	if h1 == "" {
		t.Fatal("frame hash is empty")
	}
}

func TestHashFrame_DifferentData(t *testing.T) {
	f1 := Frame{Grid: [][]int{{0, 1}, {2, 3}}, Width: 2, Height: 2}
	f2 := Frame{Grid: [][]int{{0, 1}, {2, 4}}, Width: 2, Height: 2}
	h1, _ := HashFrame(f1)
	h2, _ := HashFrame(f2)
	if h1 == h2 {
		t.Fatal("different frames must produce different hashes")
	}
}

func TestHashActionRecord_Deterministic(t *testing.T) {
	rec := ActionRecord{
		SessionID: "test-session",
		Step:      1,
		Action:    "ACTION1",
		Reasoning: json.RawMessage(`{"intent":"explore"}`),
	}
	h1, err := HashActionRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashActionRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("action hash not deterministic: %s != %s", h1, h2)
	}
}

func TestHashEpisode_Deterministic(t *testing.T) {
	rec := EpisodeRecord{
		SessionID:    "test-session",
		GameID:       "ls20",
		ActionHashes: []string{"sha256:aaa", "sha256:bbb"},
		FinalDone:    true,
		FinalReward:  1.0,
	}
	h1, err := HashEpisode(rec)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashEpisode(rec)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("episode hash not deterministic: %s != %s", h1, h2)
	}
}

// ---------------------------------------------------------------------------
// Payload construction
// ---------------------------------------------------------------------------

func TestMakeIntentPayload(t *testing.T) {
	data, err := MakeIntentPayload("s1", 3, "ACTION2", json.RawMessage(`{"goal":"win"}`))
	if err != nil {
		t.Fatal(err)
	}
	var p IntentPayload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	if p.Type != "arc.env.step" {
		t.Errorf("type = %q, want arc.env.step", p.Type)
	}
	if p.SessionID != "s1" || p.Step != 3 || p.Action != "ACTION2" {
		t.Errorf("unexpected payload: %+v", p)
	}
}

func TestMakeEffectPayload(t *testing.T) {
	data, err := MakeEffectPayload("s1", 3, "sha256:abc", "sha256:def", false, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	var p EffectPayload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	if p.Type != "arc.env.effect" {
		t.Errorf("type = %q, want arc.env.effect", p.Type)
	}
	if p.Reward != 0.5 {
		t.Errorf("reward = %f, want 0.5", p.Reward)
	}
}

func TestMakeCheckpointPayload(t *testing.T) {
	data, err := MakeCheckpointPayload("s1", "ls20", "sha256:ep", "card-1", 15, 2.0)
	if err != nil {
		t.Fatal(err)
	}
	var p CheckpointPayload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	if p.Type != "arc.episode.checkpoint" {
		t.Errorf("type = %q, want arc.episode.checkpoint", p.Type)
	}
	if p.ScorecardID != "card-1" || p.TotalSteps != 15 {
		t.Errorf("unexpected checkpoint: %+v", p)
	}
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

func TestDefaultPolicy_OfficialShadow(t *testing.T) {
	p := DefaultPolicy(RunModeOfficialShadow)
	if p.MaxOfflineSearchNodes != 0 {
		t.Errorf("official-shadow must have no search nodes, got %d", p.MaxOfflineSearchNodes)
	}
	if p.MaxOnlineRPM > 600 {
		t.Errorf("RPM exceeds ARC limit: %d", p.MaxOnlineRPM)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validation failed: %v", err)
	}
}

func TestDefaultPolicy_CommunityHarness(t *testing.T) {
	p := DefaultPolicy(RunModeCommunityHarness)
	if p.MaxOfflineSearchNodes == 0 {
		t.Error("community-harness should allow search nodes")
	}
	if p.MaxActionsPerEpisode <= DefaultPolicy(RunModeOfficialShadow).MaxActionsPerEpisode {
		t.Error("community-harness should have wider action budget")
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validation failed: %v", err)
	}
}

func TestPolicyValidation_OfficialShadowWithSearch(t *testing.T) {
	p := DefaultPolicy(RunModeOfficialShadow)
	p.MaxOfflineSearchNodes = 100 // illegal for official-shadow
	err := p.Validate()
	if err == nil {
		t.Fatal("expected validation error for search in official-shadow mode")
	}
}

func TestPolicyValidation_ExcessiveRPM(t *testing.T) {
	p := DefaultPolicy(RunModeCommunityHarness)
	p.MaxOnlineRPM = 1000 // exceeds ARC limit
	err := p.Validate()
	if err == nil {
		t.Fatal("expected validation error for RPM > 600")
	}
}

// ---------------------------------------------------------------------------
// Scorecard
// ---------------------------------------------------------------------------

func TestHashScorecard_Deterministic(t *testing.T) {
	rec := ScorecardRecord{
		CardID:  "c1",
		GameIDs: []string{"ls20"},
		Status:  "open",
	}
	h1, err := HashScorecard(rec)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashScorecard(rec)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("scorecard hash not deterministic: %s != %s", h1, h2)
	}
}

func TestMakeScorecardPayloads(t *testing.T) {
	openD, _ := MakeScorecardOpenPayload([]string{"ls20"})
	openED, _ := MakeScorecardOpenEffectPayload("c1", "hash1")
	closeD, _ := MakeScorecardClosePayload("c1")
	closeED, _ := MakeScorecardCloseEffectPayload("c1", "hash2")

	if len(openD) == 0 || len(openED) == 0 || len(closeD) == 0 || len(closeED) == 0 {
		t.Fatal("empty payloads generated")
	}
}

func TestScorecardBudgetEnforcement(t *testing.T) {
	// Set budget to 1 scorecard per hour
	cfg := ConnectorConfig{
		BridgeURL: "http://localhost:8787",
		Mode:      RunModeOfficialShadow,
	}
	policy := DefaultPolicy(cfg.Mode)
	policy.MaxOnlineScorecardsPH = 1
	cfg.Policy = policy

	c := NewConnector(cfg)

	// Context with timeout to avoid hanging if the server happens to be up
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// 1st call will pass the budget gate but fail at HTTP (no server running)
	_, err := c.OpenScorecard(ctx, []string{"ls20"})
	if err == nil {
		t.Fatal("expected OpenScorecard to fail (no server)")
	}

	// 2nd call should fail at the budget gate
	_, err2 := c.OpenScorecard(ctx, []string{"ls20"})
	if err2 == nil || err2.Error() != "budget exceeded: max scorecards per hour (1) reached" {
		t.Fatalf("expected budget error, got: %v", err2)
	}
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

func TestAllowedDataClasses(t *testing.T) {
	classes := AllowedDataClasses()
	expected := map[string]bool{
		"arc.games.list":        true,
		"arc.scorecard.open":    true,
		"arc.env.reset":         true,
		"arc.env.step.simple":   true,
		"arc.env.step.complex":  true,
		"arc.scorecard.get":     true,
		"arc.scorecard.close":   true,
		"arc.replay.fetch":      true,
	}
	if len(classes) != len(expected) {
		t.Fatalf("got %d data classes, want %d", len(classes), len(expected))
	}
	for _, c := range classes {
		if !expected[c] {
			t.Errorf("unexpected data class: %s", c)
		}
	}
}

// ---------------------------------------------------------------------------
// Run mode separation / Shadow Enforcement
// ---------------------------------------------------------------------------

func TestShadowMode_RejectsUnauthorizedGames(t *testing.T) {
	// Shadow mode
	cfgShadow := ConnectorConfig{
		BridgeURL: "http://localhost:8787",
		Mode:      RunModeOfficialShadow,
	}
	cShadow := NewConnector(cfgShadow)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// 1. Should fail to create session for arbitrary game
	_, err := cShadow.CreateSession(ctx, "ls20")
	if err == nil || err.Error() != "official-shadow mode: game \"ls20\" not associated with an open scorecard" {
		t.Fatalf("expected shadow mode gate error, got: %v", err)
	}

	// 2. Mocking an open scorecard (directly to activeGames for unit test isolation)
	cShadow.mu.Lock()
	cShadow.activeGames["ls20"] = "mock-card-1"
	cShadow.mu.Unlock()

	// 3. Should now pass the shadow gate (it will fail on the http client since bridge is down, but pass the gate)
	_, err2 := cShadow.CreateSession(ctx, "ls20")
	if err2 != nil && err2.Error() == "official-shadow mode: game \"ls20\" not associated with an open scorecard" {
		t.Fatalf("shadow mode gate incorrectly blocked authorized game")
	}

	// Harness mode
	cfgHarness := ConnectorConfig{
		BridgeURL: "http://localhost:8787",
		Mode:      RunModeCommunityHarness,
	}
	cHarness := NewConnector(cfgHarness)

	// Should pass the shadow gate instantly
	_, err3 := cHarness.CreateSession(ctx, "ls20")
	if err3 != nil && err3.Error() == "official-shadow mode: game \"ls20\" not associated with an open scorecard" {
		t.Fatalf("harness mode gate incorrectly applied shadow locks")
	}
}

func TestRunModeSeparation(t *testing.T) {
	if RunModeOfficialShadow == RunModeCommunityHarness {
		t.Fatal("modes must be distinct")
	}

	// Official-shadow forbids search
	pOfficial := DefaultPolicy(RunModeOfficialShadow)
	if pOfficial.MaxOfflineSearchNodes > 0 {
		t.Error("official-shadow prohibits search")
	}

	// Community-harness allows wider budgets
	pHarness := DefaultPolicy(RunModeCommunityHarness)
	if pHarness.MaxActionsPerEpisode <= pOfficial.MaxActionsPerEpisode {
		t.Error("harness should have wider action budget")
	}
	if pHarness.MaxParallelSessions <= pOfficial.MaxParallelSessions {
		t.Error("harness should allow more parallel sessions")
	}
}

// ---------------------------------------------------------------------------
// Connector construction
// ---------------------------------------------------------------------------

func TestNewConnector(t *testing.T) {
	c := NewConnector(ConnectorConfig{
		BridgeURL: "http://localhost:8787",
		Mode:      RunModeOfficialShadow,
	})
	if c.Mode() != RunModeOfficialShadow {
		t.Errorf("mode = %s, want OFFICIAL_SHADOW", c.Mode())
	}
	if c.graph == nil {
		t.Error("ProofGraph not initialized")
	}
	if c.gate == nil {
		t.Error("ZeroTrust gate not initialized")
	}
}

func TestNewConnector_Graph(t *testing.T) {
	c := NewConnector(ConnectorConfig{
		BridgeURL: "http://localhost:8787",
		Mode:      RunModeCommunityHarness,
	})
	g := c.Graph()
	if g == nil {
		t.Fatal("Graph() returned nil")
	}
	if g.Len() != 0 {
		t.Errorf("fresh graph should be empty, got %d nodes", g.Len())
	}
}
