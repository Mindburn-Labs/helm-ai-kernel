package arc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientHTTPMethodsAndErrors(t *testing.T) {
	ctx := context.Background()
	var sessionMode string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			_ = json.NewEncoder(w).Encode(HealthResponse{
				Status:  "ok",
				Mode:    "test",
				Version: "v1",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/games":
			_ = json.NewEncoder(w).Encode(GameListResponse{
				Games: []GameInfo{{GameID: "game-1", Description: "fixture"}},
				Count: 1,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/session":
			var req CreateSessionRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			sessionMode = req.Mode
			_ = json.NewEncoder(w).Encode(SessionInfo{
				SessionID: "s1",
				GameID:    req.GameID,
				Obs:       arcObservation(false, 0),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/session/s1/step":
			var req StepRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(StepResponse{
				SessionID: "s1",
				StepCount: 1,
				Obs:       arcObservation(false, 0.25),
				Done:      false,
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/session/s1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/scorecard":
			var req ScorecardOpenRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(ScorecardInfo{
				CardID: "card-1",
				Status: "open",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/scorecard/card-1":
			_ = json.NewEncoder(w).Encode(ScorecardInfo{
				CardID:    "card-1",
				Status:    "closed",
				Scores:    map[string]string{"game-1": "1.0"},
				ReplayURL: "https://example.test/replay",
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/scorecard/card-1":
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "missing", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL).WithTimeout(time.Second)
	if client.httpClient.Timeout != time.Second {
		t.Fatalf("timeout = %s, want 1s", client.httpClient.Timeout)
	}

	health, err := client.Health(ctx)
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if health.Status != "ok" || health.Version != "v1" {
		t.Fatalf("unexpected health response: %+v", health)
	}

	games, err := client.ListGames(ctx)
	if err != nil {
		t.Fatalf("ListGames: %v", err)
	}
	if games.Count != 1 || games.Games[0].GameID != "game-1" {
		t.Fatalf("unexpected games response: %+v", games)
	}

	session, err := client.CreateSession(ctx, "game-1", "ONLINE")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if session.SessionID != "s1" || sessionMode != "ONLINE" {
		t.Fatalf("unexpected session=%+v mode=%q", session, sessionMode)
	}

	step, err := client.Step(ctx, "s1", "ACTION1", json.RawMessage(`{"why":"test"}`))
	if err != nil {
		t.Fatalf("Step: %v", err)
	}
	if step.StepCount != 1 || step.Obs.Reward != 0.25 {
		t.Fatalf("unexpected step response: %+v", step)
	}

	if err := client.CloseSession(ctx, "s1"); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}

	card, err := client.OpenScorecard(ctx, []string{"game-1"})
	if err != nil {
		t.Fatalf("OpenScorecard: %v", err)
	}
	if card.CardID != "card-1" {
		t.Fatalf("unexpected scorecard: %+v", card)
	}

	card, err = client.GetScorecard(ctx, "card-1")
	if err != nil {
		t.Fatalf("GetScorecard: %v", err)
	}
	if card.Scores["game-1"] != "1.0" {
		t.Fatalf("unexpected scorecard result: %+v", card)
	}

	if err := client.CloseScorecard(ctx, "card-1"); err != nil {
		t.Fatalf("CloseScorecard: %v", err)
	}

	if _, err := client.get(ctx, "/missing"); err == nil || !strings.Contains(err.Error(), "GET /missing") {
		t.Fatalf("expected get status error, got %v", err)
	}
	if _, err := client.post(ctx, "/missing", map[string]string{"x": "y"}); err == nil || !strings.Contains(err.Error(), "POST /missing") {
		t.Fatalf("expected post status error, got %v", err)
	}
	if _, err := client.post(ctx, "/bad", map[string]any{"f": func() {}}); err == nil || !strings.Contains(err.Error(), "marshal request") {
		t.Fatalf("expected marshal error, got %v", err)
	}
	if err := client.CloseSession(ctx, "missing"); err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("expected close session status error, got %v", err)
	}
	if err := client.CloseScorecard(ctx, "missing"); err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("expected close scorecard status error, got %v", err)
	}

	badURL := &Client{baseURL: "http://[::1", httpClient: &http.Client{}}
	if _, err := badURL.get(ctx, "/x"); err == nil {
		t.Fatal("expected get request creation error")
	}
	if _, err := badURL.post(ctx, "/x", map[string]string{"x": "y"}); err == nil {
		t.Fatal("expected post request creation error")
	}
	if err := badURL.CloseSession(ctx, "s1"); err == nil {
		t.Fatal("expected close session request creation error")
	}
	if err := badURL.CloseScorecard(ctx, "card-1"); err == nil {
		t.Fatal("expected close scorecard request creation error")
	}
}

func TestClientDecodeErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{"))
	}))
	defer server.Close()

	ctx := context.Background()
	client := NewClient(server.URL)

	assertDecodeError := func(name string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "decode") {
			t.Fatalf("%s: expected decode error, got %v", name, err)
		}
	}

	_, err := client.Health(ctx)
	assertDecodeError("Health", err)
	_, err = client.ListGames(ctx)
	assertDecodeError("ListGames", err)
	_, err = client.CreateSession(ctx, "game-1", "OFFLINE")
	assertDecodeError("CreateSession", err)
	_, err = client.Step(ctx, "s1", "ACTION1", nil)
	assertDecodeError("Step", err)
	_, err = client.OpenScorecard(ctx, []string{"game-1"})
	assertDecodeError("OpenScorecard", err)
	_, err = client.GetScorecard(ctx, "card-1")
	assertDecodeError("GetScorecard", err)
}

func TestClientTransportErrorWrappers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("closed server unexpectedly received %s %s", r.Method, r.URL.Path)
	}))
	baseURL := server.URL
	server.Close()

	ctx := context.Background()
	client := NewClient(baseURL).WithTimeout(20 * time.Millisecond)

	assertWrappedError := func(name string, err error, want string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: expected %q error, got %v", name, want, err)
		}
	}

	_, err := client.Health(ctx)
	assertWrappedError("Health", err, "health check failed")
	_, err = client.ListGames(ctx)
	assertWrappedError("ListGames", err, "list games failed")
	_, err = client.CreateSession(ctx, "game-1", "OFFLINE")
	assertWrappedError("CreateSession", err, "create session failed")
	_, err = client.Step(ctx, "s1", "ACTION1", nil)
	assertWrappedError("Step", err, "step failed")
	_, err = client.OpenScorecard(ctx, []string{"game-1"})
	assertWrappedError("OpenScorecard", err, "open scorecard failed")
	_, err = client.GetScorecard(ctx, "card-1")
	assertWrappedError("GetScorecard", err, "get scorecard failed")
	assertWrappedError("CloseSession", client.CloseSession(ctx, "s1"), "close session failed")
	assertWrappedError("CloseScorecard", client.CloseScorecard(ctx, "card-1"), "close scorecard failed")
}

func TestConnectorLifecycleThroughBridge(t *testing.T) {
	ctx := context.Background()
	var createMode string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			_ = json.NewEncoder(w).Encode(HealthResponse{Status: "ok", Mode: "bridge", Version: "v1"})
		case r.Method == http.MethodGet && r.URL.Path == "/games":
			_ = json.NewEncoder(w).Encode(GameListResponse{
				Games: []GameInfo{{GameID: "game-1"}},
				Count: 1,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/scorecard":
			_ = json.NewEncoder(w).Encode(ScorecardInfo{CardID: "card-1", Status: "open"})
		case r.Method == http.MethodGet && r.URL.Path == "/scorecard/card-1":
			_ = json.NewEncoder(w).Encode(ScorecardInfo{
				CardID:    "card-1",
				Status:    "closed",
				Scores:    map[string]string{"game-1": "1.0"},
				ReplayURL: "https://example.test/replay",
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/scorecard/card-1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/session":
			var req CreateSessionRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			createMode = req.Mode
			_ = json.NewEncoder(w).Encode(SessionInfo{
				SessionID: "s1",
				GameID:    req.GameID,
				Obs:       arcObservation(false, 0),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/session/s1/step":
			var req StepRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			done := req.Action == "ACTION6"
			reward := 0.2
			if done {
				reward = 1.0
			}
			_ = json.NewEncoder(w).Encode(StepResponse{
				SessionID: "s1",
				StepCount: 1,
				Obs:       arcObservation(done, reward),
				Done:      done,
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/session/s1":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected route", http.StatusNotFound)
		}
	}))
	defer server.Close()

	policy := DefaultPolicy(RunModeCommunityHarness)
	policy.BridgeMode = BridgeModeOnline
	policy.MaxActionsPerEpisode = 3
	conn := NewConnector(ConnectorConfig{
		BridgeURL: server.URL,
		Mode:      RunModeCommunityHarness,
		Policy:    policy,
	})

	health, err := conn.Health(ctx)
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if health.Status != "ok" {
		t.Fatalf("unexpected health: %+v", health)
	}

	games, err := conn.ListGames(ctx)
	if err != nil {
		t.Fatalf("ListGames: %v", err)
	}
	if games.Count != 1 {
		t.Fatalf("unexpected games: %+v", games)
	}

	card, err := conn.OpenScorecard(ctx, []string{"game-1"})
	if err != nil {
		t.Fatalf("OpenScorecard: %v", err)
	}

	session, err := conn.CreateSession(ctx, "game-1")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if session.SessionID != "s1" || createMode != string(BridgeModeOnline) {
		t.Fatalf("unexpected session=%+v bridge mode=%q", session, createMode)
	}

	if _, err := conn.Step(ctx, session.SessionID, "ACTION1", json.RawMessage(`{"plan":"simple"}`)); err != nil {
		t.Fatalf("Step ACTION1: %v", err)
	}
	step, err := conn.Step(ctx, session.SessionID, "ACTION6", json.RawMessage(`{"x":1,"y":2}`))
	if err != nil {
		t.Fatalf("Step ACTION6: %v", err)
	}
	if !step.Done || step.Obs.Reward != 1.0 {
		t.Fatalf("unexpected final step: %+v", step)
	}

	gotCard, err := conn.GetScorecard(ctx, card.CardID)
	if err != nil {
		t.Fatalf("GetScorecard: %v", err)
	}
	if gotCard.Scores["game-1"] != "1.0" {
		t.Fatalf("unexpected scorecard: %+v", gotCard)
	}

	if err := conn.CloseScorecard(ctx, card.CardID); err != nil {
		t.Fatalf("CloseScorecard: %v", err)
	}
	if _, ok := conn.activeGames["game-1"]; ok {
		t.Fatal("game remained active after closing scorecard")
	}

	summary, err := conn.CloseSession(ctx, session.SessionID)
	if err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	if summary.TotalSteps != 2 || !summary.Completed || summary.FinalReward != 1.0 || summary.EpisodeHash == "" {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if conn.Graph().Len() < 9 {
		t.Fatalf("expected lifecycle receipts, graph len = %d", conn.Graph().Len())
	}
}

func TestConnectorSessionBudgetBranches(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/session":
			_ = json.NewEncoder(w).Encode(SessionInfo{
				SessionID: "s1",
				GameID:    "game-1",
				Obs:       arcObservation(false, 0),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/session/s1/step":
			_ = json.NewEncoder(w).Encode(StepResponse{
				SessionID: "s1",
				StepCount: 1,
				Obs:       arcObservation(false, 0.1),
				Done:      false,
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/session/s1":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected route", http.StatusNotFound)
		}
	}))
	defer server.Close()

	policy := DefaultPolicy(RunModeCommunityHarness)
	policy.MaxActionsPerEpisode = 1
	conn := NewConnector(ConnectorConfig{
		BridgeURL: server.URL,
		Mode:      RunModeCommunityHarness,
		Policy:    policy,
	})

	if _, err := conn.Step(ctx, "unknown", "ACTION1", nil); err == nil || !strings.Contains(err.Error(), "not tracked") {
		t.Fatalf("expected unknown session step error, got %v", err)
	}
	if _, err := conn.CloseSession(ctx, "unknown"); err == nil || !strings.Contains(err.Error(), "not tracked") {
		t.Fatalf("expected unknown session close error, got %v", err)
	}

	conn.mu.Lock()
	conn.sessions["done"] = &sessionTracker{gameID: "game-1", done: true}
	conn.mu.Unlock()
	if _, err := conn.Step(ctx, "done", "ACTION1", nil); err == nil || !strings.Contains(err.Error(), "already done") {
		t.Fatalf("expected done session error, got %v", err)
	}

	session, err := conn.CreateSession(ctx, "game-1")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := conn.Step(ctx, session.SessionID, "ACTION1", nil); err != nil {
		t.Fatalf("first step: %v", err)
	}
	if _, err := conn.Step(ctx, session.SessionID, "ACTION1", nil); err == nil || !strings.Contains(err.Error(), "budget exceeded") {
		t.Fatalf("expected action budget error, got %v", err)
	}
	if _, err := conn.CloseSession(ctx, session.SessionID); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
}

func TestConnectorGateDenialsAndBridgeBranches(t *testing.T) {
	ctx := context.Background()

	denied := NewConnector(ConnectorConfig{
		BridgeURL: "http://127.0.0.1:1",
		Mode:      RunModeCommunityHarness,
	})
	denied.connectorID = "missing-policy"

	assertGateDenied := func(name string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "gate denied") {
			t.Fatalf("%s: expected gate denial, got %v", name, err)
		}
	}

	_, err := denied.ListGames(ctx)
	assertGateDenied("ListGames", err)
	_, err = denied.CreateSession(ctx, "game-1")
	assertGateDenied("CreateSession", err)
	_, err = denied.Step(ctx, "s1", "ACTION1", nil)
	assertGateDenied("Step", err)
	_, err = denied.OpenScorecard(ctx, []string{"game-1"})
	assertGateDenied("OpenScorecard", err)
	_, err = denied.GetScorecard(ctx, "card-1")
	assertGateDenied("GetScorecard", err)
	assertGateDenied("CloseScorecard", denied.CloseScorecard(ctx, "card-1"))

	stepFailure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bridge refused step", http.StatusBadGateway)
	}))
	defer stepFailure.Close()

	conn := NewConnector(ConnectorConfig{
		BridgeURL: stepFailure.URL,
		Mode:      RunModeCommunityHarness,
	})
	conn.sessions["s1"] = &sessionTracker{gameID: "game-1"}
	if _, err := conn.Step(ctx, "s1", "ACTION1", json.RawMessage(`{"ok":true}`)); err == nil || !strings.Contains(err.Error(), "bridge step") {
		t.Fatalf("expected bridge step error, got %v", err)
	}
	if _, err := conn.Step(ctx, "s1", "ACTION1", json.RawMessage(`{`)); err == nil || !strings.Contains(err.Error(), "make intent payload") {
		t.Fatalf("expected malformed intent payload error, got %v", err)
	}

	closeScorecardServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "no final state", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer closeScorecardServer.Close()

	closer := NewConnector(ConnectorConfig{
		BridgeURL: closeScorecardServer.URL,
		Mode:      RunModeCommunityHarness,
	})
	closer.activeGames["game-1"] = "card-1"
	if err := closer.CloseScorecard(ctx, "card-1"); err != nil {
		t.Fatalf("CloseScorecard with missing final state: %v", err)
	}
	if _, ok := closer.activeGames["game-1"]; ok {
		t.Fatal("active game not cleared after close without final state")
	}
}

func TestConnectorOfficialShadowScorecardAuthorizesGame(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/scorecard":
			_ = json.NewEncoder(w).Encode(ScorecardInfo{CardID: "card-1", Status: "open"})
		case r.Method == http.MethodPost && r.URL.Path == "/session":
			_ = json.NewEncoder(w).Encode(SessionInfo{
				SessionID: "s1",
				GameID:    "game-1",
				Obs:       arcObservation(false, 0),
			})
		default:
			http.Error(w, "unexpected route", http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn := NewConnector(ConnectorConfig{
		BridgeURL: server.URL,
		Mode:      RunModeOfficialShadow,
	})
	if _, err := conn.OpenScorecard(ctx, []string{"game-1"}); err != nil {
		t.Fatalf("OpenScorecard: %v", err)
	}
	if _, err := conn.CreateSession(ctx, "game-1"); err != nil {
		t.Fatalf("CreateSession should be allowed after scorecard open: %v", err)
	}
}

func TestPolicyFallbackAndErrorBranches(t *testing.T) {
	if policy := DefaultPolicy(RunMode("unknown")); policy.Mode != RunModeOfficialShadow {
		t.Fatalf("fallback policy mode = %s, want %s", policy.Mode, RunModeOfficialShadow)
	}

	if got := errInvalidPolicy("sample").Error(); got != "arc policy error: sample" {
		t.Fatalf("policy error string = %q", got)
	}

	policy := DefaultPolicy(RunModeCommunityHarness)
	policy.MaxActionsPerEpisode = 0
	if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "max_actions_per_episode") {
		t.Fatalf("expected max actions validation error, got %v", err)
	}
}

func arcObservation(done bool, reward float64) Observation {
	return Observation{
		Frames: []Frame{{
			Grid:   [][]int{{0, 1}, {2, 3}},
			Width:  2,
			Height: 2,
		}},
		AvailableActions: []string{"ACTION1", "ACTION6"},
		LevelsCompleted:  1,
		TotalLevels:      1,
		Done:             done,
		Reward:           reward,
		Info:             map[string]string{"fixture": "true"},
	}
}
