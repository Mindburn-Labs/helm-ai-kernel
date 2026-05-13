package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ──────────────────────────────────────────────────────────────
// Autonomy Handler tests
// ──────────────────────────────────────────────────────────────

func TestAutonomyHandler_GetState_Empty(t *testing.T) {
	provider := api.NewInMemoryAutonomyProvider()
	handler := api.NewAutonomyHandler(provider)

	mux := http.NewServeMux()
	handler.Register(mux, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/autonomy/state", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var state contracts.GlobalAutonomyState
	if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if state.OrgID != "default" {
		t.Errorf("expected org_id 'default', got %q", state.OrgID)
	}
	if state.Posture != contracts.PostureObserve {
		t.Errorf("expected posture OBSERVE, got %q", state.Posture)
	}
	if state.GlobalMode != contracts.GlobalModeRunning {
		t.Errorf("expected global_mode RUNNING, got %q", state.GlobalMode)
	}
	if state.Summary.Now != "Idle — no active runs" {
		t.Errorf("unexpected summary.now: %q", state.Summary.Now)
	}
	if state.RiskLevel != contracts.RiskLevelNormal {
		t.Errorf("expected risk_level NORMAL, got %q", state.RiskLevel)
	}
}

func TestAutonomyHandler_GetState_WithBlockers(t *testing.T) {
	provider := api.NewInMemoryAutonomyProvider()
	provider.AddDecisionRequest(contracts.DecisionRequest{
		RequestID: "dr-1",
		Kind:      contracts.DecisionKindApproval,
		Title:     "Approve deployment",
		Status:    contracts.DecisionStatusPending,
		Options: []contracts.DecisionOption{
			{ID: "approve", Label: "Approve"},
			{ID: "deny", Label: "Deny"},
		},
		Priority: contracts.DecisionPriorityNormal,
	})

	handler := api.NewAutonomyHandler(provider)
	mux := http.NewServeMux()
	handler.Register(mux, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/autonomy/state", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var state contracts.GlobalAutonomyState
	if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(state.BlockersQueue) != 1 {
		t.Fatalf("expected 1 blocker, got %d", len(state.BlockersQueue))
	}
	if state.RiskLevel != contracts.RiskLevelElevated {
		t.Errorf("expected ELEVATED risk with 1 blocker, got %q", state.RiskLevel)
	}
	if state.Summary.NeedYou != "Approve deployment" {
		t.Errorf("expected needYou='Approve deployment', got %q", state.Summary.NeedYou)
	}
}

func TestAutonomyHandler_MethodNotAllowed(t *testing.T) {
	provider := api.NewInMemoryAutonomyProvider()
	handler := api.NewAutonomyHandler(provider)
	mux := http.NewServeMux()
	handler.Register(mux, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/autonomy/state", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// ──────────────────────────────────────────────────────────────
// Decision Handler tests
// ──────────────────────────────────────────────────────────────

func TestDecisionHandler_CreateAndList(t *testing.T) {
	store := api.NewInMemoryDecisionStore()
	handler := api.NewDecisionHandler(store)
	mux := http.NewServeMux()
	handler.Register(mux)

	// Create a decision
	dr := contracts.DecisionRequest{
		RequestID: "dr-test-1",
		Kind:      contracts.DecisionKindApproval,
		Title:     "Approve production deploy",
		Options: []contracts.DecisionOption{
			{ID: "approve", Label: "Approve", IsDefault: true},
			{ID: "deny", Label: "Deny"},
		},
		Priority: contracts.DecisionPriorityNormal,
	}

	body, _ := json.Marshal(dr)
	req := httptest.NewRequest(http.MethodPost, "/api/decisions", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// List decisions
	req = httptest.NewRequest(http.MethodGet, "/api/decisions", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var listResp struct {
		Decisions []contracts.DecisionRequest `json:"decisions"`
		Count     int                         `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if listResp.Count != 1 {
		t.Errorf("expected 1 decision, got %d", listResp.Count)
	}
	if listResp.Decisions[0].Status != contracts.DecisionStatusPending {
		t.Errorf("expected PENDING, got %s", listResp.Decisions[0].Status)
	}
}

func TestDecisionHandler_Resolve(t *testing.T) {
	store := api.NewInMemoryDecisionStore()
	handler := api.NewDecisionHandler(store)
	mux := http.NewServeMux()
	handler.Register(mux)

	// Seed a decision
	dr := &contracts.DecisionRequest{
		RequestID: "dr-resolve-1",
		Kind:      contracts.DecisionKindApproval,
		Title:     "Approve it",
		Options: []contracts.DecisionOption{
			{ID: "yes", Label: "Yes"},
			{ID: "no", Label: "No"},
		},
		Priority:  contracts.DecisionPriorityNormal,
		Status:    contracts.DecisionStatusPending,
		CreatedAt: time.Now().UTC(),
	}
	if err := store.Create(dr); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	// Resolve it
	resolveBody, _ := json.Marshal(map[string]string{
		"option_id":   "yes",
		"resolved_by": "operator@mindburn.org",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/decisions/dr-resolve-1/resolve", bytes.NewReader(resolveBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resolved contracts.DecisionRequest
	if err := json.Unmarshal(rec.Body.Bytes(), &resolved); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if resolved.Status != contracts.DecisionStatusResolved {
		t.Errorf("expected RESOLVED, got %s", resolved.Status)
	}
	if resolved.ResolvedOptionID != "yes" {
		t.Errorf("expected option 'yes', got %q", resolved.ResolvedOptionID)
	}
}

func TestDecisionHandler_Resolve_InvalidOption(t *testing.T) {
	store := api.NewInMemoryDecisionStore()
	handler := api.NewDecisionHandler(store)
	mux := http.NewServeMux()
	handler.Register(mux)

	dr := &contracts.DecisionRequest{
		RequestID: "dr-invalid-opt",
		Kind:      contracts.DecisionKindApproval,
		Title:     "Test",
		Options: []contracts.DecisionOption{
			{ID: "a", Label: "A"},
			{ID: "b", Label: "B"},
		},
		Priority:  contracts.DecisionPriorityNormal,
		Status:    contracts.DecisionStatusPending,
		CreatedAt: time.Now().UTC(),
	}
	_ = store.Create(dr)

	resolveBody, _ := json.Marshal(map[string]string{
		"option_id":   "nonexistent",
		"resolved_by": "op",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/decisions/dr-invalid-opt/resolve", bytes.NewReader(resolveBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestDecisionHandler_Create_ValidationError(t *testing.T) {
	store := api.NewInMemoryDecisionStore()
	handler := api.NewDecisionHandler(store)
	mux := http.NewServeMux()
	handler.Register(mux)

	// Missing options — should fail validation
	dr := contracts.DecisionRequest{
		RequestID: "dr-bad",
		Kind:      contracts.DecisionKindApproval,
		Title:     "Bad request",
		Options:   []contracts.DecisionOption{{ID: "only-one", Label: "Only"}},
	}

	body, _ := json.Marshal(dr)
	req := httptest.NewRequest(http.MethodPost, "/api/decisions", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ──────────────────────────────────────────────────────────────
// Control Endpoint tests (D3)
// ──────────────────────────────────────────────────────────────

func TestControlEndpoint_PauseAndResume(t *testing.T) {
	provider := api.NewInMemoryAutonomyProvider()
	provider.SetPosture(contracts.PostureTransact) // enough for PAUSE/RUN
	handler := api.NewAutonomyHandler(provider)
	mux := http.NewServeMux()
	handler.Register(mux, nil)

	// Pause
	body := `{"action":"PAUSE"}`
	req := httptest.NewRequest(http.MethodPost, "/api/autonomy/control", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PAUSE: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		PreviousMode string `json:"previous_mode"`
		NewMode      string `json:"new_mode"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.PreviousMode != "RUNNING" {
		t.Errorf("expected previous_mode=RUNNING, got %s", resp.PreviousMode)
	}
	if resp.NewMode != "PAUSED" {
		t.Errorf("expected new_mode=PAUSED, got %s", resp.NewMode)
	}

	// Resume
	body = `{"action":"RUN"}`
	req = httptest.NewRequest(http.MethodPost, "/api/autonomy/control", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("RUN: expected 200, got %d", rec.Code)
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.NewMode != "RUNNING" {
		t.Errorf("expected new_mode=RUNNING, got %s", resp.NewMode)
	}
}

func TestControlEndpoint_FreezeRequiresSovereign(t *testing.T) {
	provider := api.NewInMemoryAutonomyProvider()
	provider.SetPosture(contracts.PostureObserve) // too low for FREEZE
	handler := api.NewAutonomyHandler(provider)
	mux := http.NewServeMux()
	handler.Register(mux, nil)

	body := `{"action":"FREEZE"}`
	req := httptest.NewRequest(http.MethodPost, "/api/autonomy/control", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for FREEZE in OBSERVE posture, got %d", rec.Code)
	}

	// Now with Sovereign posture → should succeed
	provider.SetPosture(contracts.PostureSovereign)
	req = httptest.NewRequest(http.MethodPost, "/api/autonomy/control", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for FREEZE in SOVEREIGN posture, got %d", rec.Code)
	}
}

func TestControlEndpoint_InvalidAction(t *testing.T) {
	provider := api.NewInMemoryAutonomyProvider()
	handler := api.NewAutonomyHandler(provider)
	mux := http.NewServeMux()
	handler.Register(mux, nil)

	body := `{"action":"EXPLODE"}`
	req := httptest.NewRequest(http.MethodPost, "/api/autonomy/control", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid action, got %d", rec.Code)
	}
}

func TestControlEndpoint_MethodNotAllowed(t *testing.T) {
	provider := api.NewInMemoryAutonomyProvider()
	handler := api.NewAutonomyHandler(provider)
	mux := http.NewServeMux()
	handler.Register(mux, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/autonomy/control", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET on control endpoint, got %d", rec.Code)
	}
}

// ──────────────────────────────────────────────────────────────
// D3: Empty title rejection (Untitled gating)
// ──────────────────────────────────────────────────────────────

func TestDecisionHandler_Create_EmptyTitleRejected(t *testing.T) {
	store := api.NewInMemoryDecisionStore()
	handler := api.NewDecisionHandler(store)
	mux := http.NewServeMux()
	handler.Register(mux)

	dr := contracts.DecisionRequest{
		Kind:  contracts.DecisionKindApproval,
		Title: "", // Empty title — MUST be rejected
		Options: []contracts.DecisionOption{
			{ID: "a", Label: "Approve"},
			{ID: "b", Label: "Deny"},
		},
		Priority: contracts.DecisionPriorityNormal,
	}

	body, _ := json.Marshal(dr)
	req := httptest.NewRequest(http.MethodPost, "/api/decisions", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty title DecisionRequest, got %d: %s", rec.Code, rec.Body.String())
	}
}
