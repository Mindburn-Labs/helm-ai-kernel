package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/pdp"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	helmPDP := pdp.NewHelmPDP("test-v1", map[string]bool{
		"read_file":  true,
		"list_dir":   true,
		"write_file": true,
	})
	return NewServer(ServerConfig{PDP: helmPDP})
}

func TestEvaluate_Allow(t *testing.T) {
	srv := newTestServer(t)
	body := EvaluateRequest{
		Tool:        "read_file",
		Args:        map[string]any{"path": "/tmp/test.txt"},
		AgentID:     "agent-001",
		EffectLevel: "E0",
		SessionID:   "session-001",
	}
	reqBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp EvaluateResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !resp.Allow {
		t.Error("expected ALLOW for read_file")
	}
	if resp.ReceiptID == "" {
		t.Error("ReceiptID should be generated")
	}
	if resp.LamportClock == 0 {
		t.Error("LamportClock should be > 0")
	}
	if resp.DecisionHash == "" {
		t.Error("DecisionHash should be set")
	}
}

func TestEvaluate_Deny(t *testing.T) {
	// HelmPDP checks rules by Resource (mapped from EffectLevel).
	// Create a PDP with E4 explicitly denied.
	denyPDP := pdp.NewHelmPDP("test-v1", map[string]bool{
		"E4": false, // deny E4 (irreversible)
	})
	srv := NewServer(ServerConfig{PDP: denyPDP})

	body := EvaluateRequest{
		Tool:        "delete_file",
		AgentID:     "agent-001",
		EffectLevel: "E4", // maps to Resource, which is denied
	}
	reqBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp EvaluateResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Allow {
		t.Error("expected DENY for E4 effect level")
	}
}

func TestEvaluate_InvalidMethod(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evaluate", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestGetReceipt(t *testing.T) {
	srv := newTestServer(t)

	// Evaluate to create a receipt
	body := EvaluateRequest{Tool: "read_file", AgentID: "a", SessionID: "s"}
	reqBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var evalResp EvaluateResponse
	json.NewDecoder(w.Body).Decode(&evalResp)

	// Get the receipt
	req = httptest.NewRequest(http.MethodGet, "/api/v1/receipts/"+evalResp.ReceiptID, nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var receipt Receipt
	json.NewDecoder(w.Body).Decode(&receipt)
	if receipt.ReceiptID != evalResp.ReceiptID {
		t.Error("receipt ID mismatch")
	}
	if receipt.Signature == "" {
		t.Error("signature should be set")
	}
}

func TestGetReceipt_NotFound(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestVerifyChain(t *testing.T) {
	srv := newTestServer(t)

	// Create 3 receipts in same session
	for i := 0; i < 3; i++ {
		body := EvaluateRequest{Tool: "read_file", AgentID: "a", SessionID: "test-session"}
		reqBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
	}

	// Verify chain
	req := httptest.NewRequest(http.MethodGet, "/api/v1/verify/test-session", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var result map[string]any
	json.NewDecoder(w.Body).Decode(&result)
	if result["valid"] != true {
		t.Error("chain should be valid")
	}
	if result["receipts"].(float64) != 3 {
		t.Errorf("expected 3 receipts, got %v", result["receipts"])
	}
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var result map[string]any
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "ok" {
		t.Error("health should return ok")
	}
}

func TestCORS(t *testing.T) {
	// With no AllowedOrigins configured, CORS headers should NOT be set (secure default).
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/evaluate", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Error("OPTIONS should return 200 for preflight")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS origin should NOT be set when AllowedOrigins is nil (secure default)")
	}

	// With explicit AllowedOrigins, matching origin should be reflected.
	helmPDP := pdp.NewHelmPDP("test-v1", map[string]bool{"read_file": true})
	srvWithOrigins := NewServer(ServerConfig{
		PDP:            helmPDP,
		AllowedOrigins: []string{"https://app.example.com"},
	})
	req2 := httptest.NewRequest(http.MethodOptions, "/api/v1/evaluate", nil)
	req2.Header.Set("Origin", "https://app.example.com")
	w2 := httptest.NewRecorder()
	srvWithOrigins.ServeHTTP(w2, req2)
	if w2.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("expected CORS origin https://app.example.com, got %q", w2.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestLamportMonotonicity(t *testing.T) {
	srv := newTestServer(t)

	var lamports []uint64
	for i := 0; i < 5; i++ {
		body := EvaluateRequest{Tool: "read_file", AgentID: "a", SessionID: "s"}
		reqBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(reqBody))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		var resp EvaluateResponse
		json.NewDecoder(w.Body).Decode(&resp)
		lamports = append(lamports, resp.LamportClock)
	}

	for i := 1; i < len(lamports); i++ {
		if lamports[i] <= lamports[i-1] {
			t.Errorf("Lamport clocks not monotonic: %d <= %d", lamports[i], lamports[i-1])
		}
	}
}
