package pdp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOpaPDP_Evaluate_Allow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate request format.
		var req opaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode OPA request: %v", err)
		}
		if req.Input.Principal != "agent-001" {
			t.Errorf("expected principal 'agent-001', got %q", req.Input.Principal)
		}
		if req.Input.Action != "read_file" {
			t.Errorf("expected action 'read_file', got %q", req.Input.Action)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(opaResponse{
			Result: &opaResult{Allow: true, ReasonCode: ""},
		})
	}))
	defer server.Close()

	pdp, err := NewOpaPDP(OpaConfig{
		Endpoint:  server.URL,
		PolicyRef: "test-v1",
		TimeoutMs: 5000,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "agent-001",
		Action:    "read_file",
		Resource:  "/tmp/test.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Allow {
		t.Error("expected ALLOW, got DENY")
	}
	if resp.PolicyRef != "opa:test-v1" {
		t.Errorf("expected PolicyRef 'opa:test-v1', got %q", resp.PolicyRef)
	}
	if resp.DecisionHash == "" {
		t.Error("DecisionHash should not be empty")
	}
}

func TestOpaPDP_Evaluate_Deny(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(opaResponse{
			Result: &opaResult{Allow: false, ReasonCode: "unauthorized"},
		})
	}))
	defer server.Close()

	pdp, err := NewOpaPDP(OpaConfig{
		Endpoint:  server.URL,
		PolicyRef: "test-v1",
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "agent-001",
		Action:    "delete_file",
		Resource:  "/etc/passwd",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allow {
		t.Error("expected DENY, got ALLOW")
	}
	if resp.ReasonCode == "" {
		t.Error("ReasonCode should not be empty for DENY")
	}
}

func TestOpaPDP_FailClosed_NetworkError(t *testing.T) {
	pdp, err := NewOpaPDP(OpaConfig{
		Endpoint:  "http://localhost:1", // unreachable
		PolicyRef: "test-v1",
		TimeoutMs: 100,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "agent-001",
		Action:    "read_file",
	})
	if err != nil {
		t.Fatal("should not return error (fail-closed returns DENY response)")
	}
	if resp.Allow {
		t.Error("expected DENY on network error (fail-closed)")
	}
}

func TestOpaPDP_FailClosed_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	pdp, err := NewOpaPDP(OpaConfig{
		Endpoint: server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "agent-001",
		Action:    "read_file",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allow {
		t.Error("expected DENY on 500 (fail-closed)")
	}
}

func TestOpaPDP_FailClosed_MalformedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	pdp, err := NewOpaPDP(OpaConfig{
		Endpoint: server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "agent-001",
		Action:    "read_file",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allow {
		t.Error("expected DENY on malformed response (fail-closed)")
	}
}

func TestOpaPDP_FailClosed_NilResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(opaResponse{Result: nil})
	}))
	defer server.Close()

	pdp, err := NewOpaPDP(OpaConfig{
		Endpoint: server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "agent-001",
		Action:    "read_file",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allow {
		t.Error("expected DENY when OPA result is nil (fail-closed)")
	}
}

func TestOpaPDP_NilRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach OPA server on nil request")
	}))
	defer server.Close()

	pdp, err := NewOpaPDP(OpaConfig{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := pdp.Evaluate(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allow {
		t.Error("expected DENY on nil request")
	}
}

func TestOpaPDP_FailClosed_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // slow server
	}))
	defer server.Close()

	pdp, err := NewOpaPDP(OpaConfig{
		Endpoint:  server.URL,
		TimeoutMs: 50,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	resp, err := pdp.Evaluate(ctx, &DecisionRequest{
		Principal: "agent-001",
		Action:    "read_file",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allow {
		t.Error("expected DENY on context cancelled (fail-closed)")
	}
}

func TestOpaPDP_Backend(t *testing.T) {
	pdp, _ := NewOpaPDP(OpaConfig{
		Endpoint: "http://localhost:8181",
	})
	if pdp.Backend() != BackendOPA {
		t.Errorf("expected backend %q, got %q", BackendOPA, pdp.Backend())
	}
}

func TestOpaPDP_PolicyHash_Deterministic(t *testing.T) {
	pdp1, _ := NewOpaPDP(OpaConfig{
		Endpoint:  "http://localhost:8181/v1/data/helm",
		PolicyRef: "v1.0.0",
	})
	pdp2, _ := NewOpaPDP(OpaConfig{
		Endpoint:  "http://localhost:8181/v1/data/helm",
		PolicyRef: "v1.0.0",
	})
	if pdp1.PolicyHash() != pdp2.PolicyHash() {
		t.Error("PolicyHash should be deterministic for same config")
	}

	pdp3, _ := NewOpaPDP(OpaConfig{
		Endpoint:  "http://localhost:8181/v1/data/helm",
		PolicyRef: "v2.0.0",
	})
	if pdp1.PolicyHash() == pdp3.PolicyHash() {
		t.Error("PolicyHash should differ for different policy refs")
	}
}

func TestOpaPDP_DecisionHash_Deterministic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(opaResponse{
			Result: &opaResult{Allow: true},
		})
	}))
	defer server.Close()

	pdp, _ := NewOpaPDP(OpaConfig{Endpoint: server.URL, PolicyRef: "v1"})
	req := &DecisionRequest{Principal: "a", Action: "b", Resource: "c"}

	resp1, _ := pdp.Evaluate(context.Background(), req)
	resp2, _ := pdp.Evaluate(context.Background(), req)

	if resp1.DecisionHash != resp2.DecisionHash {
		t.Error("DecisionHash should be deterministic for same decision")
	}
}

func TestNewOpaPDP_MissingEndpoint(t *testing.T) {
	_, err := NewOpaPDP(OpaConfig{})
	if err == nil {
		t.Error("expected error for missing endpoint")
	}
}
