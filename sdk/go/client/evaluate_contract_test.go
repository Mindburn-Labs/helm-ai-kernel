package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEvaluateDecisionWithScopeBindsHeadersAndCanonicalBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/evaluate" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		for header, want := range map[string]string{
			"Authorization":       "Bearer token",
			"X-Helm-Tenant-ID":    "tenant-a",
			"X-Helm-Principal-ID": "operator-a",
			"X-Helm-Session-ID":   "session-a",
			"X-Helm-Workspace-ID": "workspace-a",
			"Idempotency-Key":     "evaluate-1",
		} {
			if got := r.Header.Get(header); got != want {
				t.Fatalf("%s = %q, want %q", header, got, want)
			}
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["action"] != "read" || body["resource"] != "ticket:1" {
			t.Fatalf("body = %#v", body)
		}
		if _, exists := body["principal"]; exists {
			t.Fatalf("caller identity leaked into request body: %#v", body)
		}
		history, ok := body["session_history"].([]interface{})
		if !ok || len(history) != 1 {
			t.Fatalf("session history = %#v", body["session_history"])
		}
		entry, ok := history[0].(map[string]interface{})
		if !ok || entry["action"] != "read-history" || entry["resource"] != "ticket:0" || entry["verdict"] != "ALLOW" || entry["timestamp"] != float64(1) {
			t.Fatalf("session history entry = %#v", history[0])
		}
		if _, exists := entry["principal"]; exists {
			t.Fatalf("caller identity leaked into session history: %#v", entry)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Helm-Receipt-ID", "rcpt-decision-1")
		w.Header().Set("X-Helm-Idempotency-Replayed", "true")
		_, _ = w.Write([]byte(`{"id":"decision-1","tenant_id":"tenant-a","session_id":"session-a","signature_schema":"helm.decision.signature.v2"}`))
	}))
	defer server.Close()

	client := New(
		server.URL,
		WithAPIKey("token"),
		WithTenantID("tenant-default"),
		WithPrincipalID("principal-default"),
		WithWorkspaceID("workspace-default"),
	)
	request := DecisionRequest{
		Action:   "read",
		Resource: "ticket:1",
		SessionHistory: []SessionAction{{
			Action:               "read-history",
			Resource:             "ticket:0",
			Verdict:              "ALLOW",
			Timestamp:            1,
			AdditionalProperties: map[string]interface{}{"principal": "must-not-serialize"},
		}},
	}
	request.AdditionalProperties = map[string]interface{}{"principal": "must-not-serialize"}
	result, err := client.EvaluateDecisionWithScope(request, EvaluationScope{
		TenantID:    "tenant-a",
		PrincipalID: "operator-a",
		SessionID:   "session-a",
		WorkspaceID: "workspace-a",
	}, "evaluate-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision.GetId() != "decision-1" || result.ReceiptID != "rcpt-decision-1" || !result.Replayed {
		t.Fatalf("result = %#v", result)
	}
}

func TestEvaluateDecisionWithScopeFailsLocallyWithoutRequiredBinding(t *testing.T) {
	client := New("http://127.0.0.1:1", WithAPIKey("token"))
	_, err := client.EvaluateDecisionWithScope(DecisionRequest{Action: "read", Resource: "ticket:1"}, EvaluationScope{
		TenantID:  "tenant-a",
		SessionID: "session-a",
	}, "")
	if err == nil {
		t.Fatalf("expected local scope validation error")
	}
}

func TestEvaluateDecisionIsRetiredLocally(t *testing.T) {
	client := New("http://127.0.0.1:1")
	_, err := client.EvaluateDecision(SurfaceRecord{"principal": "spoofed"})
	if err == nil || err.Error() != "EvaluateDecision is retired; use EvaluateDecisionWithScope with EvaluationScope" {
		t.Fatalf("unexpected legacy evaluator error: %v", err)
	}
}

func TestEvaluateDecisionWithScopeDoesNotInheritClientWorkspace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Helm-Workspace-ID"); got != "" {
			t.Fatalf("unexpected inherited workspace header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Helm-Receipt-ID", "rcpt-decision-2")
		_, _ = w.Write([]byte(`{"id":"decision-2"}`))
	}))
	defer server.Close()

	client := New(server.URL, WithAPIKey("token"), WithWorkspaceID("workspace-default"))
	_, err := client.EvaluateDecisionWithScope(
		DecisionRequest{Action: "read", Resource: "ticket:2"},
		EvaluationScope{TenantID: "tenant-a", PrincipalID: "operator-a", SessionID: "session-a"},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEvaluateDecisionWithScopeRejectsMissingReceiptID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"decision-3"}`))
	}))
	defer server.Close()

	client := New(server.URL, WithAPIKey("token"))
	_, err := client.EvaluateDecisionWithScope(
		DecisionRequest{Action: "read", Resource: "ticket:3"},
		EvaluationScope{TenantID: "tenant-a", PrincipalID: "operator-a", SessionID: "session-a"},
		"",
	)
	if err == nil || err.Error() != "evaluator response missing required X-Helm-Receipt-ID" {
		t.Fatalf("unexpected missing receipt error: %v", err)
	}
}
