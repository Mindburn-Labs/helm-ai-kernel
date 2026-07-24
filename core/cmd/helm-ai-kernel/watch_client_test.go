package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestApprovalHTTPClientListApprovals(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != approvalAPIBasePath || r.Method != http.MethodGet {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("Authorization = %q, want Bearer test-key", got)
		}
		_ = json.NewEncoder(w).Encode([]contracts.ApprovalCeremony{{
			ApprovalID:  "ap-1",
			Subject:     "shell_command",
			Action:      "shell_operate",
			State:       contracts.ApprovalCeremonyPending,
			RequestedBy: "agent.local",
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		}})
	}))
	defer server.Close()

	client, err := newApprovalHTTPClient(server.URL, "test-key")
	if err != nil {
		t.Fatalf("newApprovalHTTPClient: %v", err)
	}
	items, err := client.ListApprovals(context.Background())
	if err != nil {
		t.Fatalf("ListApprovals: %v", err)
	}
	if len(items) != 1 || items[0].ApprovalID != "ap-1" {
		t.Fatalf("items = %+v, want one ap-1", items)
	}
}

func TestApprovalHTTPClientListApprovalsUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := newApprovalHTTPClient(server.URL, "wrong-key")
	if err != nil {
		t.Fatalf("newApprovalHTTPClient: %v", err)
	}
	if _, err := client.ListApprovals(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v, want HTTP 401 error", err)
	}
}

func TestApprovalHTTPClientTransition(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != approvalAPIBasePath+"/ap-9/approve" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			Actor  string `json:"actor"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.Actor != "operator.cli" {
			t.Fatalf("actor = %q, want operator.cli", body.Actor)
		}
		_ = json.NewEncoder(w).Encode(contracts.ApprovalCeremony{
			ApprovalID: "ap-9",
			Subject:    "shell_command",
			Action:     "shell_operate",
			State:      contracts.ApprovalCeremonyAllowed,
		})
	}))
	defer server.Close()

	client, err := newApprovalHTTPClient(server.URL, "test-key")
	if err != nil {
		t.Fatalf("newApprovalHTTPClient: %v", err)
	}
	ceremony, err := client.TransitionApproval(context.Background(), "ap-9", "approve", "operator.cli", "ok")
	if err != nil {
		t.Fatalf("TransitionApproval: %v", err)
	}
	if ceremony.State != contracts.ApprovalCeremonyAllowed {
		t.Fatalf("state = %s, want approved", ceremony.State)
	}
	if _, err := client.TransitionApproval(context.Background(), "ap-9", "revoke", "operator.cli", ""); err == nil {
		t.Fatal("revoke must be rejected client-side")
	}
}

func TestApprovalHTTPClientFailClosedWithoutKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request must never reach the server without an API key")
	}))
	defer server.Close()

	client, err := newApprovalHTTPClient(server.URL, "")
	if err != nil {
		t.Fatalf("newApprovalHTTPClient: %v", err)
	}
	if _, err := client.ListApprovals(context.Background()); !errors.Is(err, errApprovalAPIKeyMissing) {
		t.Fatalf("err = %v, want errApprovalAPIKeyMissing", err)
	}
}

func TestNewApprovalHTTPClientRejectsBadURL(t *testing.T) {
	if _, err := newApprovalHTTPClient("ftp://example.com", "k"); err == nil {
		t.Fatal("non-http scheme must be rejected")
	}
	if _, err := newApprovalHTTPClient("http://", "k"); err == nil {
		t.Fatal("missing host must be rejected")
	}
}
