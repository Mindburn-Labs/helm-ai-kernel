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

func TestApprovalHTTPClientListsAndTransitions(t *testing.T) {
	apiKey := "test-key"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+apiKey {
			t.Fatalf("Authorization = %q", got)
		}
		switch r.URL.Path {
		case approvalAPIBasePath:
			if r.Method != http.MethodGet {
				t.Fatalf("list method = %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode([]contracts.ApprovalCeremony{watchTestCeremony("ap-1", time.Unix(1, 0))})
		case approvalAPIBasePath + "/ap-1/approve":
			if r.Method != http.MethodPost {
				t.Fatalf("transition method = %s", r.Method)
			}
			var body struct {
				Actor  string `json:"actor"`
				Reason string `json:"reason"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode transition: %v", err)
			}
			if body.Actor != "operator.cli" || body.Reason == "" {
				t.Fatalf("transition body = %+v", body)
			}
			item := watchTestCeremony("ap-1", time.Unix(1, 0))
			item.State = contracts.ApprovalCeremonyAllowed
			_ = json.NewEncoder(w).Encode(item)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := newApprovalHTTPClient(server.URL, apiKey)
	if err != nil {
		t.Fatalf("newApprovalHTTPClient: %v", err)
	}
	items, err := client.ListApprovals(context.Background())
	if err != nil || len(items) != 1 || items[0].ApprovalID != "ap-1" {
		t.Fatalf("ListApprovals = %+v, %v", items, err)
	}
	transitioned, err := client.TransitionApproval(context.Background(), "ap-1", "approve", "operator.cli", "reviewed")
	if err != nil || transitioned.State != contracts.ApprovalCeremonyAllowed {
		t.Fatalf("TransitionApproval = %+v, %v", transitioned, err)
	}
}

func TestApprovalHTTPClientFailsClosedWithoutKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request must not be sent without an admin key")
	}))
	defer server.Close()

	client, err := newApprovalHTTPClient(server.URL, "")
	if err != nil {
		t.Fatalf("newApprovalHTTPClient: %v", err)
	}
	if _, err := client.ListApprovals(context.Background()); !errors.Is(err, errApprovalAPIKeyMissing) {
		t.Fatalf("ListApprovals error = %v, want missing-key error", err)
	}
}

func TestApprovalHTTPClientRejectsUnsafeInputs(t *testing.T) {
	for _, rawURL := range []string{
		"ftp://example.com",
		"http://",
		"http://example.com",
		"https://key@example.com",
		"https://example.com/?api_key=argv-secret",
	} {
		if _, err := newApprovalHTTPClient(rawURL, "key"); err == nil {
			t.Errorf("newApprovalHTTPClient(%q) unexpectedly succeeded", rawURL)
		} else if strings.Contains(err.Error(), "argv-secret") {
			t.Errorf("URL rejection leaked argv material: %q", err)
		}
	}
	if _, err := newApprovalHTTPClient("https://example.com", "key\nvalue"); err == nil {
		t.Fatal("control-character API key unexpectedly succeeded")
	}

	client, err := newApprovalHTTPClient("http://127.0.0.1:8080", "key")
	if err != nil || client == nil {
		t.Fatalf("loopback HTTP client = %v, %v", client, err)
	}
	if _, err := client.TransitionApproval(context.Background(), "ap-1", "revoke", "operator", ""); err == nil {
		t.Fatal("watch client must not expose revoke")
	}
}

func TestApprovalHTTPClientSanitizesRemoteError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad\x1b[2Jresponse", http.StatusUnauthorized)
	}))
	defer server.Close()
	client, err := newApprovalHTTPClient(server.URL, "key")
	if err != nil {
		t.Fatalf("newApprovalHTTPClient: %v", err)
	}
	_, err = client.ListApprovals(context.Background())
	if err == nil || strings.Contains(err.Error(), "\x1b") || !strings.Contains(err.Error(), "401") {
		t.Fatalf("ListApprovals error = %q", err)
	}
}
