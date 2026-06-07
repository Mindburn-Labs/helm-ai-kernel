package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyStatusBlocksBody(t *testing.T) {
	for _, status := range []string{"DENIED", "PEP_VALIDATION_FAILED", "GOVERNANCE_ERROR", "PROXY_ITERATION_LIMIT", "PROXY_WALLCLOCK_LIMIT"} {
		if !proxyStatusBlocksBody(status) {
			t.Fatalf("status %s should block proxy body", status)
		}
	}
	if proxyStatusBlocksBody("APPROVED") {
		t.Fatal("APPROVED should not block proxy body")
	}
}

func TestDeniedProxyResponseBodyRemovesExecutableToolCalls(t *testing.T) {
	body := deniedProxyResponseBody("DENIED", "NO_POLICY_DEFINED", []string{"file_write"}, "corr-1")
	if strings.Contains(string(body), "tool_calls") {
		t.Fatalf("denied proxy body leaked executable tool_calls: %s", body)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	errPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("denied proxy body missing error object: %+v", payload)
	}
	if errPayload["type"] != "helm_governance_denied" || errPayload["code"] != "NO_POLICY_DEFINED" {
		t.Fatalf("unexpected denied proxy error: %+v", errPayload)
	}
	helmPayload, ok := payload["helm"].(map[string]any)
	if !ok {
		t.Fatalf("denied proxy body missing helm object: %+v", payload)
	}
	if helmPayload["status"] != "DENIED" || helmPayload["correlation_id"] != "corr-1" {
		t.Fatalf("unexpected helm block metadata: %+v", helmPayload)
	}
}

func TestContainDeniedProxyResponseReplacesExecutableBody(t *testing.T) {
	resp := &http.Response{Header: make(http.Header), StatusCode: http.StatusOK, Status: "200 OK"}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", "999")

	body := containDeniedProxyResponse(resp, "PROXY_WALLCLOCK_LIMIT", "PROXY_WALLCLOCK_LIMIT", []string{"file_write"}, "corr-2")
	if resp.StatusCode != http.StatusForbidden || resp.Status != "403 Forbidden" {
		t.Fatalf("denied response status not rewritten: %d %s", resp.StatusCode, resp.Status)
	}
	if resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("Content-Length") != "" {
		t.Fatalf("denied response headers not contained: %+v", resp.Header)
	}
	if strings.Contains(string(body), "tool_calls") {
		t.Fatalf("denied response leaked executable tool call body: %s", body)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["error"] == nil || payload["helm"] == nil {
		t.Fatalf("denied body missing structured error metadata: %+v", payload)
	}
}

func TestReceiptStoreRecoversCausalStateAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")

	store, err := newReceiptStore(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Append(&proxyReceipt{
		ReceiptID:    "r1",
		Timestamp:    "2026-01-01T00:00:00Z",
		Upstream:     "https://api.example.test",
		InputHash:    "sha256:input1",
		OutputHash:   "sha256:output1",
		Status:       "APPROVED",
		LamportClock: 1,
	}); err != nil {
		t.Fatalf("append first receipt: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}

	recovered, err := newReceiptStore(path)
	if err != nil {
		t.Fatalf("recover store: %v", err)
	}
	if recovered.LastLamport() != 1 {
		t.Fatalf("recovered lamport = %d, want 1", recovered.LastLamport())
	}
	if err := recovered.Append(&proxyReceipt{
		ReceiptID:    "r2",
		Timestamp:    "2026-01-01T00:00:01Z",
		Upstream:     "https://api.example.test",
		InputHash:    "sha256:input2",
		OutputHash:   "sha256:output2",
		Status:       "APPROVED",
		LamportClock: recovered.LastLamport() + 1,
	}); err != nil {
		t.Fatalf("append second receipt: %v", err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatalf("close recovered store: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read receipts: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("receipt line count = %d, want 2: %s", len(lines), data)
	}
	var second proxyReceipt
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("unmarshal second receipt: %v", err)
	}
	firstHash := sha256.Sum256([]byte(lines[0]))
	wantPrev := "sha256:" + hex.EncodeToString(firstHash[:])
	if second.PrevHash != wantPrev {
		t.Fatalf("second prev_hash = %q, want %q", second.PrevHash, wantPrev)
	}
	if second.LamportClock != 2 {
		t.Fatalf("second lamport = %d, want 2", second.LamportClock)
	}
}

func TestReceiptStoreRejectsBrokenExistingChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	broken := strings.Join([]string{
		`{"receipt_id":"r1","timestamp":"2026-01-01T00:00:00Z","upstream":"https://api.example.test","input_hash":"sha256:input1","output_hash":"sha256:output1","status":"APPROVED","lamport_clock":1,"prev_hash":"GENESIS"}`,
		`{"receipt_id":"r2","timestamp":"2026-01-01T00:00:01Z","upstream":"https://api.example.test","input_hash":"sha256:input2","output_hash":"sha256:output2","status":"APPROVED","lamport_clock":1,"prev_hash":"GENESIS"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatalf("write broken receipts: %v", err)
	}

	store, err := newReceiptStore(path)
	if err == nil {
		_ = store.Close()
		t.Fatal("expected broken receipt chain to be rejected")
	}
	if !strings.Contains(err.Error(), "prev_hash") {
		t.Fatalf("expected prev_hash chain error, got %v", err)
	}
}
