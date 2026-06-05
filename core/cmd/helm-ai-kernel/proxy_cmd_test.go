package main

import (
	"encoding/json"
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
