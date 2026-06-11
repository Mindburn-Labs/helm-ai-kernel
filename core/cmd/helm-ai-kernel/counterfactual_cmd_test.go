package main

import (
	"bytes"
	"strings"
	"testing"
)

const cfFixtureJSONL = `{"receipt_id":"cf-1","enforcement":"counterfactual","would_have_verdict":"DENY","reason_code":"APPROVAL_REQUIRED","observe_grant_id":"og-1","boundary_record_id":"b-1","boundary_record_hash":"sha256:a","policy_epoch":"epoch-42","tool_name":"deploy","mcp_server_id":"srv-1","args_hash":"sha256:x","created_at":"2026-06-11T12:00:00Z"}
{"receipt_id":"cf-2","enforcement":"counterfactual","would_have_verdict":"ESCALATE","reason_code":"APPROVAL_REQUIRED","observe_grant_id":"og-1","boundary_record_id":"b-2","boundary_record_hash":"sha256:b","policy_epoch":"epoch-42","tool_name":"delete","mcp_server_id":"srv-2","args_hash":"sha256:y","created_at":"2026-06-11T12:01:00Z"}
{"receipt_id":"cf-3","enforcement":"counterfactual","would_have_verdict":"ALLOW","observe_grant_id":"og-1","boundary_record_id":"b-3","boundary_record_hash":"sha256:c","policy_epoch":"epoch-42","tool_name":"read","mcp_server_id":"srv-1","args_hash":"sha256:z","created_at":"2026-06-11T12:02:00Z"}`

func TestCounterfactualSummaryDeterministicJSON(t *testing.T) {
	var out1, out2, errBuf bytes.Buffer

	receipts1, err := loadCounterfactualReceipts(strings.NewReader(cfFixtureJSONL))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(receipts1) != 3 {
		t.Fatalf("expected 3 receipts, got %d", len(receipts1))
	}

	runOnce := func(out *bytes.Buffer) int {
		errBuf.Reset()
		return runCounterfactualSummaryFromReader(strings.NewReader(cfFixtureJSONL), out, &errBuf, true)
	}
	code1 := runOnce(&out1)
	code2 := runOnce(&out2)
	if code1 != 1 || code2 != 1 {
		t.Fatalf("exit code = %d/%d, want 1 (blocks found)", code1, code2)
	}
	if out1.String() != out2.String() {
		t.Fatalf("summary not deterministic:\n%s\n---\n%s", out1.String(), out2.String())
	}
	if !strings.Contains(out1.String(), "\"would_deny\": 1") {
		t.Fatalf("expected would_deny=1 in JSON:\n%s", out1.String())
	}
	if !strings.Contains(out1.String(), "\"would_escalate\": 1") {
		t.Fatalf("expected would_escalate=1 in JSON:\n%s", out1.String())
	}
}

func TestCounterfactualSummaryRejectsEnforcedReceipt(t *testing.T) {
	enforced := `{"receipt_id":"cf-bad","enforcement":"enforced","would_have_verdict":"DENY","reason_code":"APPROVAL_REQUIRED","observe_grant_id":"og-1","boundary_record_id":"b-1","boundary_record_hash":"sha256:a","policy_epoch":"epoch-42","created_at":"2026-06-11T12:00:00Z"}`
	if _, err := loadCounterfactualReceipts(strings.NewReader(enforced)); err == nil {
		t.Fatal("P0 VIOLATION: loader accepted an enforced receipt into the counterfactual stream")
	}
}

func TestCounterfactualSummaryNoBlocksExitZero(t *testing.T) {
	allowOnly := `{"receipt_id":"cf-a","enforcement":"counterfactual","would_have_verdict":"ALLOW","observe_grant_id":"og-1","boundary_record_id":"b-1","boundary_record_hash":"sha256:a","policy_epoch":"epoch-42","tool_name":"read","mcp_server_id":"srv-1","created_at":"2026-06-11T12:00:00Z"}`
	var out, errBuf bytes.Buffer
	code := runCounterfactualSummaryFromReader(strings.NewReader(allowOnly), &out, &errBuf, false)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (no blocks)", code)
	}
	if !strings.Contains(out.String(), "No would-have blocks") {
		t.Fatalf("expected no-blocks message:\n%s", out.String())
	}
}
