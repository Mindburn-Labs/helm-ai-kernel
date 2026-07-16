package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestDemoMCPAlias verifies that `demo mcp` routes to runMCPProof and produces a
// verified MCP governance proof.
func TestDemoMCPAlias(t *testing.T) {
	out := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := runDemoCmd([]string{
		"mcp",
		"--out", out,
		"--run-id", "demo-mcp-test",
		"--at", "2026-01-01T00:00:00Z",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("demo mcp failed with code %d: stderr=%s", code, stderr.String())
	}

	var summary mcpProofSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("demo mcp output is not valid summary JSON: %v\noutput: %s", err, stdout.String())
	}
	if summary.SchemaVersion != "helm.mcp.proof/v4" {
		t.Errorf("unexpected schema version %q", summary.SchemaVersion)
	}
	if !summary.OfflineVerified || !summary.TamperRejected {
		t.Errorf("MCP proof should verify offline and reject tampering")
	}
	if summary.DispatchCount != 1 || !summary.NegativeCasesNoDispatch || !summary.ReplayNoRedispatch {
		t.Errorf("MCP proof should dispatch once, preserve negative no-dispatch, and replay idempotently: %+v", summary)
	}
	if !summary.DurationGatePass || !summary.PreDispatchBypassBlocked || !summary.ProofComplete || summary.ProofScope != "complete" || len(summary.Scenarios) != 8 || len(summary.PreDispatchBypassProbes) != 3 {
		t.Errorf("MCP proof should complete its eight policy cases and three pre-dispatch bypass probes inside the duration gate: %+v", summary)
	}
}

// TestDemoUnknownSubcommand verifies unknown subcommands are still rejected and
// the usage text advertises the mcp alias.
func TestDemoUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runDemoCmd([]string{"bogus"}, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown subcommand should exit 2, got %d", code)
	}

	stderr.Reset()
	if code := runDemoCmd(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("missing subcommand should exit 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "mcp") {
		t.Errorf("usage should advertise the mcp subcommand, got: %s", stderr.String())
	}
}
