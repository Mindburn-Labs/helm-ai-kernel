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
	if summary.SchemaVersion != "helm.mcp.proof/v1" {
		t.Errorf("unexpected schema version %q", summary.SchemaVersion)
	}
	if !summary.OfflineVerified {
		t.Errorf("MCP proof EvidencePack should verify offline")
	}
	if len(summary.Scenarios) == 0 {
		t.Errorf("MCP proof should run at least one scenario")
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
