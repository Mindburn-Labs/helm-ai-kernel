package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/tui"
)

func TestMCPScanJSONShapeAndFailOn(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", filepath.Join(dir, "home"))
	cfg := filepath.Join(dir, ".mcp.json")
	if err := os.WriteFile(cfg, []byte(`{
  "mcpServers": {
    "githb": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
    "pinned": {"command": "npx", "args": ["-y", "ok"], "sha256": "abc123"}
  }
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runCLI(t, "mcp", "scan", "--path", cfg, "--format=json")
	if code != 0 {
		t.Fatalf("scan without --fail-on should exit 0, code=%d stderr=%s", code, stderr)
	}
	if strings.Contains(stdout+stderr, "Serving") || strings.Contains(stdout+stderr, "Listen") {
		t.Fatalf("scan started a server:\n%s\n%s", stdout, stderr)
	}
	var report mcpScanV1Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout)
	}
	if report.Schema != mcpScanSchema {
		t.Fatalf("schema=%q", report.Schema)
	}
	if report.Authorizes {
		t.Fatal("scan must not authorize")
	}
	if report.ServersScanned != 2 {
		t.Fatalf("servers_scanned=%d", report.ServersScanned)
	}
	kinds := map[string]int{}
	for _, f := range report.Findings {
		kinds[f.Kind]++
	}
	if kinds["missing_hash"] == 0 {
		t.Fatalf("expected missing_hash finding: %s", stdout)
	}
	if kinds["shadowed_name"] == 0 {
		t.Fatalf("expected shadowed_name finding: %s", stdout)
	}

	failCode, _, failErr := runCLI(t, "mcp", "scan", "--path", cfg, "--fail-on", "medium", "--format=json")
	if failCode != 1 {
		t.Fatalf("--fail-on medium code=%d stderr=%s", failCode, failErr)
	}
}

func TestMCPScanUnknownFormatExit2(t *testing.T) {
	code, stdout, stderr := runCLI(t, "mcp", "scan", "--format=yaml")
	if code != 2 {
		t.Fatalf("code=%d", code)
	}
	assertCleanStdout(t, stdout)
	if !strings.Contains(stderr, "expected text|json") {
		t.Fatalf("stderr=%q", stderr)
	}
}

func TestMCPScanNeverStartsListener(t *testing.T) {
	if tui.IsListenerVerb("mcp", []string{"scan"}) {
		t.Fatal("mcp scan must not be a listener")
	}
	if tui.IsListenerVerb("mcp", tui.DefaultArgs("mcp")) {
		t.Fatal("palette default mcp scan must not be a listener")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", filepath.Join(dir, "home"))
	code, stdout, stderr := runCLI(t, "mcp", "scan", "--format=json")
	if code > 1 {
		t.Fatalf("empty local scan code=%d stderr=%s", code, stderr)
	}
	out := stdout + stderr
	if strings.Contains(out, addr) || strings.Contains(strings.ToLower(out), "listening") {
		t.Fatalf("scan bound a listener:\n%s", out)
	}
}

func TestMCPScanDoesNotWriteRegistry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dir)
	t.Chdir(dir)
	manifest := filepath.Join(dir, "tools.json")
	if err := os.WriteFile(manifest, []byte(`{"server_id":"scan-only","tools":[{"name":"echo","description":"say hi"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before := newLocalSurfaceRegistry().ListMCPServers()
	code, _, stderr := runCLI(t, "mcp", "scan", "--manifest", manifest, "--format=json")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	after := newLocalSurfaceRegistry().ListMCPServers()
	if len(after) != len(before) {
		t.Fatalf("scan mutated registry: before=%d after=%d", len(before), len(after))
	}
}

func TestMCPApproveFailsClosed(t *testing.T) {
	code, stdout, stderr := runCLI(t, "mcp", "approve", "--server-id", "anything", "--json")
	if code == 0 {
		t.Fatal("mcp approve must not succeed")
	}
	if strings.Contains(strings.ToLower(stdout+stderr), `"state":"approved"`) ||
		strings.Contains(strings.ToLower(stdout+stderr), "dispatch_ready\":true") {
		t.Fatalf("mcp approve faked success:\n%s\n%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "unavailable") && !strings.Contains(stderr, "MCP approval") {
		t.Fatalf("expected unavailable error: %q", stderr)
	}
}
