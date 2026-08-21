package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
)

func TestSetupStatusFleetJSON(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("HELM_DATA_DIR", filepath.Join(home, ".helm-ai-kernel"))
	t.Chdir(root)

	code, stdout, stderr := runCLI(t, "setup", "status", "--format=json")
	if code > 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	var fleet setupFleetStatus
	if err := json.Unmarshal([]byte(stdout), &fleet); err != nil {
		t.Fatalf("fleet JSON: %v\n%s", err, stdout)
	}
	if fleet.Operation != "status" {
		t.Fatalf("operation=%q", fleet.Operation)
	}
	if !strings.Contains(fleet.DataDir, ".helm-ai-kernel") {
		t.Fatalf("data_dir=%q", fleet.DataDir)
	}
	seen := map[string]setupSummary{}
	for _, client := range fleet.Clients {
		seen[client.Target] = client
		if client.Lifecycle == "" || client.ClientState == "" {
			t.Fatalf("%s missing lifecycle/state: %+v", client.Target, client)
		}
	}
	for _, want := range []string{"claude-code", "codex", "hermes", "deepseek", "cursor", "vscode", "windsurf"} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("fleet omitted %s", want)
		}
	}
}

func TestSetupStatusCursorDoesNotClaimLoaded(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.MkdirAll(filepath.Join(root, ".cursor"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".cursor", "mcp.json"), []byte(`{"mcpServers":{"helm-ai-kernel-governance":{"command":"helm-ai-kernel"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runCLI(t, "setup", "status", "cursor", "--format=json")
	if code > 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	var summary setupSummary
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout)
	}
	if summary.NativeLoaded {
		t.Fatal("cursor must not claim native_loaded")
	}
	if !strings.Contains(summary.ClientConfigPath, ".cursor") {
		t.Fatalf("config path=%q", summary.ClientConfigPath)
	}
	if summary.Lifecycle == "active" || summary.ClientState == "native_loaded" {
		t.Fatalf("cursor claimed active load: %+v", summary)
	}
}

func TestSetupStatusWindsurfIsPrintConfigOnly(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	code, stdout, stderr := runCLI(t, "setup", "status", "windsurf", "--format=json")
	if code > 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	var summary setupSummary
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout)
	}
	if summary.NativeLoaded {
		t.Fatal("windsurf must not claim native_loaded")
	}
	if summary.ClientState != "print_config_only" {
		t.Fatalf("windsurf state=%q want print_config_only", summary.ClientState)
	}
	if summary.ClientConfigPath != "" {
		t.Fatalf("windsurf must not invent a path: %q", summary.ClientConfigPath)
	}
}

func TestDoctorSuggestionsAreFailClosed(t *testing.T) {
	if strings.Contains(doctorOnboardingSuggestion, "--yes") {
		t.Fatalf("doctor onboarding still recommends --yes: %q", doctorOnboardingSuggestion)
	}
	if !strings.Contains(doctorOnboardingSuggestion, "setup status") {
		t.Fatalf("doctor onboarding should inspect first: %q", doctorOnboardingSuggestion)
	}
	if strings.Contains(doctorRepairSuggestion, "--yes") {
		t.Fatalf("doctor repair still recommends --yes: %q", doctorRepairSuggestion)
	}
	if !strings.Contains(doctorRepairSuggestion, "--dry-run") {
		t.Fatalf("doctor repair should be --dry-run: %q", doctorRepairSuggestion)
	}
	if strings.Contains(doctorMCPScanSuggestion, "--yes") {
		t.Fatalf("doctor mcp scan still recommends --yes: %q", doctorMCPScanSuggestion)
	}
	if doctorMCPScanSuggestion != "Run: helm-ai-kernel mcp scan" {
		t.Fatalf("doctor mcp scan suggestion drifted: %q", doctorMCPScanSuggestion)
	}
}

func TestCompensateFailedSetupApplyRemovesMCP(t *testing.T) {
	var removed bool
	orig := setupCompensateMCP
	setupCompensateMCP = func(opts setupOptions) error {
		removed = true
		return nil
	}
	t.Cleanup(func() { setupCompensateMCP = orig })

	compensateFailedSetupApply(setupOptions{Target: "claude-code"}, []ui.Step{
		{Title: "configure the HELM MCP server in /tmp/x", Status: ui.StatusPass},
		{Title: "configure the HELM PreToolUse hook in /tmp/y", Status: ui.StatusFail},
	})
	if !removed {
		t.Fatal("MCP+hook failure must compensate by removing MCP")
	}
}
