package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestDesktopCodexBridgeContractV1(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "project")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	canonicalWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatalf("resolve workspace: %v", err)
	}
	dataDir := filepath.Join(tmp, "desktop-data")
	configPath := filepath.Join(canonicalWorkspace, ".codex", "config.toml")
	hookPath := filepath.Join(canonicalWorkspace, ".codex", "hooks.json")

	previewArgs := []string{
		"setup", "codex", "--scope", "project", "--workspace", workspace,
		"--data-dir", dataDir, "--no-quickstart", "--json", "--dry-run",
	}
	preview := runDesktopCodexSetupJSON(t, previewArgs)
	assertDesktopCodexSetupSummary(t, preview, "preview", canonicalWorkspace, dataDir, false, false)
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("preview created data dir: %v", err)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("preview created Codex config: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n\n[mcp_servers.other]\ncommand = \"other-mcp\"\nargs = [\"serve\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, []byte("{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"Bash\",\"hooks\":[{\"type\":\"command\",\"command\":\"other-hook\"}]}]}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	applyArgs := []string{
		"setup", "codex", "--scope", "project", "--workspace", workspace,
		"--data-dir", dataDir, "--no-quickstart", "--json", "--yes",
	}
	applied := runDesktopCodexSetupJSON(t, applyArgs)
	assertDesktopCodexSetupSummary(t, applied, "install", canonicalWorkspace, dataDir, true, true)
	if applied.KernelURL != "" || applied.QuickstartStarted {
		t.Fatalf("headless apply advertised a Quickstart server: %#v", applied)
	}
	if got, want := applied.PlannedActions, []string{
		"scan selected workspace and write draft-only inventory artifacts",
		"configure the HELM MCP server with the selected local data directory",
		"configure the HELM PreToolUse hook for supported Codex tools",
	}; !equalSetupStrings(got, want) {
		t.Fatalf("planned actions = %#v, want %#v", got, want)
	}
	var config codexProjectConfig
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read Codex config: %v", err)
	}
	if _, err := toml.Decode(string(raw), &config); err != nil {
		t.Fatalf("decode Codex config: %v\n%s", err, raw)
	}
	server := config.MCPServers[setupMCPServerName]
	if got, want := server.Args, []string{"mcp", "serve", "--transport", "stdio", "--data-dir", dataDir}; !equalSetupStrings(got, want) {
		t.Fatalf("Codex MCP args = %#v, want %#v", got, want)
	}
	if !strings.Contains(string(raw), "[mcp_servers.other]") || !strings.Contains(string(raw), "model = \"gpt-5\"") {
		t.Fatalf("apply did not preserve existing Codex config:\n%s", raw)
	}

	statusArgs := []string{
		"setup", "status", "codex", "--scope", "project", "--workspace", workspace,
		"--data-dir", dataDir, "--no-quickstart", "--json",
	}
	status := runDesktopCodexSetupJSON(t, statusArgs)
	assertDesktopCodexSetupSummary(t, status, "status", canonicalWorkspace, dataDir, true, true)

	removeArgs := []string{
		"setup", "remove", "codex", "--scope", "project", "--workspace", workspace,
		"--data-dir", dataDir, "--no-quickstart", "--json", "--yes",
	}
	removed := runDesktopCodexSetupJSON(t, removeArgs)
	// Remove reports the safely observed pre-removal state so a Desktop client
	// can tell which local integration it actually removed.
	assertDesktopCodexSetupSummary(t, removed, "remove", canonicalWorkspace, dataDir, true, true)
	raw, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read Codex config after remove: %v", err)
	}
	if strings.Contains(string(raw), setupMCPServerName) || !strings.Contains(string(raw), "[mcp_servers.other]") {
		t.Fatalf("remove did not preserve only the unrelated Codex config:\n%s", raw)
	}
	raw, err = os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read hooks after remove: %v", err)
	}
	if strings.Contains(string(raw), "hook pre-tool --client codex") || !strings.Contains(string(raw), "other-hook") {
		t.Fatalf("remove did not preserve only the unrelated Codex hook:\n%s", raw)
	}
}

func TestDesktopCodexBridgeContractV1RequiresExplicitWorkspace(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "setup", "codex", "--scope", "project", "--dry-run", "--json", "--data-dir", filepath.Join(t.TempDir(), "desktop-data"),
	}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "requires an explicit --workspace") {
		t.Fatalf("project setup without workspace code=%d stderr=%s", code, stderr.String())
	}
}

func TestDesktopCodexBridgeContractV1DoesNotMutateWithoutYes(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "project")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(tmp, "desktop-data")

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace,
		"--data-dir", dataDir, "--no-quickstart", "--json",
	}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "pass --yes") {
		t.Fatalf("project setup without --yes code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("setup without --yes created data dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workspace, ".codex", "config.toml")); !os.IsNotExist(err) {
		t.Fatalf("setup without --yes created Codex config: %v", err)
	}
}

func TestDesktopCodexBridgeContractV1RejectsMalformedConfigWithoutOverwrite(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "project")
	configPath := filepath.Join(workspace, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		t.Fatal(err)
	}
	invalid := "[mcp_servers\ncommand = \"broken\"\n"
	if err := os.WriteFile(configPath, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace,
		"--data-dir", filepath.Join(tmp, "desktop-data"), "--no-quickstart", "--yes",
	}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "parse existing Codex config") {
		t.Fatalf("malformed project config code=%d stderr=%s", code, stderr.String())
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read malformed config: %v", err)
	}
	if string(raw) != invalid {
		t.Fatalf("malformed config was overwritten:\n%s", raw)
	}
}

func TestDesktopCodexBridgeContractV1AcceptsServerTransportFlag(t *testing.T) {
	valid := strings.Repeat("a", desktopTransportV1SecretLength)
	t.Setenv(desktopTransportV1EnabledEnv, "1")
	t.Setenv(desktopTransportV1KeyEnv, valid)
	t.Setenv(desktopTransportV1NonceEnv, strings.Repeat("b", desktopTransportV1SecretLength))
	t.Setenv("HELM_HEALTH_PORT", "0")
	t.Setenv("HELM_METRICS_ENABLED", "1")
	t.Setenv("HELM_METRICS_PORT", "")

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "server", "--desktop-transport-v1", "--data-dir", filepath.Join(t.TempDir(), "desktop-data"),
	}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "HELM_METRICS_ENABLED") {
		t.Fatalf("server transport-v1 flag was not accepted before auxiliary-health validation: code=%d stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("server rejected the transport-v1 flag: %s", stderr.String())
	}
}

func TestDesktopCodexBridgeContractV1UsesDesktopMCPDataDir(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "desktop-data")
	if err := serveLocalMCPStdioWithDataDir(strings.NewReader(""), io.Discard, dataDir); err != nil {
		t.Fatalf("start MCP runtime with Desktop data dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "root.key")); err != nil {
		t.Fatalf("Desktop MCP data dir did not receive the signer root key: %v", err)
	}
}

func runDesktopCodexSetupJSON(t *testing.T, args []string) setupSummary {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(append([]string{"helm-ai-kernel"}, args...), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("%q exit=%d stderr=%s stdout=%s", strings.Join(args, " "), code, stderr.String(), stdout.String())
	}
	decoder := json.NewDecoder(&stdout)
	var summary setupSummary
	if err := decoder.Decode(&summary); err != nil {
		t.Fatalf("decode %q JSON: %v\n%s", strings.Join(args, " "), err, stdout.String())
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("%q emitted more than one JSON value: extra=%#v err=%v stdout=%s", strings.Join(args, " "), extra, err, stdout.String())
	}
	return summary
}

func assertDesktopCodexSetupSummary(t *testing.T, summary setupSummary, operation, workspace, dataDir string, mcpInstalled, hookInstalled bool) {
	t.Helper()
	if summary.Operation != operation || summary.Target != "codex" || summary.Scope != "project" || summary.Workspace != workspace || summary.DataDir != dataDir {
		t.Fatalf("unexpected Desktop Codex setup summary: %#v", summary)
	}
	if summary.ClientConfigPath != filepath.Join(workspace, ".codex", "config.toml") || summary.HookConfigPath != filepath.Join(workspace, ".codex", "hooks.json") {
		t.Fatalf("summary did not use the selected project workspace: %#v", summary)
	}
	if summary.MCPInstalled != mcpInstalled || summary.HookInstalled != hookInstalled {
		t.Fatalf("installed state mcp=%t hook=%t, want mcp=%t hook=%t", summary.MCPInstalled, summary.HookInstalled, mcpInstalled, hookInstalled)
	}
}
