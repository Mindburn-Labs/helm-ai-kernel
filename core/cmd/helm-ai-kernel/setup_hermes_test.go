package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSetupHermesWritesFailClosedUserConfig(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "hermes", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup hermes exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	if summary.Target != "hermes" {
		t.Fatalf("target = %q, want hermes", summary.Target)
	}
	wantPath := filepath.Join(home, ".hermes", "config.yaml")
	if summary.ClientConfigPath != wantPath || summary.HookConfigPath != wantPath {
		t.Fatalf("config paths = %q / %q, want %q", summary.ClientConfigPath, summary.HookConfigPath, wantPath)
	}
	if summary.MCPInstalled || !summary.HookInstalled {
		t.Fatalf("install flags mcp=%v hook=%v, want hook-only", summary.MCPInstalled, summary.HookInstalled)
	}

	raw, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read Hermes config: %v", err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatalf("parse Hermes config: %v\n%s", err, raw)
	}
	if _, ok := root["mcp_servers"]; ok {
		t.Fatalf("Hermes hop must not write mcp_servers:\n%s", raw)
	}
	if strings.Contains(string(raw), "hooks_auto_accept") {
		t.Fatalf("setup must not write hooks_auto_accept:\n%s", raw)
	}
	if !strings.Contains(string(raw), "hook pre-tool --client hermes") {
		t.Fatalf("Hermes config missing hook command:\n%s", raw)
	}
	if !strings.Contains(string(raw), "fail_closed: true") {
		t.Fatalf("Hermes config missing fail_closed: true:\n%s", raw)
	}
	if !strings.Contains(string(raw), "timeout: 30") {
		t.Fatalf("Hermes config missing timeout: 30:\n%s", raw)
	}
	if !strings.Contains(string(raw), setupHookMatcher("hermes")) {
		t.Fatalf("Hermes config missing tool matcher:\n%s", raw)
	}
	if hermesMCPInstalled(wantPath, summary.BinaryPath, dataDir) {
		t.Fatalf("Hermes MCP binding must not be written:\n%s", raw)
	}
	command := setupHookCommand(setupOptions{Target: "hermes", DataDir: dataDir}, summary.BinaryPath)
	if !hermesHookInstalled(wantPath, command) {
		t.Fatalf("Hermes hook binding not recognized:\n%s", raw)
	}
}

func TestSetupHermesDryRunOmitsMCP(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "hermes", "--scope", "user", "--dry-run", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("dry-run exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	if summary.MCPInstalled {
		t.Fatal("dry-run must not report MCP as installed")
	}
	for _, action := range summary.PlannedActions {
		if strings.Contains(action, "MCP server") {
			t.Fatalf("Hermes plan must be hook-only: %#v", summary.PlannedActions)
		}
	}
	foundHook := false
	for _, action := range summary.PlannedActions {
		if strings.Contains(action, "pre_tool_call") {
			foundHook = true
			break
		}
	}
	if !foundHook {
		t.Fatalf("Hermes plan missing pre_tool_call hook: %#v", summary.PlannedActions)
	}
}

func TestSetupHermesNextMentionsConsent(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "hermes", "--scope", "user", "--yes", "--no-quickstart", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup hermes exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	out := stdout.String() + stderr.String()
	for _, want := range []string{"--accept-hooks", "HERMES_ACCEPT_HOOKS", "hooks_auto_accept", "Non-TTY"} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup next missing consent cue %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "DENY is visible in the Hermes UI") && !strings.Contains(out, "does not mean DENY is visible") {
		t.Fatalf("must not claim Hermes UI shows DENY:\n%s", out)
	}
}

func TestSetupHermesStatusHookOnlyIsNotDegraded(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "hermes", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup hermes exit=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "status", "hermes", "--scope", "user", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code == 2 {
		t.Fatalf("status hard-failed: stderr=%s stdout=%s", stderr.String(), stdout.String())
	}
	status := decodeSingleSetupSummary(t, &stdout)
	if status.MCPInstalled || !status.HookInstalled {
		t.Fatalf("hook-only status mcp=%v hook=%v", status.MCPInstalled, status.HookInstalled)
	}
	if status.ClientState == "degraded" || status.ClientState == "absent" {
		t.Fatalf("hook-only Hermes must not be degraded for missing MCP: %#v", status)
	}
}

func TestSetupHermesStatusDegradedWhenHookOmitted(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "hermes", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup hermes exit=%d stderr=%s", code, stderr.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	configPath := summary.HookConfigPath
	if err := removeHermesHookConfig(configPath, setupHookCommand(setupOptions{Target: "hermes", DataDir: dataDir}, summary.BinaryPath), ""); err != nil {
		t.Fatalf("omit hook: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "status", "hermes", "--scope", "user", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("status exit=%d, want 1 for a missing hook; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	status := decodeSingleSetupSummary(t, &stdout)
	if status.MCPInstalled || status.HookInstalled {
		t.Fatalf("omitted hook status mcp=%v hook=%v, want both false", status.MCPInstalled, status.HookInstalled)
	}
	if status.ClientState != "absent" {
		t.Fatalf("client_state = %q, want absent", status.ClientState)
	}
	// Omitting the hook is fail-open in Hermes: no pre_tool_call entry means
	// the tool runs and no receipt is written. Status must not report a DENY path.
	if len(hermesInstalledHookCommands(configPath)) > 0 {
		t.Fatal("omitted hook must not be treated as a configured Hermes block")
	}
}

func TestSetupHermesFailClosedFalseIsNotInstalled(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(filepath.Join(home, ".hermes"), 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	bin := filepath.Join(tmp, "helm-ai-kernel")
	dataDir := filepath.Join(tmp, "helm")
	command := setupHookCommand(setupOptions{Target: "hermes", DataDir: dataDir}, bin)
	configPath := filepath.Join(home, ".hermes", "config.yaml")
	raw := []byte("hooks:\n  pre_tool_call:\n    - matcher: " + yamlQuote(setupHookMatcher("hermes")) + "\n      command: " + yamlQuote(command) + "\n      fail_closed: false\n      timeout: 30\n")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if hermesHookInstalled(configPath, command) {
		t.Fatal("fail_closed: false must not count as an installed fail-closed hook")
	}
}

func TestSetupHermesTimeoutRequiredForInstalled(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(filepath.Join(home, ".hermes"), 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	bin := filepath.Join(tmp, "helm-ai-kernel")
	dataDir := filepath.Join(tmp, "helm")
	command := setupHookCommand(setupOptions{Target: "hermes", DataDir: dataDir}, bin)
	configPath := filepath.Join(home, ".hermes", "config.yaml")
	raw := []byte("hooks:\n  pre_tool_call:\n    - matcher: " + yamlQuote(setupHookMatcher("hermes")) + "\n      command: " + yamlQuote(command) + "\n      fail_closed: true\n")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if hermesHookInstalled(configPath, command) {
		t.Fatal("fail_closed without timeout: 30 must not count as installed")
	}
}

func TestSetupHermesRepairRestoresTimeout(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "hermes", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup hermes exit=%d stderr=%s", code, stderr.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	command := setupHookCommand(setupOptions{Target: "hermes", DataDir: dataDir}, summary.BinaryPath)
	configPath := summary.HookConfigPath
	stale := []byte("hooks:\n  pre_tool_call:\n    - matcher: " + yamlQuote(setupHookMatcher("hermes")) + "\n      command: " + yamlQuote(command) + "\n      fail_closed: true\n")
	if err := os.WriteFile(configPath, stale, 0o600); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "repair", "hermes", "--scope", "user", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("repair exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	repaired := decodeSingleSetupSummary(t, &stdout)
	if repaired.MCPInstalled || !repaired.HookInstalled {
		t.Fatalf("repair flags mcp=%v hook=%v, want hook-only", repaired.MCPInstalled, repaired.HookInstalled)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "mcp_servers") {
		t.Fatalf("repair must not write MCP:\n%s", raw)
	}
	if !strings.Contains(string(raw), "timeout: 30") || !strings.Contains(string(raw), "fail_closed: true") {
		t.Fatalf("repair did not restore fail-closed timeout hook:\n%s", raw)
	}
	if !hermesHookInstalled(configPath, command) {
		t.Fatal("repaired hook was not recognized as installed")
	}
}

func TestSetupHermesRemoveClearsOwnedEntriesAndLeftoverMCP(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "hermes", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup hermes exit=%d stderr=%s", code, stderr.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	configPath := filepath.Join(home, ".hermes", "config.yaml")
	if err := upsertHermesMCP(configPath, summary.BinaryPath, dataDir, ""); err != nil {
		t.Fatalf("plant leftover MCP: %v", err)
	}
	if err := os.WriteFile(configPath, appendExistingHermesKey(t, configPath), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "remove", "hermes", "--scope", "user", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("remove hermes exit=%d stderr=%s", code, stderr.String())
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hook pre-tool --client hermes") || strings.Contains(string(raw), setupMCPServerName) {
		t.Fatalf("owned Hermes entries remain:\n%s", raw)
	}
	if !strings.Contains(string(raw), "model: keep-me") {
		t.Fatalf("unrelated Hermes config was lost:\n%s", raw)
	}
}

func TestNormalizeSetupTargetAcceptsHermes(t *testing.T) {
	got, err := normalizeSetupTarget("hermes")
	if err != nil || got != "hermes" {
		t.Fatalf("normalize hermes = %q err=%v", got, err)
	}
	got, err = normalizeSetupTarget("deepseek")
	if err != nil || got != "deepseek" {
		t.Fatalf("normalize deepseek = %q err=%v", got, err)
	}
}

func yamlQuote(value string) string {
	raw, err := yaml.Marshal(value)
	if err != nil {
		return value
	}
	return strings.TrimSpace(string(raw))
}

func appendExistingHermesKey(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	root["model"] = "keep-me"
	out, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
