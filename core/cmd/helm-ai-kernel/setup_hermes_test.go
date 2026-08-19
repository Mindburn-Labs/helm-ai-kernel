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
	if !summary.MCPInstalled || !summary.HookInstalled {
		t.Fatalf("install flags mcp=%v hook=%v", summary.MCPInstalled, summary.HookInstalled)
	}

	raw, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read Hermes config: %v", err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatalf("parse Hermes config: %v\n%s", err, raw)
	}
	if !strings.Contains(string(raw), "hook pre-tool --client hermes") {
		t.Fatalf("Hermes config missing hook command:\n%s", raw)
	}
	if !strings.Contains(string(raw), "fail_closed: true") {
		t.Fatalf("Hermes config missing fail_closed: true:\n%s", raw)
	}
	if !strings.Contains(string(raw), setupHookMatcher("hermes")) {
		t.Fatalf("Hermes config missing tool matcher:\n%s", raw)
	}
	if !hermesMCPInstalled(wantPath, summary.BinaryPath, dataDir) {
		t.Fatalf("Hermes MCP binding not recognized:\n%s", raw)
	}
	if !hermesHookInstalled(wantPath, setupHookCommand(setupOptions{Target: "hermes", DataDir: dataDir}, summary.BinaryPath)) {
		t.Fatalf("Hermes hook binding not recognized:\n%s", raw)
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
	if !status.MCPInstalled || status.HookInstalled {
		t.Fatalf("omitted hook status mcp=%v hook=%v, want mcp true hook false", status.MCPInstalled, status.HookInstalled)
	}
	if status.ClientState != "degraded" {
		t.Fatalf("client_state = %q, want degraded", status.ClientState)
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
	raw := []byte("hooks:\n  pre_tool_call:\n    - matcher: " + yamlQuote(setupHookMatcher("hermes")) + "\n      command: " + yamlQuote(command) + "\n      fail_closed: false\n")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if hermesHookInstalled(configPath, command) {
		t.Fatal("fail_closed: false must not count as an installed fail-closed hook")
	}
}

func TestSetupHermesRemoveClearsOwnedEntries(t *testing.T) {
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
	configPath := filepath.Join(home, ".hermes", "config.yaml")
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
	if _, err := normalizeSetupTarget("deepseek"); err == nil {
		t.Fatal("deepseek must remain out of scope")
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
