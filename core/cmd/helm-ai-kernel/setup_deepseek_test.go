package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSetupDeepSeekWritesFailClosedUserConfig(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup deepseek exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	if summary.Target != "deepseek" {
		t.Fatalf("target = %q, want deepseek", summary.Target)
	}
	wantHook := filepath.Join(home, ".dsh", "hooks.json")
	wantProfile := filepath.Join(home, ".dsh", "cordis.patch.yml")
	if summary.HookConfigPath != wantHook {
		t.Fatalf("hook path = %q, want %q", summary.HookConfigPath, wantHook)
	}
	if summary.ClientConfigPath != wantProfile {
		t.Fatalf("profile path = %q, want %q", summary.ClientConfigPath, wantProfile)
	}
	if summary.MCPInstalled || !summary.HookInstalled {
		t.Fatalf("install flags mcp=%v hook=%v, want hook-only", summary.MCPInstalled, summary.HookInstalled)
	}

	raw, err := os.ReadFile(wantHook)
	if err != nil {
		t.Fatalf("read DeepSeek hook: %v", err)
	}
	if strings.Contains(string(raw), setupMCPServerName) || strings.Contains(string(raw), "mcpServers") {
		t.Fatalf("DeepSeek hop must not write MCP:\n%s", raw)
	}
	if !strings.Contains(string(raw), "hook pre-tool --client deepseek") {
		t.Fatalf("DeepSeek hook missing command:\n%s", raw)
	}
	if !strings.Contains(string(raw), `"fail_closed": true`) && !strings.Contains(string(raw), `"fail_closed":true`) {
		t.Fatalf("DeepSeek hook missing fail_closed: true:\n%s", raw)
	}
	if !strings.Contains(string(raw), `"timeout": 30`) && !strings.Contains(string(raw), `"timeout":30`) {
		t.Fatalf("DeepSeek hook missing timeout: 30:\n%s", raw)
	}
	if !strings.Contains(string(raw), setupHookMatcher("deepseek")) {
		t.Fatalf("DeepSeek hook missing lowercase tool matcher:\n%s", raw)
	}
	command := setupHookCommand(setupOptions{Target: "deepseek", DataDir: dataDir}, summary.BinaryPath)
	if !deepseekHookInstalled(wantHook, command) {
		t.Fatalf("DeepSeek hook binding not recognized:\n%s", raw)
	}

	profileRaw, err := os.ReadFile(wantProfile)
	if err != nil {
		t.Fatalf("read DeepSeek profile: %v", err)
	}
	if !strings.Contains(string(profileRaw), "configPath") {
		t.Fatalf("DSH profile missing configPath:\n%s", profileRaw)
	}
	if !strings.Contains(string(profileRaw), deepseekHooksPluginName) {
		t.Fatalf("DSH profile must use the stock hook bridge %q:\n%s", deepseekHooksPluginName, profileRaw)
	}
	for _, banned := range []string{"helm-ai-kernel-hooks", "dsh-hooks-helm", "helm-native", "agent_class"} {
		if strings.Contains(string(profileRaw), banned) {
			t.Fatalf("profile must not invent a HELM plugin or agent class %q:\n%s", banned, profileRaw)
		}
	}
	absHook, err := filepath.Abs(wantHook)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(profileRaw), absHook) {
		t.Fatalf("DSH profile configPath must point at the hook file %q:\n%s", absHook, profileRaw)
	}
	if !deepseekProfileInstalled(wantProfile, wantHook) {
		t.Fatalf("DSH profile binding not recognized:\n%s", profileRaw)
	}
}

func TestSetupDeepSeekDryRunIsHookAndProfileOnly(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--dry-run", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("dry-run exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	if summary.MCPInstalled {
		t.Fatal("dry-run must not report MCP as installed")
	}
	foundHook := false
	foundProfile := false
	for _, action := range summary.PlannedActions {
		if strings.Contains(action, "MCP server") {
			t.Fatalf("DeepSeek plan must be hook+profile only: %#v", summary.PlannedActions)
		}
		if strings.Contains(action, "PreToolUse") {
			foundHook = true
		}
		if strings.Contains(action, "configPath") {
			foundProfile = true
		}
	}
	if !foundHook {
		t.Fatalf("DeepSeek plan missing PreToolUse hook: %#v", summary.PlannedActions)
	}
	if !foundProfile {
		t.Fatalf("DeepSeek plan missing profile configPath: %#v", summary.PlannedActions)
	}
}

func TestSetupDeepSeekNextDoesNotClaimDSHWebDeny(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--yes", "--no-quickstart", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup deepseek exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	out := stdout.String() + stderr.String()
	for _, want := range []string{"configPath", "hook file dead"} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup next missing honesty cue %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "`npx @deepseek-ai/dsh web` sees DENY") && !strings.Contains(out, "does not mean") {
		t.Fatalf("must not claim dsh web sees DENY:\n%s", out)
	}
}

func TestSetupDeepSeekStatusHookAndProfileIsNotDegraded(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup deepseek exit=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "status", "deepseek", "--scope", "user", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code == 2 {
		t.Fatalf("status hard-failed: stderr=%s stdout=%s", stderr.String(), stdout.String())
	}
	status := decodeSingleSetupSummary(t, &stdout)
	if status.MCPInstalled || !status.HookInstalled {
		t.Fatalf("hook+profile status mcp=%v hook=%v", status.MCPInstalled, status.HookInstalled)
	}
	if status.ClientState == "degraded" || status.ClientState == "absent" {
		t.Fatalf("hook+profile DeepSeek must not be degraded for missing MCP: %#v", status)
	}
}

func TestSetupDeepSeekStatusDegradedWhenHookOmitted(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup deepseek exit=%d stderr=%s", code, stderr.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	hookPath := summary.HookConfigPath
	if err := removeDeepSeekHookConfig(hookPath, setupHookCommand(setupOptions{Target: "deepseek", DataDir: dataDir}, summary.BinaryPath), ""); err != nil {
		t.Fatalf("omit hook: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "status", "deepseek", "--scope", "user", "--json", "--data-dir", dataDir}, &stdout, &stderr)
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
	if len(deepseekInstalledHookCommands(hookPath)) > 0 {
		t.Fatal("omitted hook must not be treated as a configured DeepSeek block")
	}
}

func TestSetupDeepSeekMissingConfigPathIsNotInstalled(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(filepath.Join(home, ".dsh"), 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	bin := filepath.Join(tmp, "helm-ai-kernel")
	dataDir := filepath.Join(tmp, "helm")
	command := setupHookCommand(setupOptions{Target: "deepseek", DataDir: dataDir}, bin)
	hookPath := filepath.Join(home, ".dsh", "hooks.json")
	profilePath := filepath.Join(home, ".dsh", "cordis.patch.yml")
	if err := writeDeepSeekHookFixture(hookPath, command, true, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, []byte("- dsh-hooks-claude-code: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if deepseekProfileInstalled(profilePath, hookPath) {
		t.Fatal("empty configPath must not count as an installed DSH profile")
	}
	opts := setupOptions{Target: "deepseek", Scope: "user", DataDir: dataDir}
	if setupHookInstalled(opts, hookPath, bin) {
		t.Fatal("hook file without profile configPath must not count as installed")
	}
}

func TestSetupDeepSeekFailClosedFalseIsNotInstalled(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(filepath.Join(home, ".dsh"), 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	bin := filepath.Join(tmp, "helm-ai-kernel")
	dataDir := filepath.Join(tmp, "helm")
	command := setupHookCommand(setupOptions{Target: "deepseek", DataDir: dataDir}, bin)
	hookPath := filepath.Join(home, ".dsh", "hooks.json")
	if err := writeDeepSeekHookFixture(hookPath, command, false, true); err != nil {
		t.Fatal(err)
	}
	if deepseekHookInstalled(hookPath, command) {
		t.Fatal("fail_closed: false must not count as an installed fail-closed hook")
	}
}

func TestSetupDeepSeekTimeoutRequiredForInstalled(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(filepath.Join(home, ".dsh"), 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	bin := filepath.Join(tmp, "helm-ai-kernel")
	dataDir := filepath.Join(tmp, "helm")
	command := setupHookCommand(setupOptions{Target: "deepseek", DataDir: dataDir}, bin)
	hookPath := filepath.Join(home, ".dsh", "hooks.json")
	if err := writeDeepSeekHookFixture(hookPath, command, true, false); err != nil {
		t.Fatal(err)
	}
	if deepseekHookInstalled(hookPath, command) {
		t.Fatal("fail_closed without timeout: 30 must not count as installed")
	}
}

func TestSetupDeepSeekRepairRestoresTimeoutAndConfigPath(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup deepseek exit=%d stderr=%s", code, stderr.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	command := setupHookCommand(setupOptions{Target: "deepseek", DataDir: dataDir}, summary.BinaryPath)
	hookPath := summary.HookConfigPath
	profilePath := summary.ClientConfigPath
	if err := writeDeepSeekHookFixture(hookPath, command, true, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, []byte("- dsh-hooks-claude-code: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "repair", "deepseek", "--scope", "user", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("repair exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	repaired := decodeSingleSetupSummary(t, &stdout)
	if repaired.MCPInstalled || !repaired.HookInstalled {
		t.Fatalf("repair flags mcp=%v hook=%v, want hook-only", repaired.MCPInstalled, repaired.HookInstalled)
	}
	raw, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), setupMCPServerName) {
		t.Fatalf("repair must not write MCP:\n%s", raw)
	}
	if !deepseekHookInstalled(hookPath, command) {
		t.Fatalf("repair did not restore fail-closed timeout hook:\n%s", raw)
	}
	profileRaw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	if !deepseekProfileInstalled(profilePath, hookPath) {
		t.Fatalf("repair did not restore profile configPath:\n%s", profileRaw)
	}
}

func TestSetupDeepSeekRemoveClearsOwnedEntriesAndKeepsUnrelated(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup deepseek exit=%d stderr=%s", code, stderr.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	if err := appendUnrelatedDeepSeekProfile(t, summary.ClientConfigPath); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "remove", "deepseek", "--scope", "user", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("remove deepseek exit=%d stderr=%s", code, stderr.String())
	}
	hookRaw, err := os.ReadFile(summary.HookConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hookRaw), "hook pre-tool --client deepseek") {
		t.Fatalf("owned DeepSeek hook remains:\n%s", hookRaw)
	}
	profileRaw, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(profileRaw), "dsh-hooks-claude-code") {
		t.Fatalf("owned DeepSeek profile remains:\n%s", profileRaw)
	}
	if !strings.Contains(string(profileRaw), "keep-me-plugin") {
		t.Fatalf("unrelated DSH profile entry was lost:\n%s", profileRaw)
	}
}

func TestNormalizeSetupTargetAcceptsDeepSeek(t *testing.T) {
	got, err := normalizeSetupTarget("deepseek")
	if err != nil || got != "deepseek" {
		t.Fatalf("normalize deepseek = %q err=%v", got, err)
	}
}

func TestSetupDeepSeekProfileIsStockBridgeNotHelmPlugin(t *testing.T) {
	entry := deepseekProfileEntry("/abs/hooks.json")
	if yamlString(entry["id"]) != deepseekHooksPluginID || yamlString(entry["name"]) != deepseekHooksPluginName {
		t.Fatalf("stock bridge identity = %#v", entry)
	}
	if _, ok := entry[deepseekHooksPluginShort]; ok {
		t.Fatal("canonical write uses the stock id/name form, not a HELM shorthand plugin")
	}
	for key := range entry {
		if strings.Contains(key, "helm") {
			t.Fatalf("profile key %q invents a HELM plugin", key)
		}
	}
	if deepseekProfileConfigPath(entry) != deepseekAbsPath("/abs/hooks.json") {
		t.Fatalf("configPath = %q", deepseekProfileConfigPath(entry))
	}
	shorthand := map[string]any{deepseekHooksPluginShort: map[string]any{"configPath": "/abs/hooks.json"}}
	if !deepseekProfileEntryOwned(shorthand) || !deepseekProfileEntryOwned(map[string]any{
		"id":   deepseekHooksPluginAltID,
		"name": deepseekHooksPluginName,
		"config": map[string]any{
			"configPath": "/abs/hooks.json",
		},
	}) {
		t.Fatal("stock claude-code / hooks-cc aliases must still count as owned")
	}
	codex := map[string]any{
		"id":   "hooks-codex",
		"name": "@deepseek-ai/dsh-hooks-codex",
		"config": map[string]any{
			"configPath": "/abs/hooks.json",
		},
	}
	if deepseekProfileEntryOwned(codex) {
		t.Fatal("stock Codex bridge is not this hop; do not overwrite a user's Codex configPath")
	}
}

func writeDeepSeekHookFixture(path, command string, failClosed, withTimeout bool) error {
	hook := map[string]any{
		"type":        "command",
		"command":     command,
		"fail_closed": failClosed,
	}
	if withTimeout {
		hook["timeout"] = deepseekHookTimeoutSeconds
	}
	root := map[string]any{
		"hooks": map[string]any{
			deepseekHookEvent: []any{
				map[string]any{
					"matcher": setupHookMatcher("deepseek"),
					"hooks":   []any{hook},
				},
			},
		},
	}
	raw, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func appendUnrelatedDeepSeekProfile(t *testing.T, path string) error {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var entries []any
	if err := yaml.Unmarshal(raw, &entries); err != nil {
		return err
	}
	entries = append(entries, map[string]any{
		"keep-me-plugin": map[string]any{"enabled": true},
	})
	out, err := yaml.Marshal(entries)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}
