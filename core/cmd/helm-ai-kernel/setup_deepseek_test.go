package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSetupDeepseekWritesHookFileAndProfileConfigPath(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("DSH_HOME", "")
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
	wantHook := filepath.Join(home, ".dsh", deepseekHookFileName)
	wantProfile := filepath.Join(home, ".dsh", deepseekPatchFileName)
	if summary.HookConfigPath != wantHook {
		t.Fatalf("hook path = %q, want %q", summary.HookConfigPath, wantHook)
	}
	if summary.ClientConfigPath != wantProfile {
		t.Fatalf("profile path = %q, want %q", summary.ClientConfigPath, wantProfile)
	}
	if summary.MCPInstalled || !summary.HookInstalled {
		t.Fatalf("install flags mcp=%v hook=%v, want hook-only", summary.MCPInstalled, summary.HookInstalled)
	}

	hookRaw, err := os.ReadFile(wantHook)
	if err != nil {
		t.Fatalf("read Kernel hook file: %v", err)
	}
	if !strings.Contains(string(hookRaw), "hook pre-tool --client deepseek") {
		t.Fatalf("hook file missing command:\n%s", hookRaw)
	}
	if !strings.Contains(string(hookRaw), setupHookMatcher("deepseek")) {
		t.Fatalf("hook file missing lowercase DSH matcher:\n%s", hookRaw)
	}

	profileRaw, err := os.ReadFile(wantProfile)
	if err != nil {
		t.Fatalf("read DSH profile: %v", err)
	}
	if strings.Contains(string(profileRaw), setupMCPServerName) {
		t.Fatalf("DSH hop must not write MCP:\n%s", profileRaw)
	}
	if !deepseekProfileHasConfigPath(t, wantProfile, wantHook, deepseekClaudeBridgePlugin) {
		t.Fatalf("profile missing Claude-bridge configPath:\n%s", profileRaw)
	}
	if deepseekProfileHasPlugin(t, wantProfile, deepseekCodexBridgePlugin) {
		t.Fatalf("blank profile must not insert Codex bridge (missing package fails DSH boot):\n%s", profileRaw)
	}
	command := setupHookCommand(setupOptions{Target: "deepseek", DataDir: dataDir, Scope: "user"}, summary.BinaryPath)
	if !deepseekHookFileInstalled(wantHook, command) || !deepseekHopInstalled(setupOptions{Target: "deepseek", DataDir: dataDir, Scope: "user"}, summary.BinaryPath) {
		t.Fatalf("deepseek hop not recognized as installed:\nhook=%s\nprofile=%s", hookRaw, profileRaw)
	}
}

func TestSetupDeepseekDryRunOmitsMCPAndMentionsConfigPath(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("DSH_HOME", "")
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
	for _, action := range summary.PlannedActions {
		if strings.Contains(action, "MCP server") {
			t.Fatalf("deepseek plan must be hook-only: %#v", summary.PlannedActions)
		}
	}
	foundHook, foundProfile := false, false
	for _, action := range summary.PlannedActions {
		if strings.Contains(action, "Kernel PreToolUse hook file") {
			foundHook = true
		}
		if strings.Contains(action, "configPath") {
			foundProfile = true
		}
	}
	if !foundHook || !foundProfile {
		t.Fatalf("deepseek plan missing hook file or profile configPath: %#v", summary.PlannedActions)
	}
	if _, err := os.Stat(filepath.Join(home, ".dsh", deepseekHookFileName)); !os.IsNotExist(err) {
		t.Fatalf("dry-run wrote hook file: %v", err)
	}
}

func TestSetupDeepseekNextDoesNotClaimDENYVisible(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("DSH_HOME", "")
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--yes", "--no-quickstart", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup deepseek exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	out := stdout.String() + stderr.String()
	for _, want := range []string{"configPath", "@deepseek-ai/dsh-hooks-claude-code", "fail-opens"} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup next missing caveat %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "DENY is visible in the DSH UI") && !strings.Contains(out, "does not mean DENY is visible") {
		t.Fatalf("must not claim DSH UI shows DENY:\n%s", out)
	}
}

func TestSetupDeepseekStatusHookOnlyIsNotDegraded(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("DSH_HOME", "")
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
		t.Fatalf("hook-only status mcp=%v hook=%v", status.MCPInstalled, status.HookInstalled)
	}
	if status.ClientState == "degraded" || status.ClientState == "absent" {
		t.Fatalf("hook-only DeepSeek must not be degraded for missing MCP: %#v", status)
	}
}

func TestSetupDeepseekStatusNotInstalledWhenProfileOrHookOmitted(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("DSH_HOME", "")
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup deepseek exit=%d stderr=%s", code, stderr.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	hookPath := summary.HookConfigPath
	profilePath := summary.ClientConfigPath
	command := setupHookCommand(setupOptions{Target: "deepseek", DataDir: dataDir, Scope: "user"}, summary.BinaryPath)

	if err := os.Remove(profilePath); err != nil {
		t.Fatal(err)
	}
	if deepseekHopInstalled(setupOptions{Target: "deepseek", DataDir: dataDir, Scope: "user"}, summary.BinaryPath) {
		t.Fatal("hook file without profile configPath must not count as installed")
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "status", "deepseek", "--scope", "user", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("status exit=%d, want 1 for a missing profile mapping; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	status := decodeSingleSetupSummary(t, &stdout)
	if status.HookInstalled {
		t.Fatalf("missing profile must not report hook installed: %#v", status)
	}

	if err := os.WriteFile(profilePath, []byte("- insert:\n  - id: other\n    name: keep-me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeHookConfig(hookPath, command, ""); err != nil {
		t.Fatalf("omit hook: %v", err)
	}
	if deepseekHopInstalled(setupOptions{Target: "deepseek", DataDir: dataDir, Scope: "user"}, summary.BinaryPath) {
		t.Fatal("profile without Kernel hook command must not count as installed")
	}
}

func TestSetupDeepseekRepairRestoresProfileConfigPath(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("DSH_HOME", "")
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup deepseek exit=%d stderr=%s", code, stderr.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	if err := os.WriteFile(summary.ClientConfigPath, []byte("[]\n"), 0o600); err != nil {
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
	if !deepseekProfileHasConfigPath(t, summary.ClientConfigPath, summary.HookConfigPath, deepseekClaudeBridgePlugin) {
		t.Fatal("repair did not restore profile configPath")
	}
}

func TestSetupDeepseekRemoveClearsOwnedRowsAndPreservesOthers(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("DSH_HOME", "")
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup deepseek exit=%d stderr=%s", code, stderr.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	if err := os.WriteFile(summary.ClientConfigPath, appendExistingDeepseekRow(t, summary.ClientConfigPath), 0o600); err != nil {
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
		t.Fatalf("owned hook command remains:\n%s", hookRaw)
	}
	profileRaw, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(profileRaw), deepseekClaudeBridgeID) || strings.Contains(string(profileRaw), deepseekClaudeBridgePlugin) {
		t.Fatalf("owned profile rows remain:\n%s", profileRaw)
	}
	if !strings.Contains(string(profileRaw), "keep-me") {
		t.Fatalf("unrelated DSH patch row was lost:\n%s", profileRaw)
	}
}

func TestSetupDeepseekUpsertsExistingCodexBridgeConfigPath(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	dshHome := filepath.Join(home, ".dsh")
	if err := os.MkdirAll(dshHome, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("DSH_HOME", "")
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")
	profilePath := filepath.Join(dshHome, deepseekPatchFileName)
	if err := os.WriteFile(profilePath, []byte("- insert:\n  - id: hooks-codex\n    name: '@deepseek-ai/dsh-hooks-codex'\n    config:\n      configPath: /old/hooks.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup deepseek exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	if !deepseekProfileHasConfigPath(t, profilePath, summary.HookConfigPath, deepseekCodexBridgePlugin) {
		raw, _ := os.ReadFile(profilePath)
		t.Fatalf("existing Codex bridge was not pointed at Kernel hook file:\n%s", raw)
	}
}

func TestSetupDeepseekProjectScopeIsRejectedAndDefaultCoercesToUser(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("DSH_HOME", "")

	opts, code := parseSetupInstallArgs([]string{"deepseek", "--data-dir", filepath.Join(tmp, "helm")}, bytes.NewBuffer(nil))
	if code != 0 {
		t.Fatalf("default deepseek parse code=%d", code)
	}
	if opts.Scope != "user" {
		t.Fatalf("omitted --scope coerced to %q, want user", opts.Scope)
	}

	var stdout, stderr bytes.Buffer
	code = Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "project", "--yes", "--data-dir", filepath.Join(tmp, "helm")}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "user-scope only") {
		t.Fatalf("project scope exit=%d stderr=%s", code, stderr.String())
	}
}

func TestNormalizeSetupTargetAcceptsDeepseek(t *testing.T) {
	for _, in := range []string{"deepseek", "dsh", "deepseek-harness"} {
		got, err := normalizeSetupTarget(in)
		if err != nil || got != "deepseek" {
			t.Fatalf("normalize %q = %q err=%v", in, got, err)
		}
	}
}

func TestSetupDeepseekHonorsAbsoluteDSHHome(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	dshHome := filepath.Join(tmp, "custom-dsh")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("DSH_HOME", dshHome)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "deepseek", "--scope", "user", "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup deepseek exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	wantHook := filepath.Join(dshHome, deepseekHookFileName)
	wantProfile := filepath.Join(dshHome, deepseekPatchFileName)
	if summary.HookConfigPath != wantHook || summary.ClientConfigPath != wantProfile {
		t.Fatalf("DSH_HOME paths = %q / %q, want %q / %q", summary.HookConfigPath, summary.ClientConfigPath, wantHook, wantProfile)
	}
}

func deepseekProfileHasConfigPath(t *testing.T, profilePath, hookPath, plugin string) bool {
	t.Helper()
	ops, err := readYAMLList(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	want := deepseekCleanHookPath(hookPath)
	for _, op := range ops {
		obj, ok := op.(map[string]any)
		if !ok {
			continue
		}
		for _, item := range arrayValue(obj, "insert") {
			row, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if !sameDeepseekBridgePlugin(yamlString(row["name"]), plugin) {
				continue
			}
			cfg, _ := row["config"].(map[string]any)
			if cfg == nil {
				continue
			}
			if deepseekCleanHookPath(yamlString(cfg["configPath"])) == want {
				return true
			}
		}
	}
	return false
}

func deepseekProfileHasPlugin(t *testing.T, profilePath, plugin string) bool {
	t.Helper()
	ops, err := readYAMLList(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		obj, ok := op.(map[string]any)
		if !ok {
			continue
		}
		for _, item := range arrayValue(obj, "insert") {
			row, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if sameDeepseekBridgePlugin(yamlString(row["name"]), plugin) {
				return true
			}
		}
	}
	return false
}

func appendExistingDeepseekRow(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ops []any
	if err := yaml.Unmarshal(raw, &ops); err != nil {
		t.Fatal(err)
	}
	ops = append(ops, map[string]any{
		"insert": []any{
			map[string]any{"id": "keep-me", "name": "unrelated-plugin"},
		},
	})
	out, err := yaml.Marshal(ops)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
