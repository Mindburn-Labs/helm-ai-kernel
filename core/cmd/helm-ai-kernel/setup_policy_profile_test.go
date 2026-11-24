package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func TestSetupRejectsInvalidCustomPolicyBeforeWritingConfig(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	policy := filepath.Join(tmp, "invalid-policy.json")
	if err := os.WriteFile(policy, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--yes", "--no-quickstart", "--data-dir", dataDir, "--policy-profile", policy}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("invalid custom policy setup exit = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "policy profile") {
		t.Fatalf("invalid custom policy diagnostic = %s", stderr.String())
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("invalid custom policy created data state: %v", err)
	}
	for _, path := range []string{filepath.Join(home, ".codex", "config.toml"), filepath.Join(home, ".codex", "hooks.json")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("invalid custom policy wrote config %s: %v", path, err)
		}
	}
}

func TestSetupRejectsUnexpectedCustomPolicyBeforeWritingConfig(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	policy := filepath.Join(tmp, "unexpected-policy.json")
	if err := os.WriteFile(policy, []byte(`{"id":"workstation.other.v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--yes", "--no-quickstart", "--data-dir", dataDir, "--policy-profile", policy}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "policy profile") {
		t.Fatalf("unexpected custom policy setup exit = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("unexpected custom policy created data state: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "config.toml")); !os.IsNotExist(err) {
		t.Fatalf("unexpected custom policy wrote config: %v", err)
	}
}

func TestSetupStatusRequiresExactCustomPolicyDigest(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	fixture := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	profileBytes, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(tmp, "observe_draft.v1.allow.json")
	if err := os.WriteFile(profile, profileBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	_, approvedDigest, err := workstation.LoadPolicyProfileFileWithDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	opts := setupOptions{
		Target:              "codex",
		Scope:               "user",
		DataDir:             filepath.Join(tmp, "helm"),
		PolicyProfile:       profile,
		PolicyProfileSHA256: "sha256:stale",
	}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(summary.HookConfigPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := upsertHookConfig(summary.HookConfigPath, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), ""); err != nil {
		t.Fatalf("write stale hook config: %v", err)
	}

	statusArgs := []string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "user", "--no-quickstart", "--json", "--data-dir", opts.DataDir}
	assertHookInstalled := func(want bool) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := Run(statusArgs, &stdout, &stderr); code != 1 {
			t.Fatalf("status exit = %d, want 1 because MCP is absent; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
		}
		status := decodeSingleSetupSummary(t, &stdout)
		if status.HookInstalled != want {
			t.Fatalf("status hook installed = %v, want %v; summary=%#v", status.HookInstalled, want, status)
		}
	}
	assertHookInstalled(false)

	opts.PolicyProfileSHA256 = approvedDigest
	if err := upsertHookConfig(summary.HookConfigPath, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), ""); err != nil {
		t.Fatalf("reapprove hook config: %v", err)
	}
	assertHookInstalled(true)

	if err := os.WriteFile(profile, append(profileBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	assertHookInstalled(false)
}

func TestSetupStatusCustomPolicyDiscoveryFailsClosed(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", filepath.Join(tmp, "home"))
	profile := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	opts := setupOptions{Target: "codex", Scope: "user", DataDir: filepath.Join(tmp, "helm")}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	base := setupHookCommand(opts, summary.BinaryPath)
	validProfile := base + " --policy-profile " + shellQuote(profile) + " --policy-profile-sha256 sha256:approved"

	for _, test := range []struct {
		name    string
		command string
	}{
		{name: "missing digest", command: base + " --policy-profile " + shellQuote(profile)},
		{name: "missing profile", command: base + " --policy-profile-sha256 sha256:approved"},
		{name: "dynamic profile", command: base + " --policy-profile \"$PROFILE\" --policy-profile-sha256 sha256:approved"},
		{name: "ambiguous profile", command: validProfile + " --policy-profile " + shellQuote(profile)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Remove(summary.HookConfigPath); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if err := upsertHookConfig(summary.HookConfigPath, setupHookMatcher(opts.Target), test.command, ""); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "user", "--no-quickstart", "--json", "--data-dir", opts.DataDir}, &stdout, &stderr)
			if code != 2 || !strings.Contains(stderr.String(), "policy profile") {
				t.Fatalf("status code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestSetupRepairPinsCustomPolicyProfileDigest(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")
	profile := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	args := []string{"helm-ai-kernel", "setup", "repair", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--json", "--data-dir", dataDir, "--policy-profile", profile}
	var stdout, stderr bytes.Buffer
	if code := Run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("repair exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	summary, err := buildSetupSummary(setupOptions{Target: "codex", Scope: "project", Workspace: workspace, DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	hook, err := os.ReadFile(summary.HookConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := hookPolicyProfileDigest(t, profile)
	for _, want := range []string{"--policy-profile " + shellQuote(profile), "--policy-profile-sha256 " + shellQuote(digest)} {
		if !strings.Contains(string(hook), want) {
			t.Fatalf("repaired hook is missing %q:\n%s", want, hook)
		}
	}
}

func TestSetupRepairPreservesDiscoveredCustomPolicyProfile(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")
	profile := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	installed := setupOptions{
		Target:              "codex",
		Scope:               "project",
		Workspace:           workspace,
		DataDir:             dataDir,
		PolicyProfile:       profile,
		PolicyProfileSHA256: hookPolicyProfileDigest(t, profile),
	}
	summary, err := buildSetupSummary(installed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(summary.HookConfigPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := upsertHookConfig(summary.HookConfigPath, setupHookMatcher(installed.Target), setupHookCommand(installed, summary.BinaryPath), ""); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(summary.HookConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"helm-ai-kernel", "setup", "repair", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--json", "--data-dir", dataDir}
	var stdout, stderr bytes.Buffer
	if code := Run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("repair exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	after, err := os.ReadFile(summary.HookConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) || !strings.Contains(string(after), "--policy-profile "+shellQuote(profile)) || !strings.Contains(string(after), "--policy-profile-sha256 "+shellQuote(installed.PolicyProfileSHA256)) {
		t.Fatalf("plain repair rewrote installed custom policy:\n%s", after)
	}
}

func TestSetupRemoveDiscoversCustomPolicyProfile(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(tmp, "helm")
	profile := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	installed := setupOptions{
		Target:              "codex",
		Scope:               "project",
		Workspace:           workspace,
		DataDir:             dataDir,
		PolicyProfile:       profile,
		PolicyProfileSHA256: hookPolicyProfileDigest(t, profile),
	}
	summary, err := buildSetupSummary(installed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(summary.HookConfigPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := upsertHookConfig(summary.HookConfigPath, setupHookMatcher(installed.Target), setupHookCommand(installed, summary.BinaryPath), setupPrivateFileRoot(installed)); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--json", "--data-dir", dataDir}
	if code := Run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("remove exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	raw, err := os.ReadFile(summary.HookConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hook pre-tool --client codex") {
		t.Fatalf("plain remove retained custom policy hook:\n%s", raw)
	}
}
