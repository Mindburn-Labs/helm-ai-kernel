package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupDryRunJSONSummary(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", filepath.Join(tmp, "home"))
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Chdir(workspace)
	stubSetupSideEffects(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "claude-code", "--dry-run", "--json", "--data-dir", filepath.Join(tmp, "helm")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup dry-run exit = %d stderr = %s", code, stderr.String())
	}
	var summary setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("summary JSON: %v\n%s", err, stdout.String())
	}
	if summary.Target != "claude-code" {
		t.Fatalf("target = %q, want claude-code", summary.Target)
	}
	canonicalWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Scope != "project" || summary.Workspace != canonicalWorkspace {
		t.Fatalf("default setup scope/workspace = %q/%q, want project/%q", summary.Scope, summary.Workspace, canonicalWorkspace)
	}
	if summary.DataDir != filepath.Join(tmp, "helm") {
		t.Fatalf("data dir = %q", summary.DataDir)
	}
	if !strings.Contains(summary.UninstallCommand, "setup remove claude-code") {
		t.Fatalf("uninstall command missing setup remove: %s", summary.UninstallCommand)
	}
	if _, err := os.Stat(summary.DataDir); !os.IsNotExist(err) {
		t.Fatalf("dry-run should not create data dir, stat err = %v", err)
	}
}

func TestSetupPreviewWithoutClientKeepsPreflightAndWritesNothing(t *testing.T) {
	for _, target := range []string{"claude-code", "codex", "hermes", "deepseek"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			workspace := filepath.Join(root, "workspace")
			for _, dir := range []string{home, workspace} {
				if err := os.Mkdir(dir, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			t.Setenv("PATH", filepath.Join(root, "no-clients"))
			t.Chdir(workspace)
			dataDir := filepath.Join(root, "state")
			args := []string{"helm-ai-kernel", "setup", target, "--dry-run", "--json", "--data-dir", dataDir}
			if target == "hermes" || target == "deepseek" {
				args = append(args, "--scope", "user")
			}
			var stdout, stderr bytes.Buffer
			if code := Run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("preview without client exited %d: %s", code, stderr.String())
			}
			var summary setupSummary
			if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
				t.Fatal(err)
			}
			if summary.Operation != "preview" || summary.ClientDetected || summary.NativeLoaded || summary.HookInstalled || summary.MCPInstalled {
				t.Fatalf("preview claimed installed client: %+v", summary)
			}
			for _, path := range []string{dataDir, summary.ClientConfigPath, summary.HookConfigPath} {
				if path == "" {
					continue
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("preview wrote %s: %v", path, err)
				}
			}
			// A missing client must not skip validation of existing signing material.
			seed := filepath.Join(root, "invalid-seed")
			if err := os.WriteFile(seed, []byte("invalid"), 0o600); err != nil {
				t.Fatal(err)
			}
			stdout.Reset()
			stderr.Reset()
			if code := Run(append(args, "--signing-seed-file", seed), &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "validate local receipt signing key") {
				t.Fatalf("invalid signing material accepted: %d %s", code, stderr.String())
			}
		})
	}
}

func TestSetupPreflightMissingClientLeavesNoArtifacts(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	state := stubSetupSideEffects(t)
	oldFindClient := setupFindClient
	setupFindClient = func(string) (string, error) {
		return "", os.ErrNotExist
	}
	t.Cleanup(func() { setupFindClient = oldFindClient })

	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "client is not available on PATH") {
		t.Fatalf("missing client setup=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, path := range []string{
		dataDir,
		filepath.Join(workspace, ".codex", "config.toml"),
		filepath.Join(workspace, ".codex", "hooks.json"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("preflight created %s: %v", path, err)
		}
	}
	if len(state.execCalls) != 0 || len(state.quickstartArgs) != 0 || state.probeCalls != 0 {
		t.Fatalf("missing-client preflight had side effects: %#v", state)
	}
}

func TestSetupSignerPreflightLeavesNoArtifacts(t *testing.T) {
	for _, test := range []struct {
		name       string
		prepare    func(t *testing.T, tmp string) []string
		wantStderr string
	}{
		{
			name: "invalid_explicit_seed",
			prepare: func(t *testing.T, tmp string) []string {
				t.Helper()
				seedFile := filepath.Join(tmp, "invalid.seed")
				if err := os.WriteFile(seedFile, []byte("not-a-seed\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return []string{"--signing-seed-file", seedFile}
			},
			wantStderr: "signing seed must be hex",
		},
		{
			name: "production_without_explicit_seed",
			prepare: func(t *testing.T, _ string) []string {
				t.Helper()
				t.Setenv("HELM_PRODUCTION", "true")
				return nil
			},
			wantStderr: "requires --signing-seed-file",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tmp := t.TempDir()
			workspace := filepath.Join(tmp, "workspace")
			if err := os.MkdirAll(workspace, 0o750); err != nil {
				t.Fatal(err)
			}
			state := stubSetupSideEffects(t)
			dataDir := filepath.Join(tmp, "helm")
			args := []string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--data-dir", dataDir}
			args = append(args, test.prepare(t, tmp)...)
			var stdout, stderr bytes.Buffer
			code := Run(args, &stdout, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), test.wantStderr) {
				t.Fatalf("signer preflight=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			for _, path := range []string{
				dataDir,
				filepath.Join(workspace, ".codex", "config.toml"),
				filepath.Join(workspace, ".codex", "hooks.json"),
			} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("signer preflight created %s: %v", path, err)
				}
			}
			if len(state.execCalls) != 0 || len(state.quickstartArgs) != 0 || state.probeCalls != 0 {
				t.Fatalf("signer preflight had side effects: %#v", state)
			}
		})
	}
}

func TestSetupDryRunHasNoFilesystemOrProcessEffects(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	state := stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "claude-code", "--scope", "project", "--workspace", workspace, "--dry-run", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("dry-run exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, path := range []string{
		dataDir,
		filepath.Join(workspace, ".mcp.json"),
		filepath.Join(workspace, ".claude", "settings.json"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("dry-run created %s: %v", path, err)
		}
	}
	if len(state.execCalls) != 0 || len(state.quickstartArgs) != 0 || state.probeCalls != 0 {
		t.Fatalf("dry-run had process side effects: %#v", state)
	}
}

func TestSetupStatusSeparatesConfiguredFromNativeLoaded(t *testing.T) {
	for _, test := range []struct {
		name   string
		target string
		scope  string
	}{
		{name: "claude_project", target: "claude-code", scope: "project"},
		{name: "codex_user", target: "codex", scope: "user"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tmp := t.TempDir()
			home := filepath.Join(tmp, "home")
			t.Setenv("HOME", home)
			workspace := filepath.Join(tmp, "workspace")
			if err := os.MkdirAll(workspace, 0o750); err != nil {
				t.Fatal(err)
			}
			state := stubSetupSideEffects(t)
			dataDir := filepath.Join(tmp, "helm")
			opts := setupOptions{Target: test.target, Scope: test.scope, Workspace: workspace, DataDir: dataDir}
			summary, err := buildSetupSummary(opts)
			if err != nil {
				t.Fatal(err)
			}
			writeSetupMCPTestConfig(t, test.target, summary.ClientConfigPath, summary.BinaryPath, dataDir)
			if err := upsertHookConfig(summary.HookConfigPath, setupHookMatcher(test.target), setupHookCommand(opts, summary.BinaryPath), setupPrivateFileRoot(opts)); err != nil {
				t.Fatal(err)
			}

			args := []string{"helm-ai-kernel", "setup", "status", test.target, "--scope", test.scope, "--json", "--data-dir", dataDir}
			if test.scope == "project" {
				args = append(args, "--workspace", workspace)
			}
			var stdout, stderr bytes.Buffer
			if code := Run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("status exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			got := decodeSingleSetupSummary(t, &stdout)
			if !got.MCPInstalled || !got.HookInstalled || !got.ClientDetected || !got.NativeLoaded || got.ClientState != "native_loaded" {
				t.Fatalf("status did not record configured/native activation separately: %#v", got)
			}
			if state.probeCalls != 1 {
				t.Fatalf("native inspection calls=%d, want 1", state.probeCalls)
			}
		})
	}
}

func TestSetupStatusReportsConfiguredClientMissing(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	state := stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", Workspace: workspace, DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	writeSetupMCPTestConfig(t, "codex", summary.ClientConfigPath, summary.BinaryPath, dataDir)
	if err := upsertHookConfig(summary.HookConfigPath, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), setupPrivateFileRoot(opts)); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(tmp, "home")
	markCodexProjectTrusted(t, home, workspace)
	t.Setenv("HOME", home)
	oldFindClient := setupFindClient
	setupFindClient = func(string) (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { setupFindClient = oldFindClient })

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--workspace", workspace, "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("status exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	got := decodeSingleSetupSummary(t, &stdout)
	if !got.MCPInstalled || !got.HookInstalled || got.ClientDetected || got.NativeLoaded || got.ClientState != "configured_client_missing" {
		t.Fatalf("status did not distinguish a missing client from configured files: %#v", got)
	}
	if state.probeCalls != 0 {
		t.Fatalf("missing client status ran a native probe: %d", state.probeCalls)
	}
}

func TestSetupJSONSummaryMatchesOperation(t *testing.T) {
	tests := []struct {
		name            string
		wantCode        int
		wantOp          string
		wantActions     []string
		wantActionCount int
		wantURL         bool
	}{
		{
			name:            "preview",
			wantCode:        0,
			wantOp:          "preview",
			wantActionCount: 4,
			wantURL:         false,
		},
		{name: "install", wantCode: 0, wantOp: "install", wantActions: []string{}},
		{name: "status", wantCode: 1, wantOp: "status", wantActions: []string{}},
		{
			name:        "preview_remove",
			wantCode:    0,
			wantOp:      "preview_remove",
			wantActions: []string{},
		},
		{name: "remove", wantCode: 0, wantOp: "remove", wantActions: []string{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmp := t.TempDir()
			workspace := filepath.Join(tmp, "workspace")
			if err := os.MkdirAll(workspace, 0o750); err != nil {
				t.Fatal(err)
			}
			stubSetupSideEffects(t)
			dataDir := filepath.Join(tmp, "helm")
			base := []string{"--scope", "project", "--workspace", workspace, "--json", "--data-dir", dataDir}
			var args []string
			switch test.name {
			case "preview":
				args = append([]string{"helm-ai-kernel", "setup", "codex"}, append(base, "--dry-run")...)
			case "install":
				args = append([]string{"helm-ai-kernel", "setup", "codex"}, append(base, "--yes", "--no-quickstart")...)
			case "status":
				args = append([]string{"helm-ai-kernel", "setup", "status", "codex"}, base...)
			case "preview_remove":
				args = append([]string{"helm-ai-kernel", "setup", "remove", "codex"}, append(base, "--dry-run")...)
			case "remove":
				args = append([]string{"helm-ai-kernel", "setup", "remove", "codex"}, append(base, "--yes")...)
			}

			var stdout, stderr bytes.Buffer
			if code := Run(args, &stdout, &stderr); code != test.wantCode {
				t.Fatalf("%s exit = %d, want %d; stderr=%s stdout=%s", test.name, code, test.wantCode, stderr.String(), stdout.String())
			}
			summary := decodeSingleSetupSummary(t, &stdout)
			if summary.Operation != test.wantOp {
				t.Fatalf("operation = %q, want %q", summary.Operation, test.wantOp)
			}
			if test.wantActionCount > 0 && len(summary.PlannedActions) != test.wantActionCount {
				t.Fatalf("planned action count = %d, want %d: %#v", len(summary.PlannedActions), test.wantActionCount, summary.PlannedActions)
			}
			if test.wantActionCount == 0 && !equalSetupStrings(summary.PlannedActions, test.wantActions) {
				t.Fatalf("planned actions = %#v, want %#v", summary.PlannedActions, test.wantActions)
			}
			if summary.QuickstartStarted {
				t.Fatal("pre-launch summary reported Quickstart as started")
			}
			if (summary.KernelURL != "") != test.wantURL {
				t.Fatalf("kernel URL = %q, want present=%v", summary.KernelURL, test.wantURL)
			}
		})
	}
}
