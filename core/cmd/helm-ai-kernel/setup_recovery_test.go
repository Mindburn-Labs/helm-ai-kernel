package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupRepairAndRemoveAreIdempotent(t *testing.T) {
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

	repair := []string{"helm-ai-kernel", "setup", "repair", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--json", "--data-dir", dataDir}
	var stdout, stderr bytes.Buffer
	if code := Run(repair, &stdout, &stderr); code != 0 {
		t.Fatalf("first repair exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	first := decodeSingleSetupSummary(t, &stdout)
	if !first.MCPInstalled || !first.HookInstalled {
		t.Fatalf("repair did not restore the missing HELM hook: %#v", first)
	}
	hookPath := summary.HookConfigPath
	hookAfterFirst, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run(repair, &stdout, &stderr); code != 0 {
		t.Fatalf("second repair exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if got, err := os.ReadFile(hookPath); err != nil || !bytes.Equal(got, hookAfterFirst) {
		t.Fatalf("idempotent repair changed hook config: %v\n%s", err, got)
	}
	if len(state.execCalls) != 0 {
		t.Fatalf("project repair should not invoke a client process: %#v", state.execCalls)
	}

	remove := []string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--json", "--data-dir", dataDir}
	stdout.Reset()
	stderr.Reset()
	if code := Run(remove, &stdout, &stderr); code != 0 {
		t.Fatalf("first remove exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	removed := decodeSingleSetupSummary(t, &stdout)
	if removed.MCPInstalled || removed.HookInstalled || !removed.RetainedData {
		t.Fatalf("remove summary=%#v", removed)
	}
	configAfterFirst, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	hookAfterRemove, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run(remove, &stdout, &stderr); code != 0 {
		t.Fatalf("second remove exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if got, err := os.ReadFile(summary.ClientConfigPath); err != nil || !bytes.Equal(got, configAfterFirst) {
		t.Fatalf("idempotent remove changed MCP config: %v\n%s", err, got)
	}
	if got, err := os.ReadFile(hookPath); err != nil || !bytes.Equal(got, hookAfterRemove) {
		t.Fatalf("idempotent remove changed hook config: %v\n%s", err, got)
	}
}

func TestSetupInstallFailureRequiresRepair(t *testing.T) {
	for _, test := range []struct {
		name         string
		failureStage string
		customPolicy bool
	}{
		{name: "signing key", failureStage: "signing key"},
		{name: "autoconfigure", failureStage: "autoconfigure"},
		{name: "MCP", failureStage: "MCP"},
		{name: "hook", failureStage: "hook", customPolicy: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			tmp := t.TempDir()
			workspace := filepath.Join(tmp, "workspace")
			if err := os.MkdirAll(workspace, 0o750); err != nil {
				t.Fatal(err)
			}
			stubSetupSideEffects(t)
			dataDir := filepath.Join(tmp, "helm")
			profile := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")

			oldResolve := setupResolveSigningSeed
			oldAutoconfigure := setupRunAutoconfigure
			oldMCP := setupInstallMCP
			oldHook := setupInstallHook
			t.Cleanup(func() {
				setupResolveSigningSeed = oldResolve
				setupRunAutoconfigure = oldAutoconfigure
				setupInstallMCP = oldMCP
				setupInstallHook = oldHook
			})

			resolve := func(string, string, string) ([]byte, error) { return make([]byte, 32), nil }
			autoconfigure := func(dir, _ string) (string, string, error) {
				return "not_run", filepath.Join(dir, "autoconfigure", "policy.draft.json"), nil
			}
			setupResolveSigningSeed = resolve
			setupRunAutoconfigure = autoconfigure
			switch test.failureStage {
			case "signing key":
				setupResolveSigningSeed = func(string, string, string) ([]byte, error) { return nil, errors.New("signing key failed") }
			case "autoconfigure":
				setupRunAutoconfigure = func(string, string) (string, string, error) { return "", "", errors.New("autoconfigure failed") }
			case "MCP":
				setupInstallMCP = func(setupOptions, string) error { return errors.New("MCP failed") }
			case "hook":
				setupInstallHook = func(opts setupOptions, bin string) error {
					if err := oldHook(opts, bin); err != nil {
						return err
					}
					return errors.New("hook failed after writing config")
				}
			}

			install := []string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}
			if test.customPolicy {
				install = append(install, "--policy-profile", profile)
			}
			var stdout, stderr bytes.Buffer
			if code := Run(install, &stdout, &stderr); code != 1 {
				t.Fatalf("setup exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), "recovery required") {
				t.Fatalf("setup did not explain recovery:\n%s", stderr.String())
			}
			opts := setupOptions{Target: "codex", Scope: "project", Workspace: workspace, DataDir: dataDir}
			markerPath := setupRecoveryMarkerPath(opts)
			if _, err := os.Stat(markerPath); err != nil {
				t.Fatalf("recovery marker missing: %v", err)
			}

			stdout.Reset()
			stderr.Reset()
			status := []string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--workspace", workspace, "--json", "--data-dir", dataDir}
			if code := Run(status, &stdout, &stderr); code != 1 {
				t.Fatalf("status exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			pending := decodeSingleSetupSummary(t, &stdout)
			if !pending.RecoveryRequired || pending.ClientState != "recovery_required" || !strings.Contains(pending.RecoveryCommand, "setup repair codex") {
				t.Fatalf("pending setup status=%#v", pending)
			}
			if test.customPolicy && !pending.HookInstalled {
				t.Fatalf("recovery status lost the installed custom-policy hook: %#v", pending)
			}

			setupResolveSigningSeed = resolve
			setupRunAutoconfigure = autoconfigure
			setupInstallMCP = oldMCP
			setupInstallHook = oldHook
			stdout.Reset()
			stderr.Reset()
			repair := []string{"helm-ai-kernel", "setup", "repair", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--json", "--data-dir", dataDir}
			if code := Run(repair, &stdout, &stderr); code != 0 {
				t.Fatalf("repair exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			repaired := decodeSingleSetupSummary(t, &stdout)
			if repaired.RecoveryRequired || !repaired.MCPInstalled || !repaired.HookInstalled {
				t.Fatalf("repaired setup status=%#v", repaired)
			}
			if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
				t.Fatalf("recovery marker still exists: %v", err)
			}
			if test.customPolicy {
				summary, err := buildSetupSummary(opts)
				if err != nil {
					t.Fatal(err)
				}
				hook, err := os.ReadFile(summary.HookConfigPath)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(hook), "--policy-profile "+shellQuote(profile)) {
					t.Fatalf("recovery lost custom policy profile:\n%s", hook)
				}
			}
		})
	}
}

func TestSetupRepairRejectsDifferentPendingSetup(t *testing.T) {
	tmp := t.TempDir()
	firstWorkspace := filepath.Join(tmp, "first")
	secondWorkspace := filepath.Join(tmp, "second")
	for _, dir := range []string{firstWorkspace, secondWorkspace} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	dataDir := filepath.Join(tmp, "helm")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	pending := setupOptions{Target: "codex", Scope: "project", Workspace: firstWorkspace, DataDir: dataDir}
	if err := beginSetupRecovery(pending); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "repair", "claude-code", "--scope", "project", "--workspace", secondWorkspace, "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "belongs to a different setup") {
		t.Fatalf("mismatched repair exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(setupRecoveryMarkerPath(pending)); err != nil {
		t.Fatalf("mismatched repair changed recovery marker: %v", err)
	}
}

func TestSetupRecoveryMarkerRejectsInvalidState(t *testing.T) {
	opts := setupOptions{DataDir: t.TempDir()}
	if err := os.WriteFile(setupRecoveryMarkerPath(opts), []byte(`{"version":1,"target":"unknown","scope":"project","workspace":"/workspace"}\n`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, pending, err := readSetupRecoveryMarker(opts); err == nil || pending {
		t.Fatalf("invalid marker pending=%t err=%v", pending, err)
	}
}
