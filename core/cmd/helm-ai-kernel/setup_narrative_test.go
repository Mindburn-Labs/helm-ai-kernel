package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSetupNarrativeShowsResolvedStepsAndCompletion pins pack 2: a successful
// non-JSON install renders a resolved timeline (every step PASS) and a
// completion card whose next action is "restart … to activate governance", not
// the old `mcp=true hook=true` line and not a repair prescription.
func TestSetupNarrativeShowsResolvedStepsAndCompletion(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	stubSetupSideEffects(t)
	restoreSetupSigners(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--no-quickstart", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("install exit=%d stderr=%s", code, stderr.String())
	}
	chrome := stderr.String()
	if !strings.Contains(chrome, "PASS") {
		t.Fatalf("timeline shows no resolved PASS step:\n%s", chrome)
	}
	if strings.Contains(chrome, "mcp=true hook=true") {
		t.Fatalf("still emits the raw boolean status line:\n%s", chrome)
	}
	if !strings.Contains(chrome, "Setup complete") || !strings.Contains(chrome, "activate governance") {
		t.Fatalf("no completion card with an activation next-step:\n%s", chrome)
	}
	if strings.Contains(chrome, "setup repair codex") {
		t.Fatalf("healthy install must not prescribe repair:\n%s", chrome)
	}
}

// TestSetupNarrativeReportsPartialFailureInPlace pins the fail-closed adaptation
// of Neon criterion 4: a failure mid-install marks the failed step FAIL and the
// later steps as not attempted, names the residue, keeps the recovery marker,
// and still fails closed — it does not silently abort, and it does not blindly
// continue past a failed prerequisite.
func TestSetupNarrativeReportsPartialFailureInPlace(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	stubSetupSideEffects(t)
	restoreSetupSigners(t)
	dataDir := filepath.Join(tmp, "helm")

	oldHook := setupInstallHook
	t.Cleanup(func() { setupInstallHook = oldHook })
	setupInstallHook = func(setupOptions, string) error { return errors.New("hook write denied") }

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--no-quickstart", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("failed install exit=%d, want 1; stderr=%s", code, stderr.String())
	}
	chrome := stderr.String()
	if !strings.Contains(chrome, "FAIL") {
		t.Fatalf("failed step not marked FAIL:\n%s", chrome)
	}
	if !strings.Contains(chrome, "Setup did not complete") {
		t.Fatalf("no failure completion card:\n%s", chrome)
	}
	// The MCP server config was written before the hook failed; the residue must
	// be named so the user knows the firewall is half-configured.
	if !strings.Contains(chrome, "MCP server config") || !strings.Contains(chrome, "NOT fully active") {
		t.Fatalf("residue not named:\n%s", chrome)
	}
	// Still fails closed: the recovery marker remains.
	opts := setupOptions{Target: "codex", Scope: "project", Workspace: workspace, DataDir: dataDir}
	if _, err := os.Stat(setupRecoveryMarkerPath(opts)); err != nil {
		t.Fatalf("recovery marker missing after partial failure: %v", err)
	}
}

func restoreSetupSigners(t *testing.T) {
	t.Helper()
	oldResolve := setupResolveSigningSeed
	oldAutoconfigure := setupRunAutoconfigure
	t.Cleanup(func() {
		setupResolveSigningSeed = oldResolve
		setupRunAutoconfigure = oldAutoconfigure
	})
	setupResolveSigningSeed = func(string, string, string) ([]byte, error) { return make([]byte, 32), nil }
	setupRunAutoconfigure = func(dir, _ string) (string, string, error) {
		return "not_run", filepath.Join(dir, "autoconfigure", "policy.draft.json"), nil
	}
}
