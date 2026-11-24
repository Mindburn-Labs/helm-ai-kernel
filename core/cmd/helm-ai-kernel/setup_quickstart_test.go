package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestSetupQuickstartFrontDoorPreviewsBeforeYesAndForwardsConsole(t *testing.T) {
	original := setupRunFirstRun
	t.Cleanup(func() { setupRunFirstRun = original })
	var calls [][]string
	setupRunFirstRun = func(args []string, _, _ io.Writer) int {
		calls = append(calls, append([]string(nil), args...))
		return 0
	}

	dataDir := t.TempDir()
	base := []string{"helm-ai-kernel", "setup", "--quickstart", "--profile", "codex", "--data-dir", dataDir, "--console", "--console-port", "0", "--no-open"}
	var stdout, stderr bytes.Buffer
	if code := Run(base, &stdout, &stderr); code != 2 {
		t.Fatalf("unconfirmed quickstart exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	wantPreview := []string{"--profile", "codex", "--data-dir", dataDir, "--console", "--console-port", "0", "--no-open", "--dry-run"}
	if len(calls) != 1 || !reflect.DeepEqual(calls[0], wantPreview) {
		t.Fatalf("preview calls=%#v, want %#v", calls, wantPreview)
	}
	if !strings.Contains(stderr.String(), "no changes made") {
		t.Fatalf("missing confirmation guidance: %s", stderr.String())
	}

	calls = nil
	stdout.Reset()
	stderr.Reset()
	if code := Run(append(base, "--yes", "--json"), &stdout, &stderr); code != 0 {
		t.Fatalf("confirmed quickstart exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	wantStart := []string{"--profile", "codex", "--data-dir", dataDir, "--console", "--console-port", "0", "--no-open", "--yes", "--json"}
	if len(calls) != 1 || !reflect.DeepEqual(calls[0], wantStart) {
		t.Fatalf("start calls=%#v, want %#v", calls, wantStart)
	}
}

func TestSetupQuickstartResetPreviewIsAuthorizedAndRerunPreservesOptions(t *testing.T) {
	original := setupRunFirstRun
	t.Cleanup(func() { setupRunFirstRun = original })
	var calls [][]string
	setupRunFirstRun = func(args []string, _, _ io.Writer) int {
		calls = append(calls, append([]string(nil), args...))
		return 0
	}

	dataDir := filepath.Join(t.TempDir(), "helm state")
	args := []string{
		"helm-ai-kernel", "setup", "--quickstart", "--profile", "claude-code", "--data-dir", dataDir,
		"--console", "--console-port", "0", "--no-open", "--offline", "--reset", "--json",
	}
	var stdout, stderr bytes.Buffer
	if code := Run(args, &stdout, &stderr); code != 2 {
		t.Fatalf("unconfirmed reset preview exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	wantPreview := []string{
		"--profile", "claude", "--data-dir", dataDir,
		"--console", "--console-port", "0", "--no-open", "--offline", "--reset", "--yes", "--dry-run",
	}
	if len(calls) != 1 || !reflect.DeepEqual(calls[0], wantPreview) {
		t.Fatalf("reset preview calls=%#v, want %#v", calls, wantPreview)
	}
	wantRerun := "helm-ai-kernel setup --quickstart --profile 'claude' --data-dir " + shellQuote(dataDir) + " --console --console-port '0' --no-open --offline --reset --yes --json"
	if !strings.Contains(stderr.String(), wantRerun) {
		t.Fatalf("rerun guidance=%q, want command %q", stderr.String(), wantRerun)
	}

	calls = nil
	stdout.Reset()
	stderr.Reset()
	if code := Run(append(args, "--dry-run"), &stdout, &stderr); code != 0 {
		t.Fatalf("explicit reset preview exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	wantDryRunPreview := append(append([]string(nil), wantPreview...), "--json")
	if len(calls) != 1 || !reflect.DeepEqual(calls[0], wantDryRunPreview) {
		t.Fatalf("explicit reset preview calls=%#v, want %#v", calls, wantDryRunPreview)
	}
}

func TestSetupQuickstartDryRunForwardsJSON(t *testing.T) {
	original := setupRunFirstRun
	t.Cleanup(func() { setupRunFirstRun = original })
	var calls [][]string
	setupRunFirstRun = func(args []string, _, _ io.Writer) int {
		calls = append(calls, append([]string(nil), args...))
		return 0
	}

	if code := Run([]string{"helm-ai-kernel", "setup", "--quickstart", "--profile", "codex", "--dry-run", "--json"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("setup quickstart preview exit=%d", code)
	}
	want := []string{"--profile", "codex", "--data-dir", defaultQuickstartDataDir(), "--dry-run", "--json"}
	if len(calls) != 1 || !reflect.DeepEqual(calls[0], want) {
		t.Fatalf("preview calls=%#v, want %#v", calls, want)
	}
}

func TestSetupQuickstartResetPreviewReachesQuickstartWithoutMutation(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := writeQuickstartOwnershipMarker(dataDir); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dataDir, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "--quickstart", "--reset", "--offline", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stdout.String(), `"operation":"preview"`) || !strings.Contains(stderr.String(), "no changes made") {
		t.Fatalf("reset preview exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("reset preview mutated state: %v", err)
	}
}

func TestQuickstartPreviewPreflightsExistingDirectoryAcrossEntryPoints(t *testing.T) {
	original := setupRunFirstRun
	setupRunFirstRun = runQuickstartCmd
	t.Cleanup(func() { setupRunFirstRun = original })

	dataDir := filepath.Join(t.TempDir(), "foreign-state")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dataDir, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	var directStdout, directStderr bytes.Buffer
	directCode := runQuickstartCmd([]string{"--dry-run", "--offline", "--data-dir", dataDir}, &directStdout, &directStderr)
	var setupStdout, setupStderr bytes.Buffer
	setupCode := Run([]string{"helm-ai-kernel", "setup", "--quickstart", "--dry-run", "--offline", "--data-dir", dataDir}, &setupStdout, &setupStderr)

	if directCode != 1 || setupCode != directCode {
		t.Fatalf("preview codes direct=%d setup=%d direct stderr=%q setup stderr=%q", directCode, setupCode, directStderr.String(), setupStderr.String())
	}
	if directStdout.Len() != 0 || setupStdout.Len() != 0 || directStderr.String() != setupStderr.String() || !strings.Contains(directStderr.String(), "without a valid HELM quickstart ownership marker") {
		t.Fatalf("preview mismatch direct stdout=%q stderr=%q setup stdout=%q stderr=%q", directStdout.String(), directStderr.String(), setupStdout.String(), setupStderr.String())
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("foreign preview mutated state: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, quickstartOwnershipMarker)); !os.IsNotExist(err) {
		t.Fatalf("foreign preview created ownership marker: %v", err)
	}
}

func TestSetupInstallQuickstartForwardsConsoleIntent(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	state := stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace,
		"--yes", "--quickstart", "--console", "--console-port", "0", "--no-open", "--json", "--data-dir", dataDir,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	want := []string{
		"--profile", "codex", "--data-dir", filepath.Join(dataDir, "quickstart"),
		"--console", "--console-port", "0", "--no-open",
	}
	if !reflect.DeepEqual(state.quickstartArgs, want) {
		t.Fatalf("quickstart args=%#v, want %#v", state.quickstartArgs, want)
	}
}

func TestSetupDefaultDoesNotStartQuickstart(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	state := stubSetupSideEffects(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--json", "--data-dir", filepath.Join(tmp, "helm")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("default setup exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	if summary.QuickstartStarted || summary.KernelURL != "" || len(state.quickstartArgs) != 0 {
		t.Fatalf("default setup unexpectedly started Quickstart: summary=%#v calls=%#v", summary, state.quickstartArgs)
	}
}

func TestSetupInstallClaudeWritesHookAndRunsExplicitQuickstart(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	restore := stubSetupSideEffects(t)

	var stdout, stderr bytes.Buffer
	dataDir := filepath.Join(tmp, "helm")
	code := Run([]string{"helm-ai-kernel", "setup", "claude-code", "--scope", "user", "--yes", "--quickstart", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	if len(restore.execCalls) != 1 || !strings.Contains(strings.Join(restore.execCalls[0], " "), "claude mcp add") {
		t.Fatalf("exec calls = %#v, want claude mcp add", restore.execCalls)
	}
	if strings.Join(restore.quickstartArgs, " ") != "--profile claude --data-dir "+filepath.Join(dataDir, "quickstart") {
		t.Fatalf("quickstart args = %#v", restore.quickstartArgs)
	}
	hookPath := filepath.Join(home, ".claude", "settings.json")
	raw, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read hook config: %v", err)
	}
	if !strings.Contains(string(raw), "hook pre-tool --client claude-code") {
		t.Fatalf("hook config missing command:\n%s", string(raw))
	}
	if _, err := os.Stat(filepath.Join(dataDir, "autoconfigure", "policy.draft.json")); err != nil {
		t.Fatalf("policy draft missing: %v", err)
	}
}

func TestSetupInstallJSONKeepsQuickstartOutputOffStdout(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	stubSetupSideEffects(t)

	var stdout, stderr bytes.Buffer
	dataDir := filepath.Join(tmp, "helm")
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	dec := json.NewDecoder(&stdout)
	var summary setupSummary
	if err := dec.Decode(&summary); err != nil {
		t.Fatalf("summary JSON: %v\n%s", err, stdout.String())
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("stdout should contain only one JSON value, extra=%#v err=%v stdout=%s", extra, err, stdout.String())
	}
	if !strings.Contains(stderr.String(), "quickstart ready") {
		t.Fatalf("quickstart output should move to stderr in JSON mode, stderr=%s", stderr.String())
	}
	if !summary.QuickstartStarted || summary.KernelURL == "" {
		t.Fatalf("successful Quickstart summary = %#v", summary)
	}
	if len(summary.PlannedActions) != 0 {
		t.Fatalf("completed install reported planned actions: %#v", summary.PlannedActions)
	}
}

func TestSetupInstallJSONReportsOccupiedQuickstartPortTruthfully(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	state := stubSetupSideEffects(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve occupied Quickstart port: %v", err)
	}
	defer func() { _ = occupied.Close() }()
	port := occupied.Addr().(*net.TCPAddr).Port
	for _, key := range []string{"HELM_ADMIN_API_KEY", runtimeTenantIDEnv, runtimePrincipalIDEnv, quickstartExpiresAtEnv} {
		t.Setenv(key, "")
	}
	setupRunQuickstart = func(args []string, stdout, stderr io.Writer, onReady func()) int {
		state.quickstartArgs = append([]string{}, args...)
		runArgs := append(append([]string{}, args...), "--port", strconv.Itoa(port))
		return runQuickstartCmdWithReady(runArgs, stdout, stderr, onReady)
	}

	var stdout, stderr bytes.Buffer
	dataDir := filepath.Join(tmp, "helm")
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("failed Quickstart exit = %d, want 1; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	summary := decodeSingleSetupSummary(t, &stdout)
	if summary.Operation != "install" || summary.QuickstartStarted || summary.KernelURL != "" {
		t.Fatalf("failed Quickstart summary = %#v", summary)
	}
	if !summary.MCPInstalled || !summary.HookInstalled || len(summary.PlannedActions) != 0 {
		t.Fatalf("failed Quickstart install state = %#v", summary)
	}
	if len(state.quickstartArgs) == 0 || !strings.Contains(stderr.String(), "bind API server") {
		t.Fatalf("occupied Quickstart port was not exercised: args=%#v stderr=%s", state.quickstartArgs, stderr.String())
	}
}
