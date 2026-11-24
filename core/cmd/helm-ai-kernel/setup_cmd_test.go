package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
)

type setupPanicReader struct{}

func (setupPanicReader) Read([]byte) (int, error) {
	panic("noninteractive setup must not read input")
}

func TestSetupNoArgsPrintsChooser(t *testing.T) {
	oldSession := setupTerminalSession
	setupTerminalSession = func(io.Writer) (io.Reader, ui.Capabilities) {
		return setupPanicReader{}, ui.Capabilities{Width: ui.DefaultTerminalWidth}
	}
	t.Cleanup(func() { setupTerminalSession = oldSession })

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup no args exit = %d stderr = %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"helm-ai-kernel setup claude-code --yes",
		"helm-ai-kernel setup codex --yes",
		"helm-ai-kernel setup hermes --scope user --yes",
		"helm-ai-kernel setup deepseek --scope user --yes",
		"helm-ai-kernel setup --quickstart --profile mcp --yes",
		"helm-ai-kernel setup --client cursor --print-config",
		"project scope is the default",
		"Interactive terminals show the scoped preview",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup chooser missing %q:\n%s", want, out)
		}
	}
}

func TestSetupInteractiveChooserDelegatesProjectInstall(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Chdir(workspace)
	state := stubSetupSideEffects(t)

	oldSession := setupTerminalSession
	sessions := 0
	setupTerminalSession = func(io.Writer) (io.Reader, ui.Capabilities) {
		sessions++
		if sessions == 1 {
			return strings.NewReader("1\nAPPROVE\n"), ui.Capabilities{Interactive: true, Width: 80}
		}
		return strings.NewReader(""), ui.Capabilities{Interactive: true, Width: 80}
	}
	t.Cleanup(func() { setupTerminalSession = oldSession })

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("interactive setup exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if sessions != 1 {
		t.Fatalf("terminal sessions = %d, want one shared chooser/confirmation session", sessions)
	}
	if len(state.execCalls) != 1 || !strings.Contains(strings.Join(state.execCalls[0], " "), "claude mcp add --transport stdio --scope project") {
		t.Fatalf("chooser did not delegate project-scoped Claude install: %#v", state.execCalls)
	}
	if len(state.quickstartArgs) != 0 {
		t.Fatalf("chooser unexpectedly started Quickstart: %#v", state.quickstartArgs)
	}
	if _, err := os.Stat(filepath.Join(workspace, ".claude", "settings.json")); err != nil {
		t.Fatalf("project-scoped hook config was not installed: %v", err)
	}
	for _, want := range []string{"Claude Code (recommended, default)", "project scope is the default", "Type APPROVE"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("interactive setup missing %q:\n%s", want, stderr.String())
		}
	}
}

func TestSetupInteractiveChooserCancelOrInvalidDoesNotInstall(t *testing.T) {
	for _, test := range []struct {
		name     string
		input    string
		wantCode int
	}{
		{name: "cancel", input: "q\n", wantCode: 0},
		{name: "invalid", input: "nope\n", wantCode: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			tmp := t.TempDir()
			workspace := filepath.Join(tmp, "workspace")
			if err := os.MkdirAll(workspace, 0o750); err != nil {
				t.Fatal(err)
			}
			t.Chdir(workspace)
			state := stubSetupSideEffects(t)
			oldSession := setupTerminalSession
			setupTerminalSession = func(io.Writer) (io.Reader, ui.Capabilities) {
				return strings.NewReader(test.input), ui.Capabilities{Interactive: true, Width: 80}
			}
			t.Cleanup(func() { setupTerminalSession = oldSession })

			var stdout, stderr bytes.Buffer
			if code := Run([]string{"helm-ai-kernel", "setup"}, &stdout, &stderr); code != test.wantCode {
				t.Fatalf("chooser exit=%d, want %d stdout=%s stderr=%s", code, test.wantCode, stdout.String(), stderr.String())
			}
			if len(state.execCalls) != 0 || len(state.quickstartArgs) != 0 || state.probeCalls != 0 {
				t.Fatalf("chooser %s had install side effects: %#v", test.name, state)
			}
			for _, want := range []string{"no changes made", "helm-ai-kernel setup claude-code --scope project --dry-run"} {
				if !strings.Contains(stderr.String(), want) {
					t.Fatalf("chooser %s missing %q:\n%s", test.name, want, stderr.String())
				}
			}
		})
	}
}

func TestParseSetupInstallArgsDefaultsToProjectAndAcceptsUserScope(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", filepath.Join(tmp, "home"))
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "default", args: []string{"codex", "--data-dir", filepath.Join(tmp, "default")}, want: "project"},
		{name: "explicit_user", args: []string{"codex", "--scope", "user", "--data-dir", filepath.Join(tmp, "user")}, want: "user"},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts, code := parseSetupInstallArgs(test.args, io.Discard)
			if code != 0 {
				t.Fatalf("parse code=%d", code)
			}
			if opts.Scope != test.want {
				t.Fatalf("scope=%q, want %q", opts.Scope, test.want)
			}
		})
	}
}

func TestConfirmSetupInstallRequiresExactApproval(t *testing.T) {
	summary := setupSummary{
		Target:           "codex",
		Scope:            "project",
		Workspace:        "/workspace",
		ClientConfigPath: "/workspace/.codex/config.toml",
		HookConfigPath:   "/workspace/.codex/hooks.json",
		DataDir:          "/state",
		RecoveryCommand:  "helm-ai-kernel setup repair codex --scope project --yes --data-dir /state",
	}
	for _, test := range []struct {
		name      string
		input     string
		wantError error
		wantApply bool
	}{
		{name: "cancel", input: "no\n", wantError: ui.ErrConfirmationRequired},
		{name: "approve", input: "APPROVE\n", wantApply: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var chrome strings.Builder
			applied := false
			err := confirmSetupInstall(
				strings.NewReader(test.input),
				&chrome,
				ui.Capabilities{Interactive: true, Width: 100},
				summary,
				[]string{"configure the HELM MCP server", "configure the HELM PreToolUse hook"},
				func() error {
					applied = true
					return nil
				},
			)
			if test.wantError != nil && !errors.Is(err, test.wantError) {
				t.Fatalf("confirmation error = %v, want %v", err, test.wantError)
			}
			if test.wantError == nil && err != nil {
				t.Fatalf("confirmation error = %v", err)
			}
			if applied != test.wantApply {
				t.Fatalf("apply = %v, want %v", applied, test.wantApply)
			}
			for _, want := range []string{"HELM setup preview", "MCP config", "Hook config", "Data dir", "Recovery", "Type APPROVE"} {
				if !strings.Contains(chrome.String(), want) {
					t.Fatalf("confirmation preview missing %q:\n%s", want, chrome.String())
				}
			}
			if strings.Contains(chrome.String(), "\x1b") {
				t.Fatalf("confirmation preview emitted ANSI: %q", chrome.String())
			}
		})
	}
}

func TestSetupFrontDoorRejectsExplicitCrossModeFlags(t *testing.T) {
	original := setupRunFirstRun
	t.Cleanup(func() { setupRunFirstRun = original })
	calls := 0
	setupRunFirstRun = func([]string, io.Writer, io.Writer) int {
		calls++
		return 0
	}

	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "quickstart profile in support matrix mode",
			args: []string{"--profile", "codex", "--yes"},
			want: "--profile requires --quickstart",
		},
		{
			name: "support matrix client in quickstart mode",
			args: []string{"--quickstart", "--client", "cursor", "--yes"},
			want: "--client is not valid with --quickstart",
		},
		{
			name: "config print in quickstart mode",
			args: []string{"--quickstart", "--print-config", "--yes"},
			want: "--print-config is not valid with --quickstart",
		},
		{
			name: "client in json support matrix mode",
			args: []string{"--json", "--client", "cursor"},
			want: "--client is not valid with the support-matrix mode",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(append([]string{"helm-ai-kernel", "setup"}, test.args...), &stdout, &stderr)
			if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("setup %v code=%d stdout=%q stderr=%q", test.args, code, stdout.String(), stderr.String())
			}
		})
	}
	if calls != 0 {
		t.Fatalf("invalid front-door flags delegated to Quickstart %d times", calls)
	}
}

func TestSetupJSONSupportMatrix(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup --json exit = %d stderr = %s", code, stderr.String())
	}
	var matrix cliSupportMatrix
	if err := json.Unmarshal(stdout.Bytes(), &matrix); err != nil {
		t.Fatalf("support matrix JSON: %v\n%s", err, stdout.String())
	}
	for _, want := range []string{"claude-code", "codex", "hermes", "deepseek"} {
		if !containsSetupString(matrix.DirectSetup, want) {
			t.Fatalf("direct setup missing %q: %#v", want, matrix.DirectSetup)
		}
	}
	for _, want := range []string{"cursor", "windsurf", "vscode"} {
		if !containsSetupString(matrix.ConfigPrint, want) {
			t.Fatalf("config print missing %q: %#v", want, matrix.ConfigPrint)
		}
	}
	for _, want := range []string{"openclaw", "hermes", "mastra", "browser-use", "tinyfish", "e2b", "composio"} {
		if !containsSetupString(matrix.WrapperExamples, want) {
			t.Fatalf("wrapper examples missing %q: %#v", want, matrix.WrapperExamples)
		}
	}
}

func TestSetupPrintConfigDelegatesSupportedClients(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "--client", "cursor", "--print-config"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup print-config exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "# Cursor MCP Configuration") {
		t.Fatalf("cursor config missing:\n%s", stdout.String())
	}
}

func TestPublicExamplesAvoidStaleCLIStrings(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{
		"mcp print-config --client " + "claude-code",
		"127.0.0.1:" + "7715",
	}
	for _, dir := range []string{filepath.Join(root, "docs"), filepath.Join(root, "core", "cmd", "helm-ai-kernel"), filepath.Join(root, "sdk")} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			switch filepath.Ext(path) {
			case ".go", ".md", ".json", ".toml":
			default:
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			text := string(raw)
			for _, term := range banned {
				if strings.Contains(text, term) {
					t.Fatalf("%s contains stale public CLI term %q", path, term)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSetupCodexProjectRemoveUndoLocalConfig(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, ".codex"), 0o750); err != nil {
		t.Fatal(err)
	}
	canonicalWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatalf("resolve workspace: %v", err)
	}
	markCodexProjectTrusted(t, home, workspace)
	configPath := filepath.Join(workspace, ".codex", "config.toml")
	if err := os.WriteFile(configPath, []byte("model = \"gpt-6-sol\"\n\n[mcp_servers.other]\ncommand = \"other-mcp\"\nargs = [\"serve\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(workspace, ".codex", "hooks.json")
	if err := os.WriteFile(hookPath, []byte("{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"Bash\",\"hooks\":[{\"type\":\"command\",\"command\":\"other-hook\"}]}]}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := stubSetupSideEffects(t)

	var stdout, stderr bytes.Buffer
	dataDir := filepath.Join(tmp, "helm")
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	if len(restore.execCalls) != 0 {
		t.Fatalf("codex project setup should write config directly, exec calls = %#v", restore.execCalls)
	}
	var installed setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &installed); err != nil {
		t.Fatalf("decode setup summary: %v\n%s", err, stdout.String())
	}
	if installed.Workspace != canonicalWorkspace || installed.KernelURL != "" || installed.QuickstartStarted {
		t.Fatalf("unexpected headless setup summary: %#v", installed)
	}
	if len(restore.quickstartArgs) != 0 {
		t.Fatalf("--no-quickstart invoked Quickstart: %#v", restore.quickstartArgs)
	}
	if installed.Operation != "install" {
		t.Fatalf("operation = %q, want install", installed.Operation)
	}
	invRaw, err := os.ReadFile(filepath.Join(dataDir, "autoconfigure", "inventory.json"))
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	var inventory AutoconfigureInventory
	if err := json.Unmarshal(invRaw, &inventory); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	if inventory.ScanRoot != canonicalWorkspace {
		t.Fatalf("scan root = %q, want selected workspace %q", inventory.ScanRoot, canonicalWorkspace)
	}
	if !setupMCPInstalled(setupOptions{Target: "codex", Scope: "project", Workspace: workspace, WorkspaceSet: true, DataDir: dataDir}, configPath, installed.BinaryPath) {
		t.Fatal("semantic status did not recognize the installed Codex MCP server")
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read codex config: %v", err)
	}
	if !strings.Contains(string(raw), "[mcp_servers.helm-ai-kernel-governance]") {
		t.Fatalf("codex config missing MCP table:\n%s", string(raw))
	}
	var config codexProjectConfig
	if _, err := toml.Decode(string(raw), &config); err != nil {
		t.Fatalf("parse codex config: %v\n%s", err, raw)
	}
	server := config.MCPServers[setupMCPServerName]
	wantArgs := []string{"mcp", "serve", "--transport", "stdio", "--data-dir", dataDir}
	if !equalSetupStrings(server.Args, wantArgs) {
		t.Fatalf("MCP args = %#v, want %#v", server.Args, wantArgs)
	}
	raw, err = os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read hook config: %v", err)
	}
	if !strings.Contains(string(raw), "hook pre-tool --client codex") {
		t.Fatalf("codex hook config missing command:\n%s", string(raw))
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--workspace", workspace, "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("status exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	var status setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("decode status summary: %v\n%s", err, stdout.String())
	}
	if !status.MCPInstalled || !status.HookInstalled || status.ClientState != "configured_unverified" || status.KernelURL != "" {
		t.Fatalf("unexpected setup status: %#v", status)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("remove exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	raw, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read codex config after remove: %v", err)
	}
	if strings.Contains(string(raw), "helm-ai-kernel-governance") {
		t.Fatalf("codex config still contains HELM server:\n%s", string(raw))
	}
	if !strings.Contains(string(raw), "[mcp_servers.other]") || !strings.Contains(string(raw), "model = \"gpt-6-sol\"") {
		t.Fatalf("remove did not preserve unrelated Codex config:\n%s", string(raw))
	}
	raw, err = os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read hook config after remove: %v", err)
	}
	if strings.Contains(string(raw), "hook pre-tool --client codex") {
		t.Fatalf("hook config still contains HELM command:\n%s", string(raw))
	}
	if !strings.Contains(string(raw), "other-hook") {
		t.Fatalf("remove did not preserve unrelated Codex hook:\n%s", string(raw))
	}
}

func TestSetupRequiresYesForInstall(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--data-dir", t.TempDir()}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("setup without --yes exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "pass --yes") {
		t.Fatalf("stderr missing --yes guidance: %s", stderr.String())
	}
}

type setupStubState struct {
	execCalls      [][]string
	execDirs       []string
	quickstartArgs []string
	probeCalls     int
}

func stubSetupSideEffects(t *testing.T) *setupStubState {
	t.Helper()
	state := &setupStubState{}
	oldExec := setupExecCommand
	oldQuickstart := setupRunQuickstart
	oldFindClient := setupFindClient
	oldProbeClient := setupProbeClient
	clientPath := filepath.Join(t.TempDir(), "client")
	setupExecCommand = func(dir, name string, args ...string) error {
		call := append([]string{name}, args...)
		state.execCalls = append(state.execCalls, call)
		state.execDirs = append(state.execDirs, dir)
		return nil
	}
	setupRunQuickstart = func(args []string, stdout, stderr io.Writer, onReady func()) int {
		state.quickstartArgs = append([]string{}, args...)
		if onReady != nil {
			onReady()
		}
		_, _ = io.WriteString(stdout, "quickstart ready\n")
		return 0
	}
	setupFindClient = func(string) (string, error) {
		return clientPath, nil
	}
	setupProbeClient = func(string, string) error {
		state.probeCalls++
		return nil
	}
	t.Cleanup(func() {
		setupExecCommand = oldExec
		setupRunQuickstart = oldQuickstart
		setupFindClient = oldFindClient
		setupProbeClient = oldProbeClient
	})
	return state
}

func decodeSingleSetupSummary(t *testing.T, stdout *bytes.Buffer) setupSummary {
	t.Helper()
	dec := json.NewDecoder(stdout)
	var summary setupSummary
	if err := dec.Decode(&summary); err != nil {
		t.Fatalf("summary JSON: %v\n%s", err, stdout.String())
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("stdout should contain only one JSON value, extra=%#v err=%v stdout=%s", extra, err, stdout.String())
	}
	return summary
}

func containsSetupString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestSetupCodexProjectTrustPending(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, ".codex"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".codex", "config.toml"),
		[]byte("model = \"gpt-6-sol\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Untrusted: no ~/.codex/config.toml projects entry → pending.
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	if !codexProjectTrustPending(workspace) {
		t.Fatal("expected trust pending when no projects entry exists")
	}

	// Trusted: matching projects entry with trust_level=trusted → not pending.
	markCodexProjectTrusted(t, home, workspace)
	if codexProjectTrustPending(workspace) {
		t.Fatal("expected trust NOT pending once workspace is recorded trusted")
	}

	// setup status must fail-closed (exit 1) while trust is pending.
	if err := os.Remove(filepath.Join(home, ".codex", "config.toml")); err != nil {
		t.Fatal(err)
	}
	restore := stubSetupSideEffects(t)
	_ = restore
	var so, se bytes.Buffer
	dataDir := filepath.Join(tmp, "helm")
	// Install first (writes the project config), then status.
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--no-quickstart", "--json", "--data-dir", dataDir}, &so, &se); code != 0 {
		t.Fatalf("install exit = %d stderr=%s", code, se.String())
	}
	var installed setupSummary
	if err := json.Unmarshal(so.Bytes(), &installed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !installed.CodexTrustPending {
		t.Fatal("install summary should report CodexTrustPending=true for an untrusted project")
	}
	so.Reset()
	se.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--workspace", workspace, "--json", "--data-dir", dataDir}, &so, &se); code != 1 {
		t.Fatalf("pending status exit = %d, want 1; stderr=%s stdout=%s", code, se.String(), so.String())
	}
	pending := decodeSingleSetupSummary(t, &so)
	if !pending.CodexTrustPending || pending.ClientState != "trust_pending" {
		t.Fatalf("pending status lost explicit trust state: %#v", pending)
	}
}

// markCodexProjectTrusted records the workspace as trusted in
// $home/.codex/config.toml so setup/status treats a project-scoped Codex
// config as an effective (Codex-loadable) install.
func markCodexProjectTrusted(t *testing.T, home, workspace string) {
	t.Helper()
	abs, err := filepath.Abs(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o750); err != nil {
		t.Fatal(err)
	}
	body := "[projects.\"" + abs + "\"]\ntrust_level = \"trusted\"\n"
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
