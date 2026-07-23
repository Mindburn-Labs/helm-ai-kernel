package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestSetupNoArgsPrintsChooser(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup no args exit = %d stderr = %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"helm-ai-kernel setup claude-code --yes",
		"helm-ai-kernel setup codex --yes",
		"helm-ai-kernel setup --client cursor --print-config",
		"No config is written without --yes.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup chooser missing %q:\n%s", want, out)
		}
	}
}

func TestSetupHookCommandIncludesExplicitSigningSeedFile(t *testing.T) {
	opts := setupOptions{
		Target:          "codex",
		DataDir:         "/tmp/helm-data",
		SigningSeedFile: "/private/approved/workstation.seed",
	}
	command := setupHookCommand(opts, "/usr/local/bin/helm-ai-kernel")
	if !strings.Contains(command, "--signing-seed-file '/private/approved/workstation.seed'") {
		t.Fatalf("hook command did not preserve explicit signer source: %s", command)
	}
	if removal := setupUninstallCommand(opts); !strings.Contains(removal, "--signing-seed-file '/private/approved/workstation.seed'") {
		t.Fatalf("uninstall command did not preserve explicit signer source: %s", removal)
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
	for _, want := range []string{"claude-code", "codex"} {
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
	for _, want := range []string{"LangGraph", "LangChain", "CrewAI", "OpenAI Agents SDK", "AutoGen/AG2", "Semantic Kernel", "PydanticAI", "LlamaIndex", "LiteLLM", "n8n", "Zapier", "raw MCP"} {
		if !containsSetupString(matrix.FrameworkAdapters, want) {
			t.Fatalf("framework adapters missing %q: %#v", want, matrix.FrameworkAdapters)
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

func TestSetupDryRunJSONSummary(t *testing.T) {
	tmp := t.TempDir()
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

func TestSetupJSONSummaryMatchesOperation(t *testing.T) {
	tests := []struct {
		name        string
		wantCode    int
		wantOp      string
		wantActions []string
		wantURL     bool
	}{
		{
			name:     "preview",
			wantCode: 0,
			wantOp:   "preview",
			wantActions: []string{
				"scan selected workspace and write draft-only inventory artifacts",
				"configure the HELM MCP server with the selected local data directory",
				"configure the HELM PreToolUse hook for the selected client",
				"start the local Quickstart proof path",
			},
			wantURL: true,
		},
		{name: "install", wantCode: 0, wantOp: "install", wantActions: []string{}},
		{name: "status", wantCode: 1, wantOp: "status", wantActions: []string{}},
		{
			name:     "preview_remove",
			wantCode: 0,
			wantOp:   "preview_remove",
			wantActions: []string{
				"remove the HELM PreToolUse hook from the selected scope",
				"remove the HELM MCP server from the selected scope",
			},
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
			if !equalSetupStrings(summary.PlannedActions, test.wantActions) {
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

func TestSetupRequiresExplicitDataDirWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "claude-code", "--dry-run"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--data-dir is required") {
		t.Fatalf("HOME-less setup = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestSetupUserScopeRequiresAbsoluteHomeEvenWithDataDir(t *testing.T) {
	commands := [][]string{
		{"helm-ai-kernel", "setup", "codex", "--yes"},
		{"helm-ai-kernel", "setup", "status", "codex"},
		{"helm-ai-kernel", "setup", "remove", "codex", "--yes"},
	}
	for _, home := range []string{"", "relative-home"} {
		for _, command := range commands {
			name := strings.Join(command[1:3], "-")
			t.Run(home+"/"+name, func(t *testing.T) {
				t.Setenv("HOME", home)
				for _, target := range []string{"claude-code", "codex"} {
					opts := setupOptions{Target: target, Scope: "user"}
					if path := setupClientConfigPath(opts); path != "" {
						t.Fatalf("HOME=%q %s client path = %q, want empty", home, target, path)
					}
					if path := setupHookConfigPath(opts); path != "" {
						t.Fatalf("HOME=%q %s hook path = %q, want empty", home, target, path)
					}
				}
				args := append([]string{}, command...)
				args = append(args, "--data-dir", t.TempDir())
				var stdout, stderr bytes.Buffer
				code := Run(args, &stdout, &stderr)
				if code != 2 || !strings.Contains(stderr.String(), "user scope requires an absolute home directory") {
					t.Fatalf("HOME=%q args=%q setup = %d stdout=%s stderr=%s", home, args, code, stdout.String(), stderr.String())
				}
			})
		}
	}
}

func TestSetupInstallClaudeWritesHookAndRunsQuickstart(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	restore := stubSetupSideEffects(t)

	var stdout, stderr bytes.Buffer
	dataDir := filepath.Join(tmp, "helm")
	code := Run([]string{"helm-ai-kernel", "setup", "claude-code", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
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
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
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
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
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
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n\n[mcp_servers.other]\ncommand = \"other-mcp\"\nargs = [\"serve\"]\n"), 0o600); err != nil {
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
	if code != 0 {
		t.Fatalf("status exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	var status setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("decode status summary: %v\n%s", err, stdout.String())
	}
	if !status.MCPInstalled || !status.HookInstalled || status.KernelURL != "" {
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
	if !strings.Contains(string(raw), "[mcp_servers.other]") || !strings.Contains(string(raw), "model = \"gpt-5\"") {
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

func TestSetupProjectScopeDefaultsToCurrentDirectory(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Chdir(workspace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--dry-run", "--json", "--data-dir", filepath.Join(tmp, "helm")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("project setup without explicit workspace code=%d stderr=%s", code, stderr.String())
	}
	var summary setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode project setup summary: %v\n%s", err, stdout.String())
	}
	canonicalWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatalf("resolve workspace: %v", err)
	}
	if summary.Workspace != canonicalWorkspace {
		t.Fatalf("workspace = %q, want current directory %q", summary.Workspace, canonicalWorkspace)
	}
	if summary.ClientConfigPath != filepath.Join(canonicalWorkspace, ".codex", "config.toml") {
		t.Fatalf("client config path = %q", summary.ClientConfigPath)
	}

	restore := stubSetupSideEffects(t)
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--no-quickstart", "--json", "--data-dir", filepath.Join(tmp, "helm")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("project install without explicit workspace code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if len(restore.execCalls) != 0 {
		t.Fatalf("Codex project install should write config directly, exec calls = %#v", restore.execCalls)
	}
	if !setupMCPInstalled(setupOptions{Target: "codex", Scope: "project", Workspace: canonicalWorkspace, DataDir: filepath.Join(tmp, "helm")}, summary.ClientConfigPath, summary.BinaryPath) {
		t.Fatal("Codex project install did not write MCP config under the current directory")
	}
	if _, err := os.Stat(filepath.Join(canonicalWorkspace, ".codex", "hooks.json")); err != nil {
		t.Fatalf("Codex project install did not write hook config under the current directory: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "user", "--workspace", workspace, "--dry-run", "--json", "--data-dir", filepath.Join(tmp, "helm")}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "only valid with --scope project") {
		t.Fatalf("user setup with workspace code=%d stderr=%s", code, stderr.String())
	}
}

func TestSetupMCPInstalledRequiresExactScopedBinding(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	bin := filepath.Join(tmp, "bin", "helm-ai-kernel")
	dataDir := filepath.Join(tmp, "helm-data")

	for _, test := range []struct {
		target string
		scope  string
	}{
		{target: "claude-code", scope: "user"},
		{target: "claude-code", scope: "project"},
		{target: "codex", scope: "user"},
		{target: "codex", scope: "project"},
	} {
		t.Run(test.target+"_"+test.scope, func(t *testing.T) {
			workspace := filepath.Join(tmp, test.target+"-"+test.scope+"-workspace")
			if err := os.MkdirAll(workspace, 0o750); err != nil {
				t.Fatal(err)
			}
			opts := setupOptions{Target: test.target, Scope: test.scope, Workspace: workspace, DataDir: dataDir}
			path := setupClientConfigPath(opts)

			writeSetupMCPTestConfig(t, test.target, path, bin, dataDir)
			if !setupMCPInstalled(opts, path, bin) {
				t.Fatal("exact MCP binding was not recognized")
			}

			writeSetupMCPTestConfig(t, test.target, path, bin, filepath.Join(tmp, "stale-data"))
			if setupMCPInstalled(opts, path, bin) {
				t.Fatal("MCP binding with stale data directory was reported healthy")
			}

			writeSetupMCPTestConfig(t, test.target, path, filepath.Join(tmp, "stale-bin"), dataDir)
			if setupMCPInstalled(opts, path, bin) {
				t.Fatal("MCP binding with stale Kernel binary was reported healthy")
			}

			otherPath := filepath.Join(tmp, test.target+"-"+test.scope+"-other-config")
			writeSetupMCPTestConfig(t, test.target, otherPath, bin, dataDir)
			if setupMCPInstalled(opts, otherPath, bin) {
				t.Fatal("MCP binding from the wrong scope path was reported healthy")
			}

			outsidePath := filepath.Join(tmp, test.target+"-"+test.scope+"-external-config")
			writeSetupMCPTestConfig(t, test.target, outsidePath, bin, dataDir)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outsidePath, path); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			got := setupMCPInstalled(opts, path, bin)
			if test.scope == "project" && got {
				t.Fatal("project MCP binding through an external symlink was reported healthy")
			}
			if test.scope == "user" && !got {
				t.Fatal("user MCP binding through an external dotfile symlink was not recognized")
			}
		})
	}
}

func TestSetupStatusRejectsStaleMCPDataDir(t *testing.T) {
	for _, test := range []struct {
		target string
		scope  string
	}{
		{target: "claude-code", scope: "user"},
		{target: "claude-code", scope: "project"},
		{target: "codex", scope: "user"},
		{target: "codex", scope: "project"},
	} {
		t.Run(test.target+"_"+test.scope, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("HOME", filepath.Join(tmp, "home"))
			home := filepath.Join(tmp, "home")
			t.Setenv("HOME", home)
			workspace := filepath.Join(tmp, "workspace")
			if err := os.MkdirAll(workspace, 0o750); err != nil {
				t.Fatal(err)
			}
			if test.target == "codex" && test.scope == "project" {
				// Record the workspace as trusted so status reflects an
				// effective (Codex-loadable) install rather than trust-pending.
				markCodexProjectTrusted(t, home, workspace)
			}
			dataDir := filepath.Join(tmp, "helm-data")
			opts := setupOptions{Operation: "status", Target: test.target, Scope: test.scope, Workspace: workspace, DataDir: dataDir}
			summary, err := buildSetupSummary(opts)
			if err != nil {
				t.Fatal(err)
			}
			if err := upsertHookConfig(summary.HookConfigPath, setupHookMatcher(test.target), setupHookCommand(opts, summary.BinaryPath), setupPrivateFileRoot(opts)); err != nil {
				t.Fatalf("write exact hook config: %v", err)
			}
			writeSetupMCPTestConfig(t, test.target, summary.ClientConfigPath, summary.BinaryPath, filepath.Join(tmp, "stale-data"))

			args := []string{"helm-ai-kernel", "setup", "status", test.target, "--scope", test.scope, "--json", "--data-dir", dataDir}
			if test.scope == "project" {
				args = append(args, "--workspace", workspace)
			}
			var stdout, stderr bytes.Buffer
			code := Run(args, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("stale status exit = %d, want 1; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
			}
			stale := decodeSingleSetupSummary(t, &stdout)
			if stale.MCPInstalled || !stale.HookInstalled {
				t.Fatalf("stale status = %#v, want MCP false and hook true", stale)
			}

			writeSetupMCPTestConfig(t, test.target, summary.ClientConfigPath, summary.BinaryPath, dataDir)
			stdout.Reset()
			stderr.Reset()
			code = Run(args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exact status exit = %d, want 0; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
			}
			exact := decodeSingleSetupSummary(t, &stdout)
			if !exact.MCPInstalled || !exact.HookInstalled {
				t.Fatalf("exact status = %#v, want MCP and hook true", exact)
			}
		})
	}
}

func writeSetupMCPTestConfig(t *testing.T, target, path, bin, dataDir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	switch target {
	case "claude-code":
		config := claudeMCPConfig{MCPServers: map[string]claudeMCPServer{
			setupMCPServerName: {Command: bin, Args: setupMCPArgs(dataDir)},
		}}
		var err error
		raw, err = json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
	case "codex":
		raw = []byte("[mcp_servers." + setupMCPServerName + "]\ncommand = " + strconv.Quote(bin) + "\nargs = [\"mcp\", \"serve\", \"--transport\", \"stdio\", \"--data-dir\", " + strconv.Quote(dataDir) + "]\n")
	default:
		t.Fatalf("unsupported test target %q", target)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSetupClaudeProjectMCPCommandsUseSelectedWorkspace(t *testing.T) {
	tmp := t.TempDir()
	caller := filepath.Join(tmp, "caller")
	workspace := filepath.Join(tmp, "workspace")
	for _, dir := range []string{caller, workspace} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(caller)
	canonicalWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatalf("resolve workspace: %v", err)
	}
	restore := stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "claude-code", "--scope", "project", "--workspace", workspace, "--yes", "--no-quickstart", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("project setup exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	if len(restore.execCalls) != 1 || len(restore.execDirs) != 1 {
		t.Fatalf("project setup exec calls = %#v dirs = %#v", restore.execCalls, restore.execDirs)
	}
	if restore.execDirs[0] != canonicalWorkspace {
		t.Fatalf("project setup exec dir = %q, want %q", restore.execDirs[0], canonicalWorkspace)
	}
	if !strings.Contains(strings.Join(restore.execCalls[0], " "), "claude mcp add --transport stdio --scope project") {
		t.Fatalf("project setup exec call = %#v", restore.execCalls[0])
	}

	restore.execCalls = nil
	restore.execDirs = nil
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "remove", "claude-code", "--scope", "project", "--workspace", workspace, "--yes", "--no-quickstart", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("project remove exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	if len(restore.execCalls) != 1 || len(restore.execDirs) != 1 {
		t.Fatalf("project remove exec calls = %#v dirs = %#v", restore.execCalls, restore.execDirs)
	}
	if restore.execDirs[0] != canonicalWorkspace {
		t.Fatalf("project remove exec dir = %q, want %q", restore.execDirs[0], canonicalWorkspace)
	}
	if !strings.Contains(strings.Join(restore.execCalls[0], " "), "claude mcp remove --scope project") {
		t.Fatalf("project remove exec call = %#v", restore.execCalls[0])
	}
}

func TestSetupClaudeProjectPreservesSymlinkedHookConfig(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	targetDir := filepath.Join(workspace, ".managed-dotfiles", "claude")
	for _, dir := range []string{filepath.Join(workspace, ".claude"), targetDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(targetDir, "settings.json")
	if err := os.WriteFile(target, []byte("{\"hooks\":{\"PreToolUse\":[]}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(workspace, ".claude", "settings.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	opts := setupOptions{Target: "claude-code", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
	bin := filepath.Join(tmp, "helm-ai-kernel")

	if err := installSetupHook(opts, bin); err != nil {
		t.Fatalf("install symlinked Claude hook: %v", err)
	}
	assertSetupSymlinkTarget(t, link, target, 0o600, "hook pre-tool --client claude-code")
	assertNoSetupTempFiles(t, filepath.Dir(link), targetDir)

	if err := removeSetupHook(opts, bin); err != nil {
		t.Fatalf("remove symlinked Claude hook: %v", err)
	}
	assertSetupSymlinkTarget(t, link, target, 0o600, "")
	if raw, err := os.ReadFile(target); err != nil {
		t.Fatal(err)
	} else if strings.Contains(string(raw), "hook pre-tool --client claude-code") {
		t.Fatalf("Claude hook target still contains HELM command:\n%s", raw)
	}
	assertNoSetupTempFiles(t, filepath.Dir(link), targetDir)
}

func TestSetupCodexProjectPreservesSymlinkedConfigFiles(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	targetDir := filepath.Join(workspace, ".managed-dotfiles", "codex")
	for _, dir := range []string{filepath.Join(workspace, ".codex"), targetDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	configTarget := filepath.Join(targetDir, "config.toml")
	hookTarget := filepath.Join(targetDir, "hooks.json")
	if err := os.WriteFile(configTarget, []byte("model = \"gpt-5\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookTarget, []byte("{\"hooks\":{\"PreToolUse\":[]}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	configLink := filepath.Join(workspace, ".codex", "config.toml")
	hookLink := filepath.Join(workspace, ".codex", "hooks.json")
	if err := os.Symlink(configTarget, configLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(hookTarget, hookLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	opts := setupOptions{Target: "codex", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
	bin := filepath.Join(tmp, "helm-ai-kernel")

	if err := installSetupMCP(opts, bin); err != nil {
		t.Fatalf("install symlinked Codex MCP config: %v", err)
	}
	if err := installSetupHook(opts, bin); err != nil {
		t.Fatalf("install symlinked Codex hook config: %v", err)
	}
	assertSetupSymlinkTarget(t, configLink, configTarget, 0o600, "[mcp_servers."+setupMCPServerName+"]")
	assertSetupSymlinkTarget(t, hookLink, hookTarget, 0o600, "hook pre-tool --client codex")
	assertNoSetupTempFiles(t, filepath.Dir(configLink), targetDir)

	if err := removeSetupHook(opts, bin); err != nil {
		t.Fatalf("remove symlinked Codex hook config: %v", err)
	}
	if err := removeSetupMCP(opts); err != nil {
		t.Fatalf("remove symlinked Codex MCP config: %v", err)
	}
	assertSetupSymlinkTarget(t, configLink, configTarget, 0o600, "model = \"gpt-5\"")
	assertSetupSymlinkTarget(t, hookLink, hookTarget, 0o600, "")
	for path, forbidden := range map[string]string{
		configTarget: setupMCPServerName,
		hookTarget:   "hook pre-tool --client codex",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("%s still contains %q:\n%s", path, forbidden, raw)
		}
	}
	assertNoSetupTempFiles(t, filepath.Dir(configLink), targetDir)
}

func TestSetupProjectRejectsConfigSymlinkEscapes(t *testing.T) {
	t.Run("claude MCP config", func(t *testing.T) {
		tmp := t.TempDir()
		workspace := filepath.Join(tmp, "workspace")
		outside := filepath.Join(tmp, "outside")
		for _, dir := range []string{workspace, outside} {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		target := filepath.Join(outside, "mcp.json")
		original := []byte("{\"mcpServers\":{}}\n")
		if err := os.WriteFile(target, original, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(workspace, ".mcp.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		state := stubSetupSideEffects(t)
		opts := setupOptions{Target: "claude-code", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
		if err := installSetupMCP(opts, filepath.Join(tmp, "helm-ai-kernel")); err == nil || !strings.Contains(err.Error(), "outside project workspace") {
			t.Fatalf("Claude project MCP escape error = %v", err)
		}
		if len(state.execCalls) != 0 {
			t.Fatalf("Claude CLI ran after config escape: %#v", state.execCalls)
		}
		assertSetupFileUnchanged(t, link, target, original)
		assertNoSetupTempFiles(t, workspace, outside)
	})

	t.Run("claude hook config", func(t *testing.T) {
		tmp := t.TempDir()
		workspace := filepath.Join(tmp, "workspace")
		outside := filepath.Join(tmp, "outside")
		for _, dir := range []string{filepath.Join(workspace, ".claude"), outside} {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		target := filepath.Join(outside, "settings.json")
		original := []byte("{\"hooks\":{\"PreToolUse\":[]}}\n")
		if err := os.WriteFile(target, original, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(workspace, ".claude", "settings.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		opts := setupOptions{Target: "claude-code", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
		if err := installSetupHook(opts, filepath.Join(tmp, "helm-ai-kernel")); err == nil || !strings.Contains(err.Error(), "outside project workspace") {
			t.Fatalf("Claude project hook escape error = %v", err)
		}
		assertSetupFileUnchanged(t, link, target, original)
		assertNoSetupTempFiles(t, filepath.Dir(link), outside)
	})

	t.Run("codex config", func(t *testing.T) {
		tmp := t.TempDir()
		workspace := filepath.Join(tmp, "workspace")
		outside := filepath.Join(tmp, "outside")
		for _, dir := range []string{filepath.Join(workspace, ".codex"), outside} {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		target := filepath.Join(outside, "config.toml")
		original := []byte("model = \"gpt-5\"\n")
		if err := os.WriteFile(target, original, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(workspace, ".codex", "config.toml")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		opts := setupOptions{Target: "codex", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
		if err := installSetupMCP(opts, filepath.Join(tmp, "helm-ai-kernel")); err == nil || !strings.Contains(err.Error(), "outside project workspace") {
			t.Fatalf("Codex project config escape error = %v", err)
		}
		assertSetupFileUnchanged(t, link, target, original)
		assertNoSetupTempFiles(t, filepath.Dir(link), outside)
	})

	t.Run("codex parent directory", func(t *testing.T) {
		tmp := t.TempDir()
		workspace := filepath.Join(tmp, "workspace")
		outside := filepath.Join(tmp, "outside")
		for _, dir := range []string{workspace, outside} {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		link := filepath.Join(workspace, ".codex")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		opts := setupOptions{Target: "codex", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
		if err := installSetupMCP(opts, filepath.Join(tmp, "helm-ai-kernel")); err == nil || !strings.Contains(err.Error(), "outside project workspace") {
			t.Fatalf("Codex project parent escape error = %v", err)
		}
		if _, err := os.Stat(filepath.Join(outside, "config.toml")); !os.IsNotExist(err) {
			t.Fatalf("Codex config was created outside workspace, stat error = %v", err)
		}
		if info, err := os.Lstat(link); err != nil {
			t.Fatalf("Codex directory symlink was removed: %v", err)
		} else if info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("Codex directory mode = %v, want symlink", info.Mode())
		}
		assertNoSetupTempFiles(t, outside)
	})
}

func TestSetupUserScopePreservesExternalHookSymlinks(t *testing.T) {
	for _, target := range []string{"claude-code", "codex"} {
		t.Run(target, func(t *testing.T) {
			tmp := t.TempDir()
			home := filepath.Join(tmp, "home")
			external := filepath.Join(tmp, "managed-dotfiles", target)
			if err := os.MkdirAll(external, 0o750); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			opts := setupOptions{Target: target, Scope: "user", DataDir: filepath.Join(tmp, "helm")}
			link := setupHookConfigPath(opts)
			if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
				t.Fatal(err)
			}
			managed := filepath.Join(external, "hooks.json")
			if err := os.WriteFile(managed, []byte("{\"hooks\":{\"PreToolUse\":[]}}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(managed, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			bin := filepath.Join(tmp, "helm-ai-kernel")
			if err := installSetupHook(opts, bin); err != nil {
				t.Fatalf("install user hook through external symlink: %v", err)
			}
			assertSetupSymlinkTarget(t, link, managed, 0o600, "hook pre-tool --client "+target)
			if err := removeSetupHook(opts, bin); err != nil {
				t.Fatalf("remove user hook through external symlink: %v", err)
			}
			assertSetupSymlinkTarget(t, link, managed, 0o600, "")
			assertNoSetupTempFiles(t, filepath.Dir(link), external)
		})
	}
}

func TestWritePrivateFileAtomicRejectsUnsafeSymlinkTargets(t *testing.T) {
	tmp := t.TempDir()
	for _, test := range []struct {
		name   string
		target string
	}{
		{name: "dangling", target: filepath.Join(tmp, "missing.json")},
		{name: "directory", target: filepath.Join(tmp, "directory-target")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "directory" {
				if err := os.MkdirAll(test.target, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			linkDir := filepath.Join(tmp, test.name)
			if err := os.MkdirAll(linkDir, 0o750); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(linkDir, "settings.json")
			if err := os.Symlink(test.target, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if err := writePrivateFileAtomic(link, []byte("{}\n"), ""); err == nil {
				t.Fatal("unsafe symlink target unexpectedly accepted")
			}
			if info, err := os.Lstat(link); err != nil {
				t.Fatalf("symlink was removed: %v", err)
			} else if info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("path mode = %v, want symlink", info.Mode())
			}
			assertNoSetupTempFiles(t, linkDir, filepath.Dir(test.target))
		})
	}
}

func TestWritePrivateFileAtomicProjectRejectsParentSwap(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	configDir := filepath.Join(workspace, ".codex")
	outside := filepath.Join(tmp, "outside")
	for _, dir := range []string{configDir, outside} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(configDir, "config.toml")
	original := []byte("model = \"inside\"\n")
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	outsidePath := filepath.Join(outside, "config.toml")
	outsideOriginal := []byte("model = \"outside\"\n")
	if err := os.WriteFile(outsidePath, outsideOriginal, 0o600); err != nil {
		t.Fatal(err)
	}
	movedConfigDir := filepath.Join(workspace, ".codex-before-swap")
	var mutationErr error
	err := writePrivateFileAtomicWithMutationHook(configPath, []byte("model = \"attacker-controlled\"\n"), workspace, func() {
		mutationErr = os.Rename(configDir, movedConfigDir)
		if mutationErr == nil {
			mutationErr = os.Symlink(outside, configDir)
		}
	})
	if mutationErr != nil {
		t.Skipf("parent-swap symlink unavailable: %v", mutationErr)
	}
	if err == nil {
		t.Fatal("project write succeeded after its validated parent was swapped outside the workspace")
	}
	if info, lstatErr := os.Lstat(configDir); lstatErr != nil {
		t.Fatalf("swapped parent missing: %v", lstatErr)
	} else if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("swapped parent mode = %v, want symlink", info.Mode())
	}
	for path, want := range map[string][]byte{
		filepath.Join(movedConfigDir, "config.toml"): original,
		outsidePath: outsideOriginal,
	} {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		if !bytes.Equal(raw, want) {
			t.Fatalf("%s changed after parent swap:\n%s", path, raw)
		}
	}
	assertNoSetupTempFiles(t, workspace, movedConfigDir, outside)
}

func TestSetupCodexProjectRejectsMalformedConfigWithoutOverwriting(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	configPath := filepath.Join(workspace, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		t.Fatal(err)
	}
	invalid := "[mcp_servers\ncommand = \"broken\"\n"
	if err := os.WriteFile(configPath, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	stubSetupSideEffects(t)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--no-quickstart", "--data-dir", filepath.Join(tmp, "helm")}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "parse existing Codex config") {
		t.Fatalf("malformed config setup code=%d stderr=%s", code, stderr.String())
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != invalid {
		t.Fatalf("malformed config was changed:\n%s", raw)
	}
}

func TestLocalMCPRuntimeUsesExplicitDataDir(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "kernel-store")
	if _, _, err := newLocalMCPRuntimeWithDataDir(dataDir); err != nil {
		t.Fatalf("create local MCP runtime: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "root.key")); err != nil {
		t.Fatalf("custom MCP data dir did not receive the signer root key: %v", err)
	}
}

func TestSetupMigratesLegacyHookWithoutDuplicationAndProvisionsSigningKey(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	legacy := setupHookCommand(opts, bin)
	legacyConfig := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{map[string]any{
				"matcher": "^(Bash|apply_patch|mcp__.*)$",
				"hooks": []any{map[string]any{
					"type":    "command",
					"command": legacy,
				}},
			}},
		},
	}
	raw, err := json.Marshal(legacyConfig)
	if err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(tmp, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup upgrade exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	raw, err = os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), legacy); got != 1 {
		t.Fatalf("legacy hook command count = %d, want 1: %s", got, raw)
	}
	if info, err := os.Stat(workstationSigningSeedPath(dataDir)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("setup signing seed permissions = %v/%v, want 0600", info, err)
	}
	if _, err := os.Stat(workstationSigningPublicKeyPath(dataDir)); err != nil {
		t.Fatalf("setup signing public key missing: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup remove exit = %d stderr = %s", code, stderr.String())
	}
	raw, err = os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), legacy) {
		t.Fatalf("legacy hook remains after remove: %s", raw)
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
}

func stubSetupSideEffects(t *testing.T) *setupStubState {
	t.Helper()
	state := &setupStubState{}
	oldExec := setupExecCommand
	oldQuickstart := setupRunQuickstart
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
	t.Cleanup(func() {
		setupExecCommand = oldExec
		setupRunQuickstart = oldQuickstart
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

func assertSetupSymlinkTarget(t *testing.T, link, target string, mode os.FileMode, contains string) {
	t.Helper()
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat %s: %v", link, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s mode = %v, want preserved symlink", link, info.Mode())
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target %s: %v", target, err)
	}
	if contains != "" && !strings.Contains(string(raw), contains) {
		t.Fatalf("target %s missing %q:\n%s", target, contains, raw)
	}
	targetInfo, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target %s: %v", target, err)
	}
	if got := targetInfo.Mode().Perm(); got != mode {
		t.Fatalf("target %s mode = %o, want %o", target, got, mode)
	}
}

func assertSetupFileUnchanged(t *testing.T, link, target string, original []byte) {
	t.Helper()
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat %s: %v", link, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s mode = %v, want preserved symlink", link, info.Mode())
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target %s: %v", target, err)
	}
	if !bytes.Equal(raw, original) {
		t.Fatalf("target %s changed:\n%s", target, raw)
	}
}

func assertNoSetupTempFiles(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		matches, err := filepath.Glob(filepath.Join(dir, ".helm-tmp-*"))
		if err != nil {
			t.Fatalf("glob setup temp files in %s: %v", dir, err)
		}
		if len(matches) != 0 {
			t.Fatalf("setup temp files were not cleaned from %s: %#v", dir, matches)
		}
	}
}

func TestSetupCodexProjectTrustPending(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, ".codex"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".codex", "config.toml"),
		[]byte("model = \"gpt-5\"\n"), 0o600); err != nil {
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

func TestSetupNormalizesRelativeSigningSeedFile(t *testing.T) {
	var stderr bytes.Buffer
	opts, code := parseSetupInstallArgs([]string{"claude-code", "--yes", "--data-dir", t.TempDir(), "--signing-seed-file", "rel/seed.hex"}, &stderr)
	if code != 0 {
		t.Fatalf("parse exit = %d stderr=%s", code, stderr.String())
	}
	if !filepath.IsAbs(opts.SigningSeedFile) {
		t.Fatalf("SigningSeedFile = %q, want absolute (relative paths bake a cwd-dependent hook command)", opts.SigningSeedFile)
	}
}

func TestHookCommandKeyIgnoresSigningSeedFileArgument(t *testing.T) {
	base := "'/usr/local/bin/helm-ai-kernel' hook pre-tool --client claude-code --data-dir '/home/op/.helm'"
	withSeed := base + " --signing-seed-file '/home/op/keys/seed.hex'"
	withBareSeed := base + " --signing-seed-file /home/op/keys/seed.hex"

	if hookCommandKey(withSeed) != hookCommandKey(base) {
		t.Fatalf("quoted seed-file arg changes hook identity:\n%q\n%q", hookCommandKey(withSeed), hookCommandKey(base))
	}
	if hookCommandKey(withBareSeed) != hookCommandKey(base) {
		t.Fatalf("bare seed-file arg changes hook identity")
	}
	if hookCommandKey(base) != base {
		t.Fatalf("command without the flag must be unchanged, got %q", hookCommandKey(base))
	}

	// status/remove parity: a hook installed WITH the flag is found by a
	// lookup command built WITHOUT it.
	pre := []any{map[string]any{"hooks": []any{map[string]any{"command": withSeed}}}}
	if !hookCommandPresent(pre, base) {
		t.Fatal("hook installed with seed-file flag not matched by flagless lookup")
	}
}
