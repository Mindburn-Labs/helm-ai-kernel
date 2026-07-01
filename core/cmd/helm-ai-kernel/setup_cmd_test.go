package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	var stdout, stderr bytes.Buffer
	dataDir := filepath.Join(tmp, "helm")
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
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
}

func TestSetupCodexProjectRemoveUndoLocalConfig(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	restore := stubSetupSideEffects(t)

	var stdout, stderr bytes.Buffer
	dataDir := filepath.Join(tmp, "helm")
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	if len(restore.execCalls) != 0 {
		t.Fatalf("codex project setup should write config directly, exec calls = %#v", restore.execCalls)
	}
	codexConfig := filepath.Join(tmp, ".codex", "config.toml")
	raw, err := os.ReadFile(codexConfig)
	if err != nil {
		t.Fatalf("read codex config: %v", err)
	}
	if !strings.Contains(string(raw), "[mcp_servers.helm-ai-kernel-governance]") {
		t.Fatalf("codex config missing MCP table:\n%s", string(raw))
	}
	hookConfig := filepath.Join(tmp, ".codex", "hooks.json")
	raw, err = os.ReadFile(hookConfig)
	if err != nil {
		t.Fatalf("read hook config: %v", err)
	}
	if !strings.Contains(string(raw), "hook pre-tool --client codex") {
		t.Fatalf("codex hook config missing command:\n%s", string(raw))
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("remove exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	raw, err = os.ReadFile(codexConfig)
	if err != nil {
		t.Fatalf("read codex config after remove: %v", err)
	}
	if strings.Contains(string(raw), "helm-ai-kernel-governance") {
		t.Fatalf("codex config still contains HELM server:\n%s", string(raw))
	}
	raw, err = os.ReadFile(hookConfig)
	if err != nil {
		t.Fatalf("read hook config after remove: %v", err)
	}
	if strings.Contains(string(raw), "hook pre-tool --client codex") {
		t.Fatalf("hook config still contains HELM command:\n%s", string(raw))
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
	quickstartArgs []string
}

func stubSetupSideEffects(t *testing.T) *setupStubState {
	t.Helper()
	state := &setupStubState{}
	oldExec := setupExecCommand
	oldQuickstart := setupRunQuickstart
	setupExecCommand = func(name string, args ...string) error {
		call := append([]string{name}, args...)
		state.execCalls = append(state.execCalls, call)
		return nil
	}
	setupRunQuickstart = func(args []string, stdout, stderr io.Writer) int {
		state.quickstartArgs = append([]string{}, args...)
		_, _ = io.WriteString(stdout, "quickstart ready\n")
		return 0
	}
	t.Cleanup(func() {
		setupExecCommand = oldExec
		setupRunQuickstart = oldQuickstart
	})
	return state
}

func containsSetupString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
