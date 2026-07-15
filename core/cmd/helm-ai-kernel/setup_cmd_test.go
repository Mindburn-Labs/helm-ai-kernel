package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
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

func TestSetupCodexProjectDryRunCreatesNoConfigOrLifecycleState(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--dry-run", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("dry-run exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	for _, path := range []string{
		filepath.Join(tmp, ".codex", "config.toml"),
		filepath.Join(tmp, ".codex", "hooks.json"),
		filepath.Join(dataDir, "root.key"),
		filepath.Join(dataDir, "helm.db"),
	} {
		if _, err := os.Stat(path); !errorsIsNotExist(err) {
			t.Fatalf("dry-run created %s: %v", path, err)
		}
	}
}

func TestSetupInstallClaudeWritesHookAndRunsQuickstart(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	claude := writeSetupExecutable(t, filepath.Join(tmp, "claude"))
	t.Setenv(setupClaudeCodeBinaryEnv, claude)
	restore := stubSetupSideEffects(t)

	var stdout, stderr bytes.Buffer
	dataDir := filepath.Join(tmp, "helm")
	code := Run([]string{"helm-ai-kernel", "setup", "claude-code", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	if len(restore.execCalls) != 1 || restore.execCalls[0][0] != claude || !strings.Contains(strings.Join(restore.execCalls[0], " "), " mcp add") {
		t.Fatalf("exec calls = %#v, want %s mcp add", restore.execCalls, claude)
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

func TestSetupCodexProjectJSONReturnsWithoutStartingUnrelatedQuickstart(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	restore := stubSetupSideEffects(t)

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
	if len(restore.quickstartArgs) != 0 {
		t.Fatalf("Codex project setup unexpectedly started a quickstart server: %#v", restore.quickstartArgs)
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
	server := decodeCodexProjectMCP(t, raw)
	if got, want := server.Args, []string{"mcp", "serve", "--transport", "stdio", "--data-dir", dataDir}; !equalSetupStrings(got, want) {
		t.Fatalf("Codex MCP args = %#v, want %#v", got, want)
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

func TestUpsertCodexProjectMCPRefusesOwnedDataDirChange(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, ".codex", "config.toml")
	firstDataDir := filepath.Join(tmp, "helm-first")
	secondDataDir := filepath.Join(tmp, "helm-second")
	if err := upsertCodexProjectMCP(configPath, "/tmp/helm-ai-kernel", firstDataDir); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertCodexProjectMCP(configPath, "/tmp/helm-ai-kernel", secondDataDir); err == nil {
		t.Fatal("upsert unexpectedly replaced a HELM-owned MCP server with a different data-dir")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), "[mcp_servers."+setupMCPServerName+"]"); got != 1 {
		t.Fatalf("HELM MCP table count = %d, want 1:\n%s", got, raw)
	}
	if !bytes.Equal(raw, before) {
		t.Fatalf("data-dir mismatch changed Codex MCP config:\n%s", raw)
	}
	server := decodeCodexProjectMCP(t, raw)
	if got, want := server.Args, []string{"mcp", "serve", "--transport", "stdio", "--data-dir", firstDataDir}; !equalSetupStrings(got, want) {
		t.Fatalf("Codex MCP args = %#v, want %#v", got, want)
	}
}

func TestSetupCodexProjectRefusesChangedOwnedDataDirOnInstallAndRemove(t *testing.T) {
	for _, surface := range []string{"hook", "mcp"} {
		t.Run(surface, func(t *testing.T) {
			tmp := t.TempDir()
			oldWD, _ := os.Getwd()
			if err := os.Chdir(tmp); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chdir(oldWD) })
			stubSetupSideEffects(t)

			dataDir := filepath.Join(tmp, "helm")
			wrongDataDir := filepath.Join(tmp, "user-managed-state")
			args := []string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}
			var stdout, stderr bytes.Buffer
			if code := Run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("initial setup exit = %d stderr=%s", code, stderr.String())
			}

			clientPath := filepath.Join(tmp, ".codex", "config.toml")
			hookPath := filepath.Join(tmp, ".codex", "hooks.json")
			if surface == "hook" {
				raw, err := os.ReadFile(hookPath)
				if err != nil {
					t.Fatal(err)
				}
				mutated := strings.Replace(string(raw), shellQuote(dataDir), shellQuote(wrongDataDir), 1)
				if mutated == string(raw) {
					t.Fatal("test fixture did not change owned hook data-dir")
				}
				if err := os.WriteFile(hookPath, []byte(mutated), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				raw, err := os.ReadFile(clientPath)
				if err != nil {
					t.Fatal(err)
				}
				mutated := strings.Replace(string(raw), strconv.Quote(dataDir), strconv.Quote(wrongDataDir), 1)
				if mutated == string(raw) {
					t.Fatal("test fixture did not change owned MCP data-dir")
				}
				if err := os.WriteFile(clientPath, []byte(mutated), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			clientBefore, err := os.ReadFile(clientPath)
			if err != nil {
				t.Fatal(err)
			}
			hookBefore, err := os.ReadFile(hookPath)
			if err != nil {
				t.Fatal(err)
			}

			stdout.Reset()
			stderr.Reset()
			if code := Run(args, &stdout, &stderr); code != 1 {
				t.Fatalf("setup with changed %s data-dir exit = %d, want 1 stderr=%s", surface, code, stderr.String())
			}
			assertSetupConfigBytesUnchanged(t, clientPath, clientBefore, hookPath, hookBefore)

			stdout.Reset()
			stderr.Reset()
			removeArgs := []string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}
			if code := Run(removeArgs, &stdout, &stderr); code != 1 {
				t.Fatalf("remove with changed %s data-dir exit = %d, want 1 stderr=%s", surface, code, stderr.String())
			}
			assertSetupConfigBytesUnchanged(t, clientPath, clientBefore, hookPath, hookBefore)
		})
	}
}

func TestStrictOwnedSetupHookRequiresExactQuotedDataDir(t *testing.T) {
	dataDir := "/tmp/helm's state"
	command := shellQuote("/tmp/helm-ai-kernel") + " hook pre-tool --client codex --data-dir " + shellQuote(dataDir)
	entry := map[string]any{
		"matcher": setupHookMatcher("codex"),
		"hooks": []any{map[string]any{
			"type":          "command",
			"command":       command,
			"timeout":       float64(30),
			"statusMessage": setupHookOwnershipStatus,
		}},
	}
	if !isStrictOwnedSetupHookEntryForCommand(entry, "codex", command) {
		t.Fatal("exact quoted data-dir was not recognized as owned")
	}
	if isStrictOwnedSetupHookEntryForCommand(entry, "codex", setupHookCommand(setupOptions{Target: "codex", DataDir: "/tmp/other"}, "/tmp/helm-ai-kernel")) {
		t.Fatal("different data-dir was recognized as owned")
	}
	injected := command + " ; echo injected"
	if isStrictOwnedSetupHookEntryForCommand(entry, "codex", injected) {
		t.Fatal("extended shell command was recognized as owned")
	}
}

func TestUpsertCodexProjectMCPRefusesUnownedSameNameServer(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, ".codex", "config.toml")
	original := []byte("[mcp_servers.helm-ai-kernel-governance]\ncommand = \"/usr/local/bin/user-owned-server\"\nargs = [\"serve\"]\n")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := upsertCodexProjectMCP(configPath, "/tmp/helm-ai-kernel", filepath.Join(tmp, "helm")); err == nil {
		t.Fatal("upsert unexpectedly replaced a same-named user-owned MCP server")
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("unowned MCP config changed:\n%s", after)
	}
}

func TestSetupCodexProjectRefusesUnownedSameNameServerWithoutRewritingIt(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	configPath := filepath.Join(tmp, ".codex", "config.toml")
	original := []byte("[mcp_servers.helm-ai-kernel-governance]\ncommand = \"/usr/local/bin/user-owned-server\"\nargs = [\"serve\"]\n")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}

	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("setup exit = %d, want 1 stderr = %s", code, stderr.String())
	}
	after, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, original) || !os.SameFile(before, after) {
		t.Fatalf("refused install rewrote user-owned config:\n%s", raw)
	}
	if _, err := os.Stat(dataDir); !errorsIsNotExist(err) {
		t.Fatalf("refused install created Kernel state: %v", err)
	}
}

func TestSetupCodexProjectRefusesMalformedTOMLWithoutRewritingIt(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	configPath := filepath.Join(tmp, ".codex", "config.toml")
	original := []byte("[mcp_servers.helm-ai-kernel-governance\ncommand = \"/tmp/helm-ai-kernel\"\n")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}

	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("setup exit = %d, want 1 stderr = %s", code, stderr.String())
	}
	after, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, original) || !os.SameFile(before, after) {
		t.Fatalf("malformed Codex TOML was rewritten:\n%s", raw)
	}
	if _, err := os.Stat(dataDir); !errorsIsNotExist(err) {
		t.Fatalf("malformed-config refusal created Kernel state: %v", err)
	}
}

func TestSetupCodexProjectRefusesSymlinkedConfig(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	target := filepath.Join(tmp, "user-owned.toml")
	original := []byte("[mcp_servers.unrelated]\ncommand = \"/tmp/user-server\"\n")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(tmp, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, configPath); err != nil {
		t.Fatal(err)
	}

	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("setup exit = %d, want 1 stderr = %s", code, stderr.String())
	}
	info, err := os.Lstat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("setup replaced a user-owned config symlink: mode=%v", info.Mode())
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, original) {
		t.Fatalf("setup changed symlink target:\n%s", raw)
	}
	if _, err := os.Stat(dataDir); !errorsIsNotExist(err) {
		t.Fatalf("symlink refusal created Kernel state: %v", err)
	}
}

func TestSetupCodexProjectRefusesSymlinkedConfigParent(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	externalDir := filepath.Join(tmp, "external-codex")
	if err := os.MkdirAll(externalDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(externalDir, filepath.Join(tmp, ".codex")); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("setup exit = %d, want 1 stderr = %s", code, stderr.String())
	}
	info, err := os.Lstat(filepath.Join(tmp, ".codex"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("setup replaced a symlinked config parent: mode=%v", info.Mode())
	}
	if _, err := os.Stat(filepath.Join(externalDir, "config.toml")); !errorsIsNotExist(err) {
		t.Fatalf("setup wrote through symlinked config parent: %v", err)
	}
	if _, err := os.Stat(dataDir); !errorsIsNotExist(err) {
		t.Fatalf("symlink-parent refusal created Kernel state: %v", err)
	}
}

func TestSetupCodexProjectRefusesExtendedOwnedMCPConfigWithoutRewrite(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertCodexProjectMCP(summary.ClientConfigPath, summary.BinaryPath, dataDir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	original := append(raw, []byte("\n[mcp_servers."+setupMCPServerName+".env]\nUSER_ADDED = \"keep-me\"\n")...)
	if err := os.WriteFile(summary.ClientConfigPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("setup exit = %d, want 1 stderr = %s", code, stderr.String())
	}
	after, err := os.Stat(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, original) || !os.SameFile(before, after) {
		t.Fatalf("setup rewrote extended HELM MCP config:\n%s", current)
	}
	if !strings.Contains(stderr.String(), "user-managed fields") {
		t.Fatalf("setup did not explain extended MCP refusal: %s", stderr.String())
	}
}

func TestSetupCodexProjectRemoveRefusesExtendedOwnedMCPConfigWithoutCorruption(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertCodexProjectMCP(summary.ClientConfigPath, summary.BinaryPath, dataDir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	original := append(raw, []byte("\n[mcp_servers."+setupMCPServerName+".env]\nUSER_ADDED = \"keep-me\"\n")...)
	if err := os.WriteFile(summary.ClientConfigPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("remove exit = %d, want 1 stderr = %s", code, stderr.String())
	}
	after, err := os.Stat(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, original) || !os.SameFile(before, after) {
		t.Fatalf("remove corrupted extended HELM MCP config:\n%s", current)
	}
	if !strings.Contains(stderr.String(), "user-managed fields") {
		t.Fatalf("remove did not explain extended MCP refusal: %s", stderr.String())
	}
}

func TestSetupCodexProjectLifecycleIsSignedAndDoesNotClaimClientLoad(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	t.Setenv("HELM_RECEIPT_PROFILE", "")
	stubSetupSideEffects(t)

	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("setup exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	var summary setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode setup summary: %v\n%s", err, stdout.String())
	}
	if !summary.MCPConfigured || !summary.HookConfigured || !summary.LocalConfigVerified {
		t.Fatalf("setup did not report exact local config: %#v", summary)
	}
	if summary.Configured || summary.ClientLoadObserved {
		t.Fatalf("setup must not claim an unobserved Codex integration: %#v", summary)
	}
	if !summary.SyntheticDenialVerified || summary.LifecycleReceiptID == "" {
		t.Fatalf("missing verified synthetic denial lifecycle receipt: %#v", summary)
	}
	if summary.LifecycleEvidencePath == "" {
		t.Fatalf("missing retained lifecycle evidence path: %#v", summary)
	}

	db, _, receiptStore, err := setupLiteModeWithDataDir(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	receipt, err := receiptStore.GetByReceiptID(context.Background(), summary.LifecycleReceiptID)
	if err != nil {
		t.Fatalf("read lifecycle receipt: %v", err)
	}
	if receipt.Status != "DENY" || receipt.EffectID != "mcp.tools.call/file_write" || receipt.OutputHash == "" || receipt.ArgsHash == "" {
		t.Fatalf("unexpected install lifecycle receipt: %#v", receipt)
	}
	if got, _ := receipt.Metadata["client_load_observed"].(bool); got {
		t.Fatalf("receipt must not claim a Codex load: %#v", receipt.Metadata)
	}
	signer, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := helmcrypto.NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := verifier.VerifyReceipt(receipt); err != nil || !ok {
		t.Fatalf("lifecycle receipt signature invalid: ok=%v err=%v", ok, err)
	}
	evidence, err := verifySetupLifecycleEvidence(dataDir, receipt)
	if err != nil {
		t.Fatalf("verify retained lifecycle evidence: %v", err)
	}
	if !evidence.Observation.MCPConfigured || !evidence.Observation.HookConfigured || evidence.Observation.ClientLoadObserved || evidence.Observation.KernelDispatchObserved || evidence.Observation.SyntheticDenial == nil || !evidence.Observation.SyntheticDenial.Verified || evidence.Observation.SyntheticDenial.Dispatched {
		t.Fatalf("unexpected signed lifecycle observation: %#v", evidence.Observation)
	}
	for _, mutate := range []func(*contracts.Receipt){
		func(r *contracts.Receipt) { r.ArgsHash = "tampered" },
		func(r *contracts.Receipt) { r.OutputHash = "tampered" },
		func(r *contracts.Receipt) { r.Status = "ALLOW" },
		func(r *contracts.Receipt) { r.PrevHash = "tampered" },
	} {
		tampered := *receipt
		mutate(&tampered)
		if ok, err := verifier.VerifyReceipt(&tampered); err == nil && ok {
			t.Fatalf("tampered signed lifecycle field unexpectedly verified: %#v", tampered)
		}
	}
	if err := os.WriteFile(summary.LifecycleEvidencePath, []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySetupLifecycleEvidence(dataDir, receipt); err == nil {
		t.Fatal("tampered lifecycle evidence unexpectedly verified")
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "install binding evidence") {
		t.Fatalf("tampered install evidence did not block automatic removal: code=%d stderr=%s", code, stderr.String())
	}
	originalEvidence, err := canonicalize.JCS(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(summary.LifecycleEvidencePath, originalEvidence, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "synthetic-denial")); !errorsIsNotExist(err) {
		t.Fatalf("synthetic denial probe directory was retained: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("remove exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	var removal setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &removal); err != nil {
		t.Fatalf("decode removal summary: %v\n%s", err, stdout.String())
	}
	if removal.MCPConfigured || removal.HookConfigured || removal.LocalConfigVerified || removal.Configured {
		t.Fatalf("remove still reports configuration: %#v", removal)
	}
	if removal.ClientLoadObserved {
		t.Fatalf("remove must not claim a client load: %#v", removal)
	}
	if removal.LifecycleReceiptID == "" {
		t.Fatalf("remove did not issue a lifecycle receipt: %#v", removal)
	}
	removeReceipt, err := receiptStore.GetByReceiptID(context.Background(), removal.LifecycleReceiptID)
	if err != nil {
		t.Fatalf("read remove lifecycle receipt: %v", err)
	}
	installChainHash, err := contracts.ReceiptChainHash(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if removeReceipt.Status != "REVOKED" || removeReceipt.PrevHash != installChainHash || removeReceipt.LamportClock != receipt.LamportClock+1 {
		t.Fatalf("unexpected remove lifecycle receipt: %#v", removeReceipt)
	}
	if ok, err := verifier.VerifyReceipt(removeReceipt); err != nil || !ok {
		t.Fatalf("remove lifecycle receipt signature invalid: ok=%v err=%v", ok, err)
	}
}

func TestCodexLifecycleRemovalSurvivesReceiptProfileDrift(t *testing.T) {
	for _, tc := range []struct {
		name           string
		installProfile string
		removeProfile  string
	}{
		{name: "hybrid install classical remove", installProfile: "hybrid", removeProfile: ""},
		{name: "classical install hybrid remove", installProfile: "", removeProfile: "hybrid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := chdirTempDir(t)
			dataDir := filepath.Join(tmp, "helm")
			t.Setenv("HELM_RECEIPT_PROFILE", tc.installProfile)
			var stdout, stderr bytes.Buffer
			if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
				t.Fatalf("install exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
			}
			t.Setenv("HELM_RECEIPT_PROFILE", tc.removeProfile)
			stdout.Reset()
			stderr.Reset()
			if code := Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
				t.Fatalf("remove exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
			}
		})
	}
}

func TestSetupCodexProjectInstallRequiresDurableRecoveryWhenLifecycleReceiptFails(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	clientPath := filepath.Join(tmp, ".codex", "config.toml")
	hookPath := filepath.Join(tmp, ".codex", "hooks.json")
	const userSentinel = "user-config-secret-must-not-enter-journal"
	clientBefore := []byte("[mcp_servers.unrelated]\ncommand = \"/tmp/" + userSentinel + "\"\n")
	hookBefore := []byte(`{"hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"type":"command","command":"echo ` + userSentinel + `","statusMessage":"user"}]}]}}` + "\n")
	if err := os.MkdirAll(filepath.Dir(clientPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientPath, clientBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, hookBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	previousRecord := recordCodexProjectSetupLifecycleFn
	recordCodexProjectSetupLifecycleFn = func(setupOptions, setupSummary, string) (setupLifecycleResult, error) {
		return setupLifecycleResult{}, errors.New("receipt store unavailable")
	}
	t.Cleanup(func() { recordCodexProjectSetupLifecycleFn = previousRecord })

	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("setup exit = %d, want 1 stderr = %s", code, stderr.String())
	}
	journal, err := readSetupRecoveryJournal(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if journal == nil {
		t.Fatal("failed setup did not retain a durable recovery journal")
	}
	journalRaw, err := os.ReadFile(setupRecoveryJournalPath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(journalRaw), userSentinel) {
		t.Fatalf("recovery journal persisted user config bytes: %s", journalRaw)
	}
	if err := serveLocalMCPStdioWithDataDir(strings.NewReader(""), io.Discard, dataDir); err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("pending recovery did not block MCP startup: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("pending recovery status exit = %d stderr=%s", code, stderr.String())
	}
	var pendingStatus setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &pendingStatus); err != nil {
		t.Fatal(err)
	}
	if !pendingStatus.RecoveryRequired {
		t.Fatalf("pending recovery status did not expose recovery_required: %#v", pendingStatus)
	}

	recordCodexProjectSetupLifecycleFn = previousRecord
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("recovery exit = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if pending, err := setupRecoveryRequired(dataDir); err != nil || pending {
		t.Fatalf("recovery journal remained after a completed recovery: pending=%v err=%v", pending, err)
	}
	clientAfter, err := os.ReadFile(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	hookAfter, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(clientAfter), userSentinel) || !strings.Contains(string(hookAfter), userSentinel) || !strings.Contains(string(clientAfter), setupMCPServerName) || !strings.Contains(string(hookAfter), setupHookOwnershipStatus) {
		t.Fatalf("recovery did not preserve user state and complete HELM configuration:\nclient=%s\nhook=%s", clientAfter, hookAfter)
	}
}

func TestSetupCodexProjectRecoveryWithoutReceiptRejectsInvalidProfileBeforeConfigMutation(t *testing.T) {
	tmp := chdirTempDir(t)
	stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")
	previousRecord := recordCodexProjectSetupLifecycleFn
	recordCodexProjectSetupLifecycleFn = func(setupOptions, setupSummary, string) (setupLifecycleResult, error) {
		return setupLifecycleResult{}, errors.New("injected pre-receipt lifecycle failure")
	}
	t.Cleanup(func() { recordCodexProjectSetupLifecycleFn = previousRecord })

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 {
		t.Fatalf("setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if pending, err := setupRecoveryRequired(dataDir); err != nil || !pending {
		t.Fatalf("pre-receipt lifecycle failure did not retain recovery journal: pending=%v err=%v", pending, err)
	}
	for _, path := range []string{filepath.Join(tmp, ".codex", "config.toml"), filepath.Join(tmp, ".codex", "hooks.json")} {
		if err := os.Remove(path); err != nil {
			t.Fatalf("restore recorded before-state %s: %v", path, err)
		}
	}
	recordCodexProjectSetupLifecycleFn = previousRecord
	t.Setenv("HELM_RECEIPT_PROFILE", "invalid-profile")
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "validate receipt profile before resumable config mutation") {
		t.Fatalf("invalid-profile recovery exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	for _, path := range []string{
		filepath.Join(tmp, ".codex", "config.toml"),
		filepath.Join(tmp, ".codex", "hooks.json"),
		filepath.Join(dataDir, "root.key"),
		filepath.Join(dataDir, "root.mldsa65.key"),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("invalid-profile recovery mutated %s: %v", path, err)
		}
	}
	if pending, err := setupRecoveryRequired(dataDir); err != nil || !pending {
		t.Fatalf("invalid-profile recovery did not retain journal: pending=%v err=%v", pending, err)
	}
}

func TestSetupCodexProjectRecoveryDoesNotDuplicateCommittedReceipt(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	previousFinalize := finalizeCodexProjectRecoveryJournal
	finalizeCodexProjectRecoveryJournal = func(string, *setupRecoveryJournal) error {
		return errors.New("injected journal-finalize failure")
	}
	t.Cleanup(func() { finalizeCodexProjectRecoveryJournal = previousFinalize })

	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("setup exit = %d, want 1 stderr=%s", code, stderr.String())
	}
	journal, err := readSetupRecoveryJournal(dataDir)
	if err != nil || journal == nil {
		t.Fatalf("missing journal after finalization failure: journal=%#v err=%v", journal, err)
	}
	db, _, _, err := setupLiteModeWithDataDir(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	var before int
	if err := db.QueryRow(`SELECT COUNT(1) FROM receipts WHERE receipt_id = ?`, journal.LifecycleReceiptID).Scan(&before); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if before != 1 {
		t.Fatalf("prepared receipt count = %d, want 1", before)
	}

	finalizeCodexProjectRecoveryJournal = previousFinalize
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("recovery exit = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	db, _, _, err = setupLiteModeWithDataDir(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var after int
	if err := db.QueryRow(`SELECT COUNT(1) FROM receipts WHERE receipt_id = ?`, journal.LifecycleReceiptID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != 1 {
		t.Fatalf("recovery appended duplicate lifecycle receipt: count=%d", after)
	}
}

func TestSetupCodexProjectRecoveryUsesPersistedReceiptProfileWithoutNewAuthority(t *testing.T) {
	cases := []struct {
		name              string
		initialProfile    string
		recoveryProfile   string
		assertNoMLDSARoot bool
	}{
		{
			name:              "classical_to_hybrid",
			initialProfile:    "classical",
			recoveryProfile:   "hybrid",
			assertNoMLDSARoot: true,
		},
		{
			name:            "hybrid_to_classical",
			initialProfile:  "hybrid",
			recoveryProfile: "classical",
		},
		{
			name:              "classical_to_invalid_profile",
			initialProfile:    "classical",
			recoveryProfile:   "invalid-profile",
			assertNoMLDSARoot: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			oldWD, _ := os.Getwd()
			if err := os.Chdir(tmp); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chdir(oldWD) })
			stubSetupSideEffects(t)
			t.Setenv("HELM_RECEIPT_PROFILE", tc.initialProfile)

			previousFinalize := finalizeCodexProjectRecoveryJournal
			finalizeCodexProjectRecoveryJournal = func(string, *setupRecoveryJournal) error {
				return errors.New("injected journal-finalize failure")
			}
			t.Cleanup(func() { finalizeCodexProjectRecoveryJournal = previousFinalize })

			dataDir := filepath.Join(tmp, "helm")
			var stdout, stderr bytes.Buffer
			if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 {
				t.Fatalf("setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
			}
			journal, err := readSetupRecoveryJournal(dataDir)
			if err != nil || journal == nil {
				t.Fatalf("missing journal after finalization failure: journal=%#v err=%v", journal, err)
			}

			t.Setenv("HELM_RECEIPT_PROFILE", tc.recoveryProfile)
			finalizeCodexProjectRecoveryJournal = previousFinalize
			stdout.Reset()
			stderr.Reset()
			if code := Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
				t.Fatalf("recovery exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
			}
			if pending, err := setupRecoveryRequired(dataDir); err != nil || pending {
				t.Fatalf("recovery journal remained after persisted-profile recovery: pending=%v err=%v", pending, err)
			}
			db, _, _, err := setupLiteModeWithDataDir(context.Background(), dataDir)
			if err != nil {
				t.Fatal(err)
			}
			var count int
			if err := db.QueryRow(`SELECT COUNT(1) FROM receipts WHERE receipt_id = ?`, journal.LifecycleReceiptID).Scan(&count); err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("persisted-profile recovery appended duplicate lifecycle receipt: count=%d", count)
			}
			if tc.assertNoMLDSARoot {
				if _, err := os.Stat(filepath.Join(dataDir, "root.mldsa65.key")); !os.IsNotExist(err) {
					t.Fatalf("recovery generated an ML-DSA key from current profile: %v", err)
				}
			}
		})
	}
}

func TestSetupCodexProjectFailedLifecycleCleansNewSignerAndReceiptStoreState(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)
	t.Setenv("HELM_RECEIPT_PROFILE", "invalid-profile")

	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("setup exit = %d, want 1 stderr = %s", code, stderr.String())
	}
	for _, path := range []string{
		filepath.Join(tmp, ".codex", "config.toml"),
		filepath.Join(tmp, ".codex", "hooks.json"),
		filepath.Join(dataDir, "root.key"),
		filepath.Join(dataDir, "root.pub"),
		filepath.Join(dataDir, "root.mldsa65.key"),
		filepath.Join(dataDir, "helm.db"),
		filepath.Join(dataDir, "helm.db-wal"),
		filepath.Join(dataDir, "helm.db-shm"),
		filepath.Join(dataDir, "helm.db-journal"),
		filepath.Join(dataDir, "autoconfigure", "inventory.json"),
		filepath.Join(dataDir, "autoconfigure", "policy.draft.json"),
		filepath.Join(dataDir, "autoconfigure", "mcp_quarantine_plan.json"),
	} {
		if _, err := os.Stat(path); !errorsIsNotExist(err) {
			t.Fatalf("failed lifecycle left durable state %s: %v", path, err)
		}
	}
}

func TestSetupCodexProjectRetainsRecoveryJournalAfterKnownAbortedReceiptAppend(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	previousPrepared := setupLifecycleStorePrepared
	setupLifecycleStorePrepared = func(db *sql.DB) error {
		_, err := db.Exec(`CREATE TRIGGER helm_setup_abort BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT, 'injected setup receipt failure'); END;`)
		return err
	}
	t.Cleanup(func() { setupLifecycleStorePrepared = previousPrepared })

	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("setup exit = %d, want 1 stderr=%s", code, stderr.String())
	}
	if pending, err := setupRecoveryRequired(dataDir); err != nil || !pending {
		t.Fatalf("known-aborted receipt append did not retain recovery state: pending=%v err=%v", pending, err)
	}
	if err := serveLocalMCPStdioWithDataDir(strings.NewReader(""), io.Discard, dataDir); err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("pending aborted receipt recovery did not block MCP startup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "helm.db")); err != nil {
		t.Fatalf("known-aborted receipt path did not retain its SQLite state for recovery: %v", err)
	}
	journal, err := readSetupRecoveryJournal(dataDir)
	if err != nil || journal == nil {
		t.Fatalf("known-aborted receipt append did not retain its journal: journal=%#v err=%v", journal, err)
	}

	setupLifecycleStorePrepared = previousPrepared
	db, _, _, err := setupLiteModeWithDataDir(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TRIGGER helm_setup_abort`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("known-aborted receipt recovery exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if pending, err := setupRecoveryRequired(dataDir); err != nil || pending {
		t.Fatalf("known-aborted receipt recovery remained pending=%v err=%v", pending, err)
	}
	db, _, _, err = setupLiteModeWithDataDir(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var count int
	if err := db.QueryRow(`SELECT COUNT(1) FROM receipts WHERE receipt_id = ?`, journal.LifecycleReceiptID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("known-aborted receipt recovery appended %d receipts, want 1", count)
	}
}

func TestSetupCodexProjectDryRunAcceptsStandardTempRoot(t *testing.T) {
	for _, root := range []string{"/tmp", "/var/tmp"} {
		t.Run(root, func(t *testing.T) {
			tmp, err := os.MkdirTemp(root, "helm-setup-data-dir-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(tmp) })
			workdir := t.TempDir()
			oldWD, _ := os.Getwd()
			if err := os.Chdir(workdir); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chdir(oldWD) })

			var stdout, stderr bytes.Buffer
			code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--dry-run", "--data-dir", filepath.Join(tmp, "state")}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("setup dry-run under %s exit = %d, want 0 stderr=%s", root, code, stderr.String())
			}
		})
	}
}

func TestNormalizeSetupDataDirRejectsChildSymlinkUnderStandardTempRoot(t *testing.T) {
	tmp, err := os.MkdirTemp("/tmp", "helm-setup-data-dir-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	external := t.TempDir()
	link := filepath.Join(tmp, "user-link")
	if err := os.Symlink(external, link); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizeSetupDataDir(filepath.Join(link, "state")); err == nil {
		t.Fatal("normalizer accepted a descendant symlink below a standard temp root")
	}
}

func TestSetupCodexProjectRejectsDataDirSymlinksBeforeAnyWrite(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dataDirRel string
	}{
		{name: "final", dataDirRel: "state-link"},
		{name: "ancestor", dataDirRel: filepath.Join("state-parent", "helm")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			oldWD, _ := os.Getwd()
			if err := os.Chdir(tmp); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chdir(oldWD) })
			stubSetupSideEffects(t)

			external := filepath.Join(tmp, "external")
			if err := os.MkdirAll(external, 0o750); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(tmp, "state-link")
			if tc.name == "ancestor" {
				link = filepath.Join(tmp, "state-parent")
			}
			if err := os.Symlink(external, link); err != nil {
				t.Fatal(err)
			}

			var stdout, stderr bytes.Buffer
			code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", filepath.Join(tmp, tc.dataDirRel)}, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("setup exit = %d, want 2 stderr = %s", code, stderr.String())
			}
			entries, err := os.ReadDir(external)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("setup wrote through data-dir symlink: %#v", entries)
			}
			if _, err := os.Stat(filepath.Join(tmp, ".codex")); !errorsIsNotExist(err) {
				t.Fatalf("data-dir refusal wrote client config: %v", err)
			}
		})
	}
}

func TestSetupCodexProjectRejectsSymlinkedEnvironmentDataDirRoots(t *testing.T) {
	for _, variable := range []string{"TMPDIR", "HOME"} {
		t.Run(variable, func(t *testing.T) {
			base := t.TempDir()
			workdir := t.TempDir()
			oldWD, _ := os.Getwd()
			if err := os.Chdir(workdir); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chdir(oldWD) })
			stubSetupSideEffects(t)

			external := filepath.Join(base, "external")
			envRootTarget := filepath.Join(external, "real-root")
			if err := os.MkdirAll(envRootTarget, 0o750); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(base, strings.ToLower(variable)+"-link")
			if err := os.Symlink(external, link); err != nil {
				t.Fatal(err)
			}
			// Keep the other environment-derived candidate real but outside the
			// data path, so the test proves the selected symlinked root is not
			// accepted as a traversal boundary.
			envRoot := filepath.Join(link, "real-root")
			if variable == "TMPDIR" {
				t.Setenv("HOME", workdir)
			} else {
				t.Setenv("TMPDIR", workdir)
			}
			t.Setenv(variable, envRoot)

			var stdout, stderr bytes.Buffer
			code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", filepath.Join(envRoot, "helm")}, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("setup exit = %d, want 2 stderr=%s", code, stderr.String())
			}
			if _, err := os.Stat(filepath.Join(envRootTarget, "helm")); !errorsIsNotExist(err) {
				t.Fatalf("setup wrote through %s symlink root: %v", variable, err)
			}
		})
	}
}

func TestSetupCodexProjectRefusesUnmarkedSameShapeMCPServer(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	original := []byte("[mcp_servers." + setupMCPServerName + "]\ncommand = " + strconv.Quote(summary.BinaryPath) + "\nargs = [\"mcp\", \"serve\", \"--transport\", \"stdio\", \"--data-dir\", " + strconv.Quote(dataDir) + "]\n")
	if err := os.MkdirAll(filepath.Dir(summary.ClientConfigPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(summary.ClientConfigPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "no HELM ownership marker") {
		t.Fatalf("setup did not refuse unmarked same-shape MCP: exit=%d stderr=%s", code, stderr.String())
	}
	after, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("setup rewrote unmarked same-shape MCP config:\n%s", after)
	}
	if _, err := os.Stat(dataDir); !errorsIsNotExist(err) {
		t.Fatalf("unmarked MCP refusal created Kernel state: %v", err)
	}
}

func TestSetupCodexProjectRefusesMutatedOwnedHookWithoutRewrite(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertOwnedSetupHookConfig(summary.HookConfigPath, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), opts.Target); err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	raw, err := os.ReadFile(summary.HookConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	hook := root["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	hook["timeout"] = float64(31)
	mutated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	mutated = append(mutated, '\n')
	if err := os.WriteFile(summary.HookConfigPath, mutated, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "user-managed fields") {
		t.Fatalf("setup did not refuse mutated owned hook: exit=%d stderr=%s", code, stderr.String())
	}
	after, err := os.ReadFile(summary.HookConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, mutated) {
		t.Fatalf("setup rewrote user-mutated hook:\n%s", after)
	}
	if _, err := os.Stat(dataDir); !errorsIsNotExist(err) {
		t.Fatalf("mutated hook refusal created Kernel state: %v", err)
	}
}

func TestSetupCodexProjectRefusesMalformedHookJSONWithoutRewrite(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"hooks":"user-owned"}` + "\n"),
		[]byte(`{"hooks":{"PreToolUse":{}}}` + "\n"),
	} {
		t.Run(string(raw), func(t *testing.T) {
			tmp := t.TempDir()
			oldWD, _ := os.Getwd()
			if err := os.Chdir(tmp); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chdir(oldWD) })
			stubSetupSideEffects(t)

			hookPath := filepath.Join(tmp, ".codex", "hooks.json")
			if err := os.MkdirAll(filepath.Dir(hookPath), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(hookPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			dataDir := filepath.Join(tmp, "helm")
			var stdout, stderr bytes.Buffer
			code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), "hook config") {
				t.Fatalf("setup did not reject malformed hook JSON: exit=%d stderr=%s", code, stderr.String())
			}
			after, err := os.ReadFile(hookPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, raw) {
				t.Fatalf("setup rewrote malformed hook config:\n%s", after)
			}
			if _, err := os.Stat(dataDir); !errorsIsNotExist(err) {
				t.Fatalf("malformed hook refusal created Kernel state: %v", err)
			}
		})
	}
}

func TestSetupCodexProjectRefusesInactiveOrMixedProjectHookSource(t *testing.T) {
	for name, config := range map[string][]byte{
		"hooks-disabled": []byte("[features]\nhooks = false\n"),
		"inline-hooks":   []byte("[[hooks.PreToolUse]]\nmatcher = \"^Bash$\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"echo user-owned\"\n"),
	} {
		t.Run(name, func(t *testing.T) {
			tmp := t.TempDir()
			oldWD, _ := os.Getwd()
			if err := os.Chdir(tmp); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chdir(oldWD) })
			stubSetupSideEffects(t)

			configPath := filepath.Join(tmp, ".codex", "config.toml")
			if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, config, 0o600); err != nil {
				t.Fatal(err)
			}
			dataDir := filepath.Join(tmp, "helm")
			var stdout, stderr bytes.Buffer
			code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("setup exit = %d, want 1 stderr=%s", code, stderr.String())
			}
			after, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, config) {
				t.Fatalf("setup rewrote %s config:\n%s", name, after)
			}
			if _, err := os.Stat(filepath.Join(tmp, ".codex", "hooks.json")); !errorsIsNotExist(err) {
				t.Fatalf("setup wrote hooks.json beside %s config: %v", name, err)
			}
			if _, err := os.Stat(dataDir); !errorsIsNotExist(err) {
				t.Fatalf("%s refusal created Kernel state: %v", name, err)
			}
		})
	}
}

func TestCodexProjectTransactionRepeatsHookSourceChecks(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	opts := setupOptions{Target: "codex", Scope: "project", DataDir: filepath.Join(tmp, "helm")}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightCodexProjectSetup(opts, summary); err != nil {
		t.Fatalf("empty project preflight: %v", err)
	}
	inline := []byte("[[hooks.PreToolUse]]\nmatcher = \"^Bash$\"\n")
	if err := os.MkdirAll(filepath.Dir(summary.ClientConfigPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(summary.ClientConfigPath, inline, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCodexProjectRecoveryInstall(opts, summary); err == nil {
		t.Fatal("journaled install preparation accepted inline hook config written after preflight")
	}
	afterInstall, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterInstall, inline) {
		t.Fatalf("install rewrote post-preflight inline config:\n%s", afterInstall)
	}

	// Removal must make the same decision before it deletes either owned file.
	if err := os.Remove(summary.ClientConfigPath); err != nil {
		t.Fatal(err)
	}
	if err := upsertCodexProjectMCP(summary.ClientConfigPath, summary.BinaryPath, opts.DataDir); err != nil {
		t.Fatal(err)
	}
	if err := upsertOwnedSetupHookConfig(summary.HookConfigPath, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), opts.Target); err != nil {
		t.Fatal(err)
	}
	clientBefore, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	clientBefore = append(clientBefore, inline...)
	if err := os.WriteFile(summary.ClientConfigPath, clientBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	hookBefore, err := os.ReadFile(summary.HookConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCodexProjectRecoveryRemove(opts, summary); err == nil {
		t.Fatal("journaled removal preparation accepted inline hook config")
	}
	clientAfter, _ := os.ReadFile(summary.ClientConfigPath)
	hookAfter, _ := os.ReadFile(summary.HookConfigPath)
	if !bytes.Equal(clientAfter, clientBefore) || !bytes.Equal(hookAfter, hookBefore) {
		t.Fatalf("remove mutated config across mixed hook sources:\nclient=%s\nhook=%s", clientAfter, hookAfter)
	}
}

func TestCodexProjectConfigTransactionRefusesConcurrentPreWriteChange(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	opts := setupOptions{Target: "codex", Scope: "project", DataDir: filepath.Join(tmp, "helm")}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := beginCodexProjectConfigTransaction(summary)
	if err != nil {
		t.Fatal(err)
	}
	userConfig := []byte("[mcp_servers.user]\ncommand = \"echo\"\n")
	if err := os.MkdirAll(filepath.Dir(summary.ClientConfigPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(summary.ClientConfigPath, userConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	next, err := buildUpsertCodexProjectMCPState(tx.clientBefore(), summary.BinaryPath, opts.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.replaceClientState(next); err == nil {
		t.Fatal("transaction overwrote a config changed after its snapshot")
	}
	after, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, userConfig) {
		t.Fatalf("transaction overwrote concurrent pre-write config:\n%s", after)
	}
}

func TestSetupCodexProjectRecoveryRefusesToOverwriteConcurrentConfigChange(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	dataDir := filepath.Join(tmp, "helm")
	previousRecord := recordCodexProjectSetupLifecycleFn
	recordCodexProjectSetupLifecycleFn = func(_ setupOptions, summary setupSummary, _ string) (setupLifecycleResult, error) {
		if err := os.WriteFile(summary.ClientConfigPath, []byte("# user changed this after HELM wrote it\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return setupLifecycleResult{}, errors.New("receipt store unavailable")
	}
	t.Cleanup(func() { recordCodexProjectSetupLifecycleFn = previousRecord })

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("setup exit = %d, want 1 stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "local recovery is required") {
		t.Fatalf("setup did not report retained recovery: %s", stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(tmp, ".codex", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "# user changed this after HELM wrote it\n" {
		t.Fatalf("setup overwrote concurrent user config:\n%s", raw)
	}
	if pending, err := setupRecoveryRequired(dataDir); err != nil || !pending {
		t.Fatalf("concurrent change did not retain recovery journal: pending=%v err=%v", pending, err)
	}

	recordCodexProjectSetupLifecycleFn = previousRecord
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "conflict") {
		t.Fatalf("recovery did not refuse concurrent user config: code=%d stderr=%s", code, stderr.String())
	}
	raw, err = os.ReadFile(filepath.Join(tmp, ".codex", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "# user changed this after HELM wrote it\n" {
		t.Fatalf("recovery overwrote concurrent user config:\n%s", raw)
	}
}

func TestSetupCodexProjectRemoveRequiresRecoveryWhenLifecycleReceiptFails(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	stubSetupSideEffects(t)

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("initial setup exit = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	previousRecord := recordCodexProjectSetupLifecycleFn
	recordCodexProjectSetupLifecycleFn = func(setupOptions, setupSummary, string) (setupLifecycleResult, error) {
		return setupLifecycleResult{}, errors.New("receipt store unavailable")
	}
	t.Cleanup(func() { recordCodexProjectSetupLifecycleFn = previousRecord })

	stdout.Reset()
	stderr.Reset()
	code := Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("remove exit = %d, want 1 stderr = %s", code, stderr.String())
	}
	if pending, err := setupRecoveryRequired(dataDir); err != nil || !pending {
		t.Fatalf("failed revoke did not retain recovery journal: pending=%v err=%v", pending, err)
	}

	recordCodexProjectSetupLifecycleFn = previousRecord
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("remove recovery exit = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if pending, err := setupRecoveryRequired(dataDir); err != nil || pending {
		t.Fatalf("remove recovery journal remained: pending=%v err=%v", pending, err)
	}
	clientAfter, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	hookAfter, err := os.ReadFile(summary.HookConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(clientAfter), setupMCPServerName) || strings.Contains(string(hookAfter), setupHookOwnershipStatus) {
		t.Fatalf("remove recovery left owned config:\nclient=%s\nhook=%s", clientAfter, hookAfter)
	}
}

func TestSetupCodexProjectRemoveNoOpDoesNotCreateLifecycleState(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	dataDir := filepath.Join(tmp, "helm")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("no-op remove exit = %d stderr = %s", code, stderr.String())
	}
	var summary setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.LifecycleReceiptID != "" || summary.LifecycleEvidencePath != "" {
		t.Fatalf("no-op remove unexpectedly issued lifecycle evidence: %#v", summary)
	}
	for _, stateFile := range []string{filepath.Join(dataDir, "root.key"), filepath.Join(dataDir, "helm.db")} {
		if _, err := os.Stat(stateFile); !errorsIsNotExist(err) {
			t.Fatalf("no-op remove created local state %s: %v", stateFile, err)
		}
	}
}

func TestSetupCodexProjectRemovePartialMCPDoesNotCreateEmptyHookConfig(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertCodexProjectMCP(summary.ClientConfigPath, summary.BinaryPath, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(summary.HookConfigPath); !errorsIsNotExist(err) {
		t.Fatalf("fixture unexpectedly has a hook config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "no prior HELM install binding") {
		t.Fatalf("unproven partial config removal must fail closed: code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(summary.HookConfigPath); !errorsIsNotExist(err) {
		t.Fatalf("remove created an empty hook config: %v", err)
	}
	clientAfter, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil || !strings.Contains(string(clientAfter), setupMCPServerName) {
		t.Fatalf("unproven partial config was changed: %q err=%v", clientAfter, err)
	}
}

func TestSetupCodexProjectRemoveDryRunReportsCurrentConfigWithoutState(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertCodexProjectMCP(summary.ClientConfigPath, summary.BinaryPath, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := upsertOwnedSetupHookConfig(summary.HookConfigPath, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), opts.Target); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--dry-run", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("remove dry-run exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	var dryRun setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &dryRun); err != nil {
		t.Fatal(err)
	}
	if !dryRun.MCPConfigured || !dryRun.HookConfigured || !dryRun.LocalConfigVerified || dryRun.Configured {
		t.Fatalf("remove dry-run did not distinguish local config from client integration: %#v", dryRun)
	}
	for _, stateFile := range []string{filepath.Join(dataDir, "root.key"), filepath.Join(dataDir, "helm.db")} {
		if _, err := os.Stat(stateFile); !errorsIsNotExist(err) {
			t.Fatalf("remove dry-run created local state %s: %v", stateFile, err)
		}
	}
}

func TestSetupCodexProjectRemovePreservesUnownedSameNameMCPServer(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	original := []byte("[mcp_servers.helm-ai-kernel-governance]\ncommand = \"/usr/local/bin/user-owned-server\"\nargs = [\"serve\"]\n")
	if err := os.MkdirAll(filepath.Dir(summary.ClientConfigPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(summary.ClientConfigPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := upsertOwnedSetupHookConfig(summary.HookConfigPath, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), opts.Target); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "not a proven HELM installation") {
		t.Fatalf("remove must fail closed across ambiguous MCP/hook ownership: code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	after, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("remove changed a same-named user-owned MCP server:\n%s", after)
	}
	rawHook, err := os.ReadFile(summary.HookConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawHook), setupHookOwnershipStatus) {
		t.Fatalf("ambiguous removal changed the hook:\n%s", rawHook)
	}
}

func TestSetupStatusReportsConfiguredNotClientLoadedWithoutCreatingState(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertCodexProjectMCP(summary.ClientConfigPath, summary.BinaryPath, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := upsertOwnedSetupHookConfig(summary.HookConfigPath, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), opts.Target); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("status exit = %d, want 1 stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	var status setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("decode status summary: %v\n%s", err, stdout.String())
	}
	if !status.MCPConfigured || !status.HookConfigured || !status.LocalConfigVerified {
		t.Fatalf("status did not report exact local config: %#v", status)
	}
	if status.Configured || status.ClientLoadObserved {
		t.Fatalf("status must not turn config presence into a Codex integration claim: %#v", status)
	}
	for _, stateFile := range []string{filepath.Join(dataDir, "root.key"), filepath.Join(dataDir, "helm.db")} {
		if _, err := os.Stat(stateFile); !errorsIsNotExist(err) {
			t.Fatalf("status created local state %s: %v", stateFile, err)
		}
	}
}

func TestSetupStatusRefusesToCallExtendedCodexMCPConfigExact(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertCodexProjectMCP(summary.ClientConfigPath, summary.BinaryPath, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := upsertOwnedSetupHookConfig(summary.HookConfigPath, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), opts.Target); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte("\n[mcp_servers."+setupMCPServerName+".env]\nUSER_ADDED = \"keep-me\"\n")...)
	if err := os.WriteFile(summary.ClientConfigPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("status exit = %d, want 1 stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	var status setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.MCPConfigured || !status.HookConfigured || status.LocalConfigVerified || status.Configured {
		t.Fatalf("extended MCP table was reported as exact local configuration: %#v", status)
	}
}

func TestSetupStatusRefusesToCallWrongCodexHookMatcherExact(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertCodexProjectMCP(summary.ClientConfigPath, summary.BinaryPath, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := upsertOwnedSetupHookConfig(summary.HookConfigPath, "^Bash$", setupHookCommand(opts, summary.BinaryPath), opts.Target); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("status exit = %d, want 1 stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	var status setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.MCPConfigured || status.HookConfigured || status.LocalConfigVerified || status.Configured {
		t.Fatalf("wrong hook matcher was reported as exact local configuration: %#v", status)
	}
}

func TestRemoveSetupHookRevokesStaleOwnedCodexCommand(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	opts := setupOptions{Target: "codex", Scope: "project", DataDir: filepath.Join(tmp, "helm")}
	staleCommand := shellQuote("/old/helm-ai-kernel") + " hook pre-tool --client codex --data-dir " + shellQuote(opts.DataDir)
	hookPath := setupHookConfigPath(opts)
	if err := upsertOwnedSetupHookConfig(hookPath, setupHookMatcher(opts.Target), staleCommand, opts.Target); err != nil {
		t.Fatal(err)
	}
	if err := removeSetupHook(opts, "/new/helm-ai-kernel"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hook pre-tool --client codex --data-dir") {
		t.Fatalf("stale owned Codex hook survived removal:\n%s", raw)
	}
}

func TestInstallSetupHookReplacesStaleOwnedEntryWithoutRemovingUserHook(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	opts := setupOptions{Target: "codex", Scope: "project", DataDir: filepath.Join(tmp, "helm")}
	hookPath := setupHookConfigPath(opts)
	if err := writeJSONObject(hookPath, map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{
		"matcher": "^Bash$",
		"hooks": []any{map[string]any{
			"type":          "command",
			"command":       "echo user-owned",
			"timeout":       float64(30),
			"statusMessage": "user-owned",
		}},
	}}}}); err != nil {
		t.Fatal(err)
	}
	staleCommand := setupHookCommand(opts, "/old/helm-ai-kernel")
	if err := upsertOwnedSetupHookConfig(hookPath, setupHookMatcher(opts.Target), staleCommand, opts.Target); err != nil {
		t.Fatal(err)
	}
	if err := installSetupHook(opts, "/new/helm-ai-kernel"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), setupHookOwnershipStatus) != 1 {
		t.Fatalf("owned hook was duplicated instead of replaced:\n%s", raw)
	}
	if strings.Contains(string(raw), "/old/helm-ai-kernel") || !strings.Contains(string(raw), "/new/helm-ai-kernel") {
		t.Fatalf("owned hook did not migrate to current binary:\n%s", raw)
	}
	if !strings.Contains(string(raw), "echo user-owned") {
		t.Fatalf("updating HELM hook removed user hook:\n%s", raw)
	}
}

func TestInstallSetupHookRefusesToReplaceUnownedMatchingCommand(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	opts := setupOptions{Target: "codex", Scope: "project", DataDir: filepath.Join(tmp, "helm")}
	hookPath := setupHookConfigPath(opts)
	command := setupHookCommand(opts, "/tmp/helm-ai-kernel")
	original := []byte(`{"hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"type":"command","command":` + strconv.Quote(command) + `,"statusMessage":"user-owned"}]}]}}` + "\n")
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installSetupHook(opts, "/tmp/helm-ai-kernel"); err == nil {
		t.Fatal("install unexpectedly replaced an unowned matching hook")
	}
	after, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("unowned matching hook changed:\n%s", after)
	}
}

func TestSetupStatusRejectsWrongCodexDataDirInsteadOfSubstringMatch(t *testing.T) {
	tmp := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	dataDir := filepath.Join(tmp, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertCodexProjectMCP(summary.ClientConfigPath, summary.BinaryPath, filepath.Join(tmp, "wrong-state")); err != nil {
		t.Fatal(err)
	}
	if err := upsertOwnedSetupHookConfig(summary.HookConfigPath, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), opts.Target); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("status exit = %d, want 1 stderr = %s", code, stderr.String())
	}
	var status setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.MCPConfigured || !status.HookConfigured || status.LocalConfigVerified || status.Configured {
		t.Fatalf("wrong data-dir was reported as configured: %#v", status)
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

func decodeCodexProjectMCP(t *testing.T, raw []byte) struct {
	Command string   `toml:"command"`
	Args    []string `toml:"args"`
} {
	t.Helper()
	var config struct {
		MCPServers map[string]struct {
			Command string   `toml:"command"`
			Args    []string `toml:"args"`
		} `toml:"mcp_servers"`
	}
	if _, err := toml.Decode(string(raw), &config); err != nil {
		t.Fatalf("decode Codex TOML: %v\n%s", err, raw)
	}
	server, ok := config.MCPServers[setupMCPServerName]
	if !ok {
		t.Fatalf("Codex TOML has no %q server: %#v", setupMCPServerName, config.MCPServers)
	}
	return server
}

func equalSetupStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func assertSetupConfigBytesUnchanged(t *testing.T, clientPath string, clientWant []byte, hookPath string, hookWant []byte) {
	t.Helper()
	clientGot, err := os.ReadFile(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	hookGot, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientGot, clientWant) || !bytes.Equal(hookGot, hookWant) {
		t.Fatalf("setup changed config despite ownership conflict:\nclient=%s\nhook=%s", clientGot, hookGot)
	}
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
