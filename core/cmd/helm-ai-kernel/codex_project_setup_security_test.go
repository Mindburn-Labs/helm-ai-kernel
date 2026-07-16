package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCodexProjectSetupRejectsEmptyAndRootWorkspace(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	for _, args := range [][]string{
		{"setup", "codex", "--scope", "project", "--workspace=", "--dry-run", "--json", "--data-dir", dataDir},
		{"setup", "codex", "--scope", "project", "--workspace", string(filepath.Separator), "--dry-run", "--json", "--data-dir", dataDir},
	} {
		var stdout, stderr bytes.Buffer
		code := Run(append([]string{"helm-ai-kernel"}, args...), &stdout, &stderr)
		if code != 2 {
			t.Fatalf("%q exit=%d stderr=%s", strings.Join(args, " "), code, stderr.String())
		}
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("invalid workspace created data dir: %v", err)
	}
}

func TestClaudeProjectScopeKeepsCallerWorkingDirectory(t *testing.T) {
	workspace := t.TempDir()
	t.Chdir(workspace)
	dataDir := filepath.Join(workspace, "data")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "claude-code", "--scope", "project", "--dry-run", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Claude project dry-run exit=%d stderr=%s", code, stderr.String())
	}
	var summary setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.ClientConfigPath != ".mcp.json" || summary.HookConfigPath != filepath.Join(".claude", "settings.json") {
		t.Fatalf("Claude project paths = %#v", summary)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "claude-code", "--scope", "project", "--workspace", workspace, "--dry-run", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "only for Codex") {
		t.Fatalf("Claude project workspace override exit=%d stderr=%s", code, stderr.String())
	}
}

func TestCodexProjectSetupRejectsSymlinkedConfigPathsWithoutExternalMutation(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, workspace, external string) (map[string][]byte, map[string]string)
	}{
		{
			name: "dot-codex-directory",
			setup: func(t *testing.T, workspace, external string) (map[string][]byte, map[string]string) {
				t.Helper()
				config := []byte("model = \"external\"\n")
				hooks := []byte("{\"hooks\":{\"PreToolUse\":[]}}\n")
				mustWriteSetupFile(t, filepath.Join(external, "config.toml"), config)
				mustWriteSetupFile(t, filepath.Join(external, "hooks.json"), hooks)
				if err := os.Symlink(external, filepath.Join(workspace, ".codex")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				return map[string][]byte{
					filepath.Join(external, "config.toml"): config,
					filepath.Join(external, "hooks.json"):  hooks,
				}, nil
			},
		},
		{
			name: "config-file",
			setup: func(t *testing.T, workspace, external string) (map[string][]byte, map[string]string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Join(workspace, ".codex"), 0o700); err != nil {
					t.Fatal(err)
				}
				config := []byte("model = \"external\"\n")
				target := filepath.Join(external, "config.toml")
				mustWriteSetupFile(t, target, config)
				if err := os.Symlink(target, filepath.Join(workspace, ".codex", "config.toml")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				return map[string][]byte{target: config}, map[string]string{filepath.Join(workspace, ".codex", "hooks.json"): ""}
			},
		},
		{
			name: "hooks-file-preflight",
			setup: func(t *testing.T, workspace, external string) (map[string][]byte, map[string]string) {
				t.Helper()
				configPath := filepath.Join(workspace, ".codex", "config.toml")
				config := []byte("model = \"inside\"\n")
				mustWriteSetupFile(t, configPath, config)
				hooks := []byte("{\"hooks\":{\"PreToolUse\":[]}}\n")
				target := filepath.Join(external, "hooks.json")
				mustWriteSetupFile(t, target, hooks)
				if err := os.Symlink(target, filepath.Join(workspace, ".codex", "hooks.json")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				return map[string][]byte{configPath: config, target: hooks}, nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspace := filepath.Join(t.TempDir(), "workspace")
			external := filepath.Join(t.TempDir(), "external")
			if err := os.MkdirAll(workspace, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(external, 0o750); err != nil {
				t.Fatal(err)
			}
			expected, absent := test.setup(t, workspace, external)
			code, _, _, stderr := runCodexProjectSetupCommand(t, []string{
				"setup", "codex", "--scope", "project", "--workspace", workspace,
				"--data-dir", filepath.Join(t.TempDir(), "data"), "--no-quickstart", "--yes",
			})
			if code != 1 || !strings.Contains(stderr, "symlinked project .codex") {
				t.Fatalf("symlinked project setup exit=%d stderr=%s", code, stderr)
			}
			for path, want := range expected {
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read %s: %v", path, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("external or preflight file changed at %s:\n%s", path, got)
				}
			}
			for path := range absent {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("unexpected file at %s: %v", path, err)
				}
			}
		})
	}
}

func TestCodexProjectSetupPreflightsIncompatibleHooksWithoutPartialMutation(t *testing.T) {
	for _, hooks := range []string{
		`{"hooks":"wrong-type"}` + "\n",
		`{"hooks":{"PreToolUse":{}}}` + "\n",
	} {
		t.Run(hooks, func(t *testing.T) {
			workspace := filepath.Join(t.TempDir(), "workspace")
			configPath := filepath.Join(workspace, ".codex", "config.toml")
			hooksPath := filepath.Join(workspace, ".codex", "hooks.json")
			config := []byte("model = \"preserve\"\n")
			mustWriteSetupFile(t, configPath, config)
			mustWriteSetupFile(t, hooksPath, []byte(hooks))
			dataDir := filepath.Join(t.TempDir(), "data")

			for _, args := range [][]string{
				{"setup", "codex", "--scope", "project", "--workspace", workspace, "--data-dir", dataDir, "--no-quickstart", "--yes"},
				{"setup", "remove", "codex", "--scope", "project", "--workspace", workspace, "--data-dir", dataDir, "--no-quickstart", "--yes"},
			} {
				code, _, _, stderr := runCodexProjectSetupCommand(t, args)
				if code != 1 || !strings.Contains(stderr, "Codex hooks") {
					t.Fatalf("%q exit=%d stderr=%s", strings.Join(args, " "), code, stderr)
				}
				assertSetupFileBytes(t, configPath, config)
				assertSetupFileBytes(t, hooksPath, []byte(hooks))
			}
		})
	}
}

func TestCodexProjectSetupReplacesQuotedNestedOwnedTOMLTables(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	dataDir := filepath.Join(t.TempDir(), "data")
	configPath := filepath.Join(workspace, ".codex", "config.toml")
	hooksPath := filepath.Join(workspace, ".codex", "hooks.json")
	config := "model = \"gpt-5\"\n\n" +
		"[mcp_servers.\"helm-ai-kernel-governance\"] # old owned table\n" +
		"command = \"/old/helm-ai-kernel\"\nargs = [\"mcp\", \"serve\", \"--transport\", \"stdio\", \"--data-dir\", " + strconv.Quote(dataDir) + "]\n\n" +
		"[mcp_servers.\"helm-ai-kernel-governance\".env] # old owned nested table\n" +
		"LEGACY = \"remove-me\"\n\n" +
		"[mcp_servers.other]\ncommand = \"other\"\nargs = [\"serve\"]\n"
	mustWriteSetupFile(t, configPath, []byte(config))
	mustWriteSetupFile(t, hooksPath, []byte(`{"hooks":{"PreToolUse":[]}}`+"\n"))
	apply := []string{"setup", "codex", "--scope", "project", "--workspace", workspace, "--data-dir", dataDir, "--no-quickstart", "--yes"}
	if code, _, _, stderr := runCodexProjectSetupCommand(t, apply); code != 0 {
		t.Fatalf("quoted-table apply exit=%d stderr=%s", code, stderr)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "LEGACY") || strings.Count(string(raw), setupMCPServerName) != 1 || !strings.Contains(string(raw), "[mcp_servers.other]") {
		t.Fatalf("owned TOML replacement was not scoped correctly:\n%s", raw)
	}
	remove := []string{"setup", "remove", "codex", "--scope", "project", "--workspace", workspace, "--data-dir", dataDir, "--no-quickstart", "--yes"}
	if code, _, _, stderr := runCodexProjectSetupCommand(t, remove); code != 0 {
		t.Fatalf("quoted-table remove exit=%d stderr=%s", code, stderr)
	}
	raw, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), setupMCPServerName) || !strings.Contains(string(raw), "[mcp_servers.other]") {
		t.Fatalf("owned TOML removal was not scoped correctly:\n%s", raw)
	}
}

func TestCodexProjectStatusBindsExactBinaryAndReportsFalseJSONFields(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	dataDir := filepath.Join(t.TempDir(), "data")
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, err = filepath.Abs(bin)
	if err != nil {
		t.Fatal(err)
	}
	opts := setupOptions{Target: "codex", Scope: "project", Workspace: workspace, DataDir: dataDir}
	config := "[mcp_servers." + setupMCPServerName + "]\ncommand = \"/not/the/current/binary\"\nargs = [\"mcp\", \"serve\", \"--transport\", \"stdio\", \"--data-dir\", " + strconv.Quote(dataDir) + "]\n"
	mustWriteSetupFile(t, filepath.Join(workspace, ".codex", "config.toml"), []byte(config))
	hooks := map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{
		"matcher": setupHookMatcher("codex"),
		"hooks": []any{map[string]any{
			"type":          "command",
			"command":       setupHookCommand(opts, bin),
			"timeout":       float64(30),
			"statusMessage": "Checking HELM policy",
		}},
	}}}}
	rawHooks, err := json.Marshal(hooks)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteSetupFile(t, filepath.Join(workspace, ".codex", "hooks.json"), append(rawHooks, '\n'))

	code, summary, raw, stderr := runCodexProjectSetupCommand(t, []string{
		"setup", "status", "codex", "--scope", "project", "--workspace", workspace,
		"--data-dir", dataDir, "--no-quickstart", "--json",
	})
	if code != 1 || stderr != "" || summary.MCPInstalled || !summary.HookInstalled {
		t.Fatalf("exact-binding status exit=%d summary=%#v stderr=%s", code, summary, stderr)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]bool{"mcp_installed": false, "hook_installed": true} {
		value, ok := fields[field]
		if !ok {
			t.Fatalf("status JSON omitted %s: %s", field, raw)
		}
		var got bool
		if err := json.Unmarshal(value, &got); err != nil || got != want {
			t.Fatalf("status JSON %s=%s, want %t err=%v", field, value, want, err)
		}
	}
}

func TestCodexProjectEmptyStatusAndRemovePreviewReportExplicitFalseState(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(t.TempDir(), "data")
	for _, test := range []struct {
		args       []string
		code       int
		operation  string
		wantAction string
	}{
		{
			args:       []string{"setup", "status", "codex", "--scope", "project", "--workspace", workspace, "--data-dir", dataDir, "--no-quickstart", "--json"},
			code:       1,
			operation:  "status",
			wantAction: "inspect the existing local integration without writing files",
		},
		{
			args:       []string{"setup", "remove", "codex", "--scope", "project", "--workspace", workspace, "--data-dir", dataDir, "--no-quickstart", "--dry-run", "--json"},
			code:       0,
			operation:  "preview_remove",
			wantAction: "remove the HELM MCP server and PreToolUse hook from the selected scope",
		},
	} {
		code, summary, raw, stderr := runCodexProjectSetupCommand(t, test.args)
		if code != test.code || stderr != "" || summary.Operation != test.operation || summary.MCPInstalled || summary.HookInstalled || !equalSetupStrings(summary.PlannedActions, []string{test.wantAction}) {
			t.Fatalf("%q exit=%d summary=%#v stderr=%s", strings.Join(test.args, " "), code, summary, stderr)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"mcp_installed", "hook_installed"} {
			value, ok := fields[field]
			if !ok || string(value) != "false" {
				t.Fatalf("%s summary omitted explicit false %s: %s", test.operation, field, raw)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(workspace, ".codex")); !os.IsNotExist(err) {
		t.Fatalf("read-only status/remove preview created .codex: %v", err)
	}
}

func TestCodexProjectSetupPreservesNonHELMNamedMCPServer(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	dataDir := filepath.Join(t.TempDir(), "data")
	configPath := filepath.Join(workspace, ".codex", "config.toml")
	config := []byte("[mcp_servers." + setupMCPServerName + "]\ncommand = \"/usr/local/bin/helm-ai-kernel-malware\"\nargs = [\"mcp\", \"serve\", \"--transport\", \"stdio\", \"--data-dir\", " + strconv.Quote(dataDir) + "]\n")
	mustWriteSetupFile(t, configPath, config)
	mustWriteSetupFile(t, filepath.Join(workspace, ".codex", "hooks.json"), []byte(`{"hooks":{"PreToolUse":[]}}`+"\n"))
	apply := []string{"setup", "codex", "--scope", "project", "--workspace", workspace, "--data-dir", dataDir, "--no-quickstart", "--yes"}
	if code, _, _, stderr := runCodexProjectSetupCommand(t, apply); code != 1 || !strings.Contains(stderr, "refuse to replace non-HELM") {
		t.Fatalf("unowned named MCP apply exit=%d stderr=%s", code, stderr)
	}
	assertSetupFileBytes(t, configPath, config)
	remove := []string{"setup", "remove", "codex", "--scope", "project", "--workspace", workspace, "--data-dir", dataDir, "--no-quickstart", "--yes"}
	if code, _, _, stderr := runCodexProjectSetupCommand(t, remove); code != 0 || stderr != "" {
		t.Fatalf("unowned named MCP remove exit=%d stderr=%s", code, stderr)
	}
	assertSetupFileBytes(t, configPath, config)
}

func TestCodexProjectSetupMigratesOwnedHookOnBinaryRelocation(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	dataDir := filepath.Join(t.TempDir(), "data")
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, err = filepath.Abs(bin)
	if err != nil {
		t.Fatal(err)
	}
	opts := setupOptions{Target: "codex", Scope: "project", Workspace: workspace, DataDir: dataDir}
	oldCommand := setupHookCommand(opts, "/Applications/HELM-old.app/Contents/MacOS/helm-ai-kernel")
	lookalike := shellQuote("/usr/local/bin/custom-policy") + " hook pre-tool --client codex --data-dir " + shellQuote(dataDir)
	hooks := map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{
		"matcher": "^Read$", // a shared user entry; migration must not widen it.
		"hooks": []any{
			map[string]any{"type": "command", "command": oldCommand, "timeout": float64(30), "statusMessage": "Checking HELM policy"},
			map[string]any{"type": "command", "command": lookalike, "timeout": float64(30), "statusMessage": "A different product"},
		},
	}}}}
	rawHooks, err := json.Marshal(hooks)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteSetupFile(t, filepath.Join(workspace, ".codex", "hooks.json"), append(rawHooks, '\n'))
	apply := []string{"setup", "codex", "--scope", "project", "--workspace", workspace, "--data-dir", dataDir, "--no-quickstart", "--yes"}
	if code, _, _, stderr := runCodexProjectSetupCommand(t, apply); code != 0 {
		t.Fatalf("relocation apply exit=%d stderr=%s", code, stderr)
	}
	updated, err := os.ReadFile(filepath.Join(workspace, ".codex", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	currentCommand := setupHookCommand(opts, bin)
	if strings.Contains(string(updated), oldCommand) || strings.Count(string(updated), currentCommand) != 1 || !strings.Contains(string(updated), lookalike) {
		t.Fatalf("hook relocation did not migrate exactly the marked HELM hook:\n%s", updated)
	}
	status := []string{"setup", "status", "codex", "--scope", "project", "--workspace", workspace, "--data-dir", dataDir, "--no-quickstart", "--json"}
	if code, summary, _, stderr := runCodexProjectSetupCommand(t, status); code != 0 || !summary.HookInstalled || !summary.MCPInstalled || stderr != "" {
		t.Fatalf("relocation status exit=%d summary=%#v stderr=%s", code, summary, stderr)
	}
	remove := []string{"setup", "remove", "codex", "--scope", "project", "--workspace", workspace, "--data-dir", dataDir, "--no-quickstart", "--yes"}
	if code, _, _, stderr := runCodexProjectSetupCommand(t, remove); code != 0 {
		t.Fatalf("relocation remove exit=%d stderr=%s", code, stderr)
	}
	updated, err = os.ReadFile(filepath.Join(workspace, ".codex", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(updated), currentCommand) || !strings.Contains(string(updated), lookalike) {
		t.Fatalf("remove did not preserve unmarked lookalike:\n%s", updated)
	}
}

func runCodexProjectSetupCommand(t *testing.T, args []string) (int, setupSummary, []byte, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(append([]string{"helm-ai-kernel"}, args...), &stdout, &stderr)
	var summary setupSummary
	if strings.Contains(strings.Join(args, " "), " --json") || containsSetupString(args, "--json") {
		if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
			t.Fatalf("decode setup JSON for %q: %v\n%s", strings.Join(args, " "), err, stdout.String())
		}
	}
	return code, summary, stdout.Bytes(), stderr.String()
}

func mustWriteSetupFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertSetupFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s changed:\n%s", path, got)
	}
}
