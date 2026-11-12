package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// matcherTestSetup is one client install in a scratch home and workspace.
type matcherTestSetup struct {
	opts     setupOptions
	summary  setupSummary
	hookPath string
	command  string
}

func newMatcherTestSetup(t *testing.T, target string) matcherTestSetup {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", filepath.Join(tmp, "home"))
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	if resolved, err := filepath.EvalSymlinks(workspace); err == nil {
		workspace = resolved
	}
	stubSetupSideEffects(t)
	opts := setupOptions{Target: target, Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	return matcherTestSetup{opts: opts, summary: summary, hookPath: summary.HookConfigPath, command: setupHookCommand(opts, summary.BinaryPath)}
}

func (m matcherTestSetup) writeClaudeHookEntry(t *testing.T, matcher string, hooks ...map[string]any) {
	t.Helper()
	items := []any{}
	for _, hook := range hooks {
		items = append(items, hook)
	}
	raw, err := json.Marshal(map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{"matcher": matcher, "hooks": items}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(m.hookPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.hookPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (m matcherTestSetup) installedMatchers(t *testing.T) []string {
	t.Helper()
	root, err := readJSONObject(m.hookPath)
	if err != nil {
		t.Fatal(err)
	}
	var matchers []string
	for _, item := range arrayValue(objectValue(root, "hooks"), "PreToolUse") {
		if obj, ok := item.(map[string]any); ok {
			matcher, _ := obj["matcher"].(string)
			matchers = append(matchers, matcher)
		}
	}
	return matchers
}

func (m matcherTestSetup) install(t *testing.T) (stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", m.opts.Target, "--scope", "project", "--workspace", m.opts.Workspace, "--yes", "--no-quickstart", "--json", "--data-dir", m.opts.DataDir}, &out, &errOut)
	if code != 0 {
		t.Fatalf("setup exit = %d stdout = %s stderr = %s", code, out.String(), errOut.String())
	}
	return out.String(), errOut.String()
}

// The matcher an earlier release installed: before the read and fetch tools.
const olderClaudeMatcher = "^(Bash|Edit|Write|MultiEdit|NotebookEdit|mcp__.*)$"

// An entry that holds only the HELM hook is HELM's, so a re-install gives it
// the matcher of this release and with it the tools this release classifies.
func TestSetupUpgradesTheMatcherOfItsOwnHookEntry(t *testing.T) {
	m := newMatcherTestSetup(t, "claude-code")
	m.writeClaudeHookEntry(t, olderClaudeMatcher, map[string]any{"type": "command", "command": m.command, "timeout": 30})
	m.install(t)
	if got := m.installedMatchers(t); len(got) != 1 || got[0] != setupHookMatcher("claude-code") {
		t.Fatalf("matchers after a re-install = %q, want only %q", got, setupHookMatcher("claude-code"))
	}
}

// An entry that also holds another hook is the user's: setup leaves its
// matcher alone and says so, naming the file and the matcher it kept.
func TestSetupWarnsAboutASharedHookEntryItWillNotRewrite(t *testing.T) {
	m := newMatcherTestSetup(t, "claude-code")
	m.writeClaudeHookEntry(t, olderClaudeMatcher,
		map[string]any{"type": "command", "command": m.command, "timeout": 30},
		map[string]any{"type": "command", "command": "other-hook"})
	stdout, stderr := m.install(t)
	if got := m.installedMatchers(t); len(got) != 1 || got[0] != olderClaudeMatcher {
		t.Fatalf("matchers after a re-install = %q, want the shared entry left as %q", got, olderClaudeMatcher)
	}
	for _, text := range []string{m.hookPath, olderClaudeMatcher, setupHookMatcher("claude-code")} {
		if !strings.Contains(stderr, text) {
			t.Errorf("setup did not warn with %q:\n%s", text, stderr)
		}
	}
	var summary map[string]any
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
		t.Fatalf("summary JSON: %v\n%s", err, stdout)
	}
	if warnings, _ := summary["warnings"].([]any); len(warnings) != 1 {
		t.Fatalf("summary warnings = %v, want the one shared entry", summary["warnings"])
	}
}

// setup status compares the installed matcher with the one this release
// installs, so an install that routes fewer tools is reported, not healthy.
func TestSetupStatusReportsAnOutdatedHookMatcher(t *testing.T) {
	for _, tc := range []struct {
		target, older string
	}{
		{"claude-code", olderClaudeMatcher},
		{"hermes", "^(terminal|write_file|patch|mcp_.*)$"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			m := newMatcherTestSetup(t, tc.target)
			writeSetupMCPTestConfig(t, tc.target, m.summary.ClientConfigPath, m.summary.BinaryPath, m.opts.DataDir)
			install := func(matcher string) {
				t.Helper()
				var err error
				if tc.target == "hermes" {
					err = upsertHermesHookConfig(m.hookPath, matcher, m.command, setupPrivateFileRoot(m.opts))
				} else {
					_ = os.Remove(m.hookPath)
					err = upsertHookConfig(m.hookPath, matcher, m.command, setupPrivateFileRoot(m.opts))
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			status := func(jsonOut bool) (int, string) {
				t.Helper()
				args := []string{"helm-ai-kernel", "setup", "status", tc.target, "--scope", "project", "--workspace", m.opts.Workspace, "--data-dir", m.opts.DataDir}
				if jsonOut {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				code := Run(args, &stdout, &stderr)
				return code, stdout.String()
			}

			install(tc.older)
			code, out := status(true)
			var summary map[string]any
			if err := json.Unmarshal([]byte(out), &summary); err != nil {
				t.Fatalf("status JSON: %v\n%s", err, out)
			}
			if summary["hook_matcher"] != tc.older || summary["hook_matcher_expected"] != setupHookMatcher(tc.target) || summary["hook_matcher_outdated"] != true {
				t.Fatalf("status does not report the outdated matcher: %v", summary)
			}
			if code == 0 {
				t.Fatalf("status exit = 0 with an outdated matcher")
			}
			if _, text := status(false); !strings.Contains(text, "outdated") || !strings.Contains(text, tc.older) {
				t.Fatalf("status text does not report the outdated matcher:\n%s", text)
			}

			install(setupHookMatcher(tc.target))
			_, out = status(true)
			summary = map[string]any{}
			if err := json.Unmarshal([]byte(out), &summary); err != nil {
				t.Fatalf("status JSON: %v\n%s", err, out)
			}
			if summary["hook_matcher"] != setupHookMatcher(tc.target) || summary["hook_matcher_outdated"] == true {
				t.Fatalf("status reports a current matcher as outdated: %v", summary)
			}
		})
	}
}

// Tools that run code, load a URL or read an MCP resource reach the hook.
func TestSetupHookMatcherRoutesCodeBrowserAndResourceTools(t *testing.T) {
	for target, tools := range map[string][]string{
		"claude-code": {"ReadMcpResourceTool", "ListMcpResourcesTool"},
		"hermes":      {"execute_code", "browser_navigate", "vision_analyze"},
	} {
		for _, tool := range tools {
			if !regexpMatches(t, setupHookMatcher(target), tool) {
				t.Errorf("%s matcher %q does not route %s", target, setupHookMatcher(target), tool)
			}
		}
	}
}

// Running setup again changes nothing once the hook is current.
func TestSetupHookInstallIsIdempotent(t *testing.T) {
	for _, target := range []string{"claude-code", "hermes"} {
		t.Run(target, func(t *testing.T) {
			m := newMatcherTestSetup(t, target)
			m.install(t)
			first, err := os.ReadFile(m.hookPath)
			if err != nil {
				t.Fatal(err)
			}
			_, stderr := m.install(t)
			second, err := os.ReadFile(m.hookPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(first, second) {
				t.Fatalf("a second setup changed %s:\n%s\n---\n%s", m.hookPath, first, second)
			}
			if strings.Contains(stderr, "matcher") {
				t.Fatalf("a current install warned about its matcher:\n%s", stderr)
			}
		})
	}
}
