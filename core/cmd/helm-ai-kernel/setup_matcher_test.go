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

// statusJSON runs setup status for the test install and decodes its summary.
func (m matcherTestSetup) status(t *testing.T, jsonOut bool) (int, string, map[string]any) {
	t.Helper()
	args := []string{"helm-ai-kernel", "setup", "status", m.opts.Target, "--scope", "project", "--workspace", m.opts.Workspace, "--data-dir", m.opts.DataDir}
	if jsonOut {
		args = append(args, "--json")
	}
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	if !jsonOut {
		return code, stdout.String(), nil
	}
	var summary map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("status JSON: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	return code, stdout.String(), summary
}

// The upgrade hint is a command that upgrades this install: for a project
// install it names the scope, the workspace and the data directory, so it
// does not configure another one.
func TestSetupOutdatedMatcherHintUpgradesThisInstall(t *testing.T) {
	m := newMatcherTestSetup(t, "claude-code")
	writeSetupMCPTestConfig(t, "claude-code", m.summary.ClientConfigPath, m.summary.BinaryPath, m.opts.DataDir)
	if err := upsertHookConfig(m.hookPath, olderClaudeMatcher, m.command, setupPrivateFileRoot(m.opts)); err != nil {
		t.Fatal(err)
	}
	want := "helm-ai-kernel setup claude-code --scope project --workspace " + shellQuote(m.opts.Workspace) + " --yes --data-dir " + shellQuote(m.opts.DataDir)
	_, text, _ := m.status(t, false)
	if !strings.Contains(text, want) {
		t.Fatalf("status text does not give the upgrade command %q:\n%s", want, text)
	}
	if _, _, summary := m.status(t, true); summary["hook_matcher_upgrade_command"] != want {
		t.Fatalf("status JSON hook_matcher_upgrade_command = %v, want %q", summary["hook_matcher_upgrade_command"], want)
	}
}

// writeClaudeHookEntries writes one PreToolUse entry per matcher, each holding
// only the HELM hook.
func (m matcherTestSetup) writeClaudeHookEntries(t *testing.T, matchers ...string) {
	t.Helper()
	entries := []any{}
	for _, matcher := range matchers {
		entries = append(entries, map[string]any{"matcher": matcher, "hooks": []any{map[string]any{"type": "command", "command": m.command, "timeout": 30}}})
	}
	raw, err := json.Marshal(map[string]any{"hooks": map[string]any{"PreToolUse": entries}})
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

// A tool reaches the hook when any entry that holds the HELM hook routes it,
// so status reads every such entry, not the first.
func TestSetupStatusReadsEveryHelmHookEntry(t *testing.T) {
	m := newMatcherTestSetup(t, "claude-code")
	writeSetupMCPTestConfig(t, "claude-code", m.summary.ClientConfigPath, m.summary.BinaryPath, m.opts.DataDir)
	readers := "^(Read|Grep|Glob|WebFetch|ReadMcpResourceTool|ListMcpResourcesTool)$"
	m.writeClaudeHookEntries(t, olderClaudeMatcher, readers)
	_, out, summary := m.status(t, true)
	if summary["hook_matcher_outdated"] == true {
		t.Fatalf("two entries that together route every tool were reported outdated:\n%s", out)
	}
	if matchers, _ := summary["hook_matchers"].([]any); len(matchers) != 2 || matchers[0] != olderClaudeMatcher || matchers[1] != readers {
		t.Fatalf("hook_matchers = %v, want both entries", summary["hook_matchers"])
	}

	m.writeClaudeHookEntries(t, olderClaudeMatcher, "^(Read)$")
	_, out, summary = m.status(t, true)
	missing, _ := summary["hook_matcher_missing_tools"].([]any)
	var names []string
	for _, tool := range missing {
		names = append(names, tool.(string))
	}
	if summary["hook_matcher_outdated"] != true || strings.Join(names, ",") != "Grep,Glob,WebFetch,ReadMcpResourceTool,ListMcpResourcesTool" {
		t.Fatalf("missing tools = %v (outdated %v), want the tools neither entry routes:\n%s", names, summary["hook_matcher_outdated"], out)
	}
}

// Claude Code reads a matcher of plain names as exact tool names and any other
// matcher as a regular expression that may match anywhere in the name. setup
// reads it the same way, so "Edit" does not count as routing MultiEdit.
func TestSetupReadsAClaudeCodeMatcherAsClaudeCodeDoes(t *testing.T) {
	for _, tc := range []struct {
		matcher string
		missing string
	}{
		{"Bash|Edit|Write|Read|Grep|Glob|WebFetch|ReadMcpResourceTool|ListMcpResourcesTool", "MultiEdit,NotebookEdit,mcp__.*"},
		{"Edit", "Bash,Write,MultiEdit,NotebookEdit,Read,Grep,Glob,WebFetch,ReadMcpResourceTool,ListMcpResourcesTool,mcp__.*"},
		{"Bash|Edit|Write|MultiEdit|NotebookEdit|Read|Grep|Glob|WebFetch|ReadMcpResourceTool|ListMcpResourcesTool|mcp__github__create_issue", "mcp__.*"},
		{"Bash|.*Edit|Write|Read|Grep|Glob|WebFetch|.*McpResource.*|mcp__.*", ""},
		{"Edit|Write|Bash|Read|Gr.p|Glob|WebFetch|Mcp|mcp__", ""},
		{"*", ""},
		{"", ""},
		{setupHookMatcher("claude-code"), ""},
	} {
		if got := strings.Join(setupHookMatcherMissing("claude-code", tc.matcher), ","); got != tc.missing {
			t.Errorf("matcher %q misses %q, want %q", tc.matcher, got, tc.missing)
		}
	}
}

// setup does not rewrite an entry it shares with other hooks, so status does
// not offer setup as the fix for one: it says to edit the entry instead.
func TestSetupStatusOffersNoUpgradeForASharedHookEntry(t *testing.T) {
	m := newMatcherTestSetup(t, "claude-code")
	writeSetupMCPTestConfig(t, "claude-code", m.summary.ClientConfigPath, m.summary.BinaryPath, m.opts.DataDir)
	m.writeClaudeHookEntry(t, olderClaudeMatcher,
		map[string]any{"type": "command", "command": m.command, "timeout": 30},
		map[string]any{"type": "command", "command": "other-hook"})
	_, out, summary := m.status(t, true)
	if summary["hook_matcher_outdated"] != true {
		t.Fatalf("a shared entry with an old matcher was not reported outdated:\n%s", out)
	}
	if command, present := summary["hook_matcher_upgrade_command"]; present {
		t.Fatalf("status offers %v for an entry setup will not rewrite", command)
	}
	warnings, _ := summary["warnings"].([]any)
	if len(warnings) != 1 || !strings.Contains(warnings[0].(string), m.hookPath) || !strings.Contains(warnings[0].(string), olderClaudeMatcher) {
		t.Fatalf("warnings = %v, want one that names the file and the matcher", summary["warnings"])
	}
	_, text, _ := m.status(t, false)
	if strings.Contains(text, "to upgrade it") || !strings.Contains(text, "also holds other hooks") {
		t.Fatalf("status text offers setup for a shared entry or does not say why it cannot:\n%s", text)
	}
}

// A shared entry with an old matcher beside an entry of HELM's own that
// routes every tool leaves nothing unrouted, so setup has nothing to warn
// about.
func TestSetupDoesNotWarnWhenAnotherEntryRoutesEveryTool(t *testing.T) {
	m := newMatcherTestSetup(t, "claude-code")
	shared := map[string]any{"matcher": olderClaudeMatcher, "hooks": []any{
		map[string]any{"type": "command", "command": m.command, "timeout": 30},
		map[string]any{"type": "command", "command": "other-hook"},
	}}
	own := map[string]any{"matcher": setupHookMatcher("claude-code"), "hooks": []any{map[string]any{"type": "command", "command": m.command, "timeout": 30}}}
	raw, err := json.Marshal(map[string]any{"hooks": map[string]any{"PreToolUse": []any{shared, own}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(m.hookPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.hookPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := m.install(t)
	if strings.Contains(stderr, "warning") {
		t.Fatalf("setup warned although every tool is routed:\n%s", stderr)
	}
	var summary map[string]any
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
		t.Fatalf("summary JSON: %v\n%s", err, stdout)
	}
	if warnings, present := summary["warnings"]; present {
		t.Fatalf("summary warnings = %v, want none", warnings)
	}
}

// The upgrade hint keeps the install's policy profile, so running it does not
// fall back to the built-in profile.
func TestSetupOutdatedMatcherHintKeepsThePolicyProfile(t *testing.T) {
	m := newMatcherTestSetup(t, "claude-code")
	writeSetupMCPTestConfig(t, "claude-code", m.summary.ClientConfigPath, m.summary.BinaryPath, m.opts.DataDir)
	raw, err := os.ReadFile(filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(profile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := m.opts
	opts.PolicyProfile = profile
	if err := populateSetupPolicyProfileDigest(&opts); err != nil {
		t.Fatal(err)
	}
	if err := upsertHookConfig(m.hookPath, olderClaudeMatcher, setupHookCommand(opts, m.summary.BinaryPath), setupPrivateFileRoot(m.opts)); err != nil {
		t.Fatal(err)
	}
	_, out, summary := m.status(t, true)
	command, _ := summary["hook_matcher_upgrade_command"].(string)
	if !strings.Contains(command, " --policy-profile "+shellQuote(profile)) {
		t.Fatalf("upgrade command %q does not keep the policy profile %s:\n%s", command, profile, out)
	}
}

func TestSetupDoesNotInferMCPFamilyCoverageFromExamples(t *testing.T) {
	for _, target := range []string{"claude-code", "codex", "hermes", "deepseek"} {
		pattern, example := "mcp__.*", "mcp__server__tool"
		if target == "hermes" || target == "deepseek" {
			pattern, example = "mcp_.*", "mcp_server_tool"
		}
		for _, replacement := range []string{example, example + "|" + example + "_other", "mcp_.*_tool"} {
			matcher := strings.Replace(setupHookMatcher(target), pattern, replacement, 1)
			if missing := setupHookMatchersMissing(target, []string{matcher}); len(missing) == 0 {
				t.Errorf("%s %q claims MCP family coverage", target, matcher)
			}
		}
		if missing := setupHookMatchersMissing(target, []string{setupHookMatcher(target)}); len(missing) != 0 {
			t.Errorf("%s shipped matcher misses %v", target, missing)
		}
	}
	m := newMatcherTestSetup(t, "claude-code")
	writeSetupMCPTestConfig(t, "claude-code", m.summary.ClientConfigPath, m.summary.BinaryPath, m.opts.DataDir)
	narrow := strings.Replace(setupHookMatcher("claude-code"), "mcp__.*", "mcp__server__tool", 1)
	m.writeClaudeHookEntry(t, narrow, map[string]any{"type": "command", "command": m.command, "timeout": 30}, map[string]any{"type": "command", "command": "other-hook"})
	_, out, summary := m.status(t, true)
	if summary["hook_matcher_outdated"] != true || summary["client_state"] != "degraded" {
		t.Errorf("narrow matcher not degraded: %s", out)
	}
	warnings, _ := summary["warnings"].([]any)
	if len(warnings) == 0 {
		t.Error("shared narrow MCP matcher emitted no warning")
	}
	m.writeClaudeHookEntry(t, setupHookMatcher("claude-code"), map[string]any{"type": "command", "command": m.command, "timeout": 30}, map[string]any{"type": "command", "command": "other-hook"})
	_, out, summary = m.status(t, true)
	if summary["hook_matcher_outdated"] == true {
		t.Errorf("complete shared matcher degraded: %s", out)
	}
}
