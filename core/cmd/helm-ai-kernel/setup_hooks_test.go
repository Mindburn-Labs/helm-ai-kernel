package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestSetupHookCommandIncludesExplicitSigningSeedFile(t *testing.T) {
	opts := setupOptions{
		Target:              "codex",
		DataDir:             "/tmp/helm-data",
		SigningSeedFile:     "/private/approved/workstation.seed",
		PolicyProfile:       "/private/approved/policy.json",
		PolicyProfileSHA256: "sha256:approved",
	}
	command := setupHookCommand(opts, "/usr/local/bin/helm-ai-kernel")
	if !strings.Contains(command, "--signing-seed-file '/private/approved/workstation.seed'") {
		t.Fatalf("hook command did not preserve explicit signer source: %s", command)
	}
	if !strings.Contains(command, "--policy-profile '/private/approved/policy.json'") {
		t.Fatalf("hook command did not preserve policy profile: %s", command)
	}
	if !strings.Contains(command, "--policy-profile-sha256 'sha256:approved'") {
		t.Fatalf("hook command did not preserve approved policy digest: %s", command)
	}
	if removal := setupUninstallCommand(opts); !strings.Contains(removal, "--signing-seed-file '/private/approved/workstation.seed'") {
		t.Fatalf("uninstall command did not preserve explicit signer source: %s", removal)
	} else if !strings.Contains(removal, "--policy-profile '/private/approved/policy.json'") {
		t.Fatalf("uninstall command did not preserve policy profile: %s", removal)
	}
	if recovery := setupRecoveryCommand(opts); !strings.Contains(recovery, "--signing-seed-file '/private/approved/workstation.seed'") {
		t.Fatalf("recovery command did not preserve explicit signer source: %s", recovery)
	} else if !strings.Contains(recovery, "--policy-profile '/private/approved/policy.json'") {
		t.Fatalf("recovery command did not preserve policy profile: %s", recovery)
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

func TestSetupNormalizesRelativeHookFilePaths(t *testing.T) {
	var stderr bytes.Buffer
	opts, code := parseSetupInstallArgs([]string{"claude-code", "--yes", "--data-dir", t.TempDir(), "--signing-seed-file", "rel/seed.hex", "--policy-profile", "rel/policy.json"}, &stderr)
	if code != 0 {
		t.Fatalf("parse exit = %d stderr=%s", code, stderr.String())
	}
	if !filepath.IsAbs(opts.SigningSeedFile) {
		t.Fatalf("SigningSeedFile = %q, want absolute (relative paths bake a cwd-dependent hook command)", opts.SigningSeedFile)
	}
	if !filepath.IsAbs(opts.PolicyProfile) {
		t.Fatalf("PolicyProfile = %q, want absolute (relative paths bake a cwd-dependent hook command)", opts.PolicyProfile)
	}
}

func TestHookCommandKeyIgnoresSigningSeedFileArgument(t *testing.T) {
	base := "'/usr/local/bin/helm-ai-kernel' hook pre-tool --client claude-code --data-dir '/home/op/.helm'"
	withSeed := base + " --signing-seed-file '/home/op/keys/seed.hex'"
	withBareSeed := base + " --signing-seed-file /home/op/keys/seed.hex"
	withProfile := base + " --policy-profile '/home/op/policies/allow.json'"
	withDigest := withProfile + " --policy-profile-sha256 sha256:approved"
	withBoth := withSeed + " --policy-profile '/home/op/policies/allow.json' --policy-profile-sha256 sha256:approved"

	if hookCommandKey(withSeed) != hookCommandKey(base) {
		t.Fatalf("quoted seed-file arg changes hook identity:\n%q\n%q", hookCommandKey(withSeed), hookCommandKey(base))
	}
	if hookCommandKey(withBareSeed) != hookCommandKey(base) {
		t.Fatalf("bare seed-file arg changes hook identity")
	}
	if hookCommandKey(withProfile) != hookCommandKey(base) || hookCommandKey(withDigest) != hookCommandKey(base) || hookCommandKey(withBoth) != hookCommandKey(base) {
		t.Fatalf("policy-profile arg changes hook identity")
	}
	if hookCommandConfigKey(withProfile) == hookCommandConfigKey(base) {
		t.Fatal("policy profile was incorrectly stripped from status configuration")
	}
	if hookCommandConfigKey(withDigest) == hookCommandConfigKey(withProfile) {
		t.Fatal("policy profile digest was incorrectly stripped from status configuration")
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

func TestHookCommandKeyHandlesEscapedQuotesInSeedPath(t *testing.T) {
	base := "'/usr/local/bin/helm-ai-kernel' hook pre-tool --client claude-code --data-dir '/home/op/.helm'"
	trickyPath := "/tmp/o'brien/seed.hex"
	withSeed := base + " --signing-seed-file " + shellQuote(trickyPath)

	if got := hookCommandKey(withSeed); got != base {
		t.Fatalf("escaped-quote seed path not fully stripped:\n got %q\nwant %q", got, base)
	}
}

func TestUpsertHookConfigUpdatesSeedFileOnReinstall(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "settings.json")
	base := "'/usr/local/bin/helm-ai-kernel' hook pre-tool --client claude-code --data-dir '/home/op/.helm'"
	oldCmd := base + " --signing-seed-file '/keys/old.hex'"
	newCmd := base + " --signing-seed-file '/keys/new.hex'"

	if err := upsertHookConfig(path, "*", oldCmd, tmp); err != nil {
		t.Fatalf("initial install: %v", err)
	}
	if err := upsertHookConfig(path, "*", newCmd, tmp); err != nil {
		t.Fatalf("reinstall with rotated seed: %v", err)
	}

	root, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(root)
	if !strings.Contains(string(raw), "/keys/new.hex") {
		t.Fatalf("reinstall did not update stored seed path: %s", raw)
	}
	if strings.Contains(string(raw), "/keys/old.hex") {
		t.Fatalf("stale seed path survived reinstall: %s", raw)
	}
}

func TestUpsertHookConfigUpdatesPolicyProfileOnReinstall(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "settings.json")
	base := "'/usr/local/bin/helm-ai-kernel' hook pre-tool --client claude-code --data-dir '/home/op/.helm'"
	oldCmd := base + " --policy-profile '/policies/old.json' --policy-profile-sha256 sha256:old"
	newCmd := base + " --policy-profile '/policies/new.json' --policy-profile-sha256 sha256:new"

	if err := upsertHookConfig(path, "*", oldCmd, tmp); err != nil {
		t.Fatalf("initial install: %v", err)
	}
	if err := upsertHookConfig(path, "*", newCmd, tmp); err != nil {
		t.Fatalf("reinstall with changed policy: %v", err)
	}

	root, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(root)
	if !strings.Contains(string(raw), "/policies/new.json") || !strings.Contains(string(raw), "sha256:new") || strings.Contains(string(raw), "/policies/old.json") || strings.Contains(string(raw), "sha256:old") {
		t.Fatalf("reinstall did not replace stored policy profile: %s", raw)
	}
}

// TestSetupHookMatcherCoversClaudeCodeWriteTools is the 04-08 regression: the
// installed matcher must route every file-writing Claude Code tool to the hook.
func TestSetupHookMatcherCoversClaudeCodeWriteTools(t *testing.T) {
	matcher := regexp.MustCompile(setupHookMatcher("claude-code"))
	for _, tool := range []string{"Bash", "Edit", "Write", "MultiEdit", "NotebookEdit", "mcp__filesystem__write_file"} {
		if !matcher.MatchString(tool) {
			t.Fatalf("claude-code hook matcher %q misses %s", matcher, tool)
		}
	}
}
