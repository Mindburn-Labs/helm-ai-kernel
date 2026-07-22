package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func runShellHook(t *testing.T, dataDir, mode, command string) (int, string, string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--client", "claude-code", "--data-dir", dataDir}
	if mode != "" {
		args = append(args, "--shell-mode", mode)
	}
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd(args, bytes.NewReader(payload), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func soleReceiptReason(t *testing.T, dataDir string) string {
	t.Helper()
	receipts := globReceipts(t, dataDir)
	if len(receipts) != 1 {
		t.Fatalf("receipts = %v, want exactly one", receipts)
	}
	receipt, err := workstation.LoadDecisionReceipt(receipts[0])
	if err != nil {
		t.Fatalf("load receipt: %v", err)
	}
	if receipt.Verdict != contracts.WorkstationVerdictDeny {
		t.Fatalf("receipt verdict = %s, want DENY", receipt.Verdict)
	}
	if ok, err := workstation.VerifyDecisionReceiptSignature(receipt); err != nil || !ok {
		t.Fatalf("receipt signature ok=%v err=%v", ok, err)
	}
	return receipt.ReasonCode
}

func TestHookAllowlistModeAllowsAllowlistedReadOnly(t *testing.T) {
	// Each of these maps to an action already present in the default profile's
	// Observe.AllowedActions, so allowlist mode works before any user edits.
	for _, command := range []string{"git status", "git diff HEAD~1", "ls -la", "go test ./...", "cat README.md"} {
		t.Run(command, func(t *testing.T) {
			tmp := t.TempDir()
			restoreHookClock(t)
			code, stdout, stderr := runShellHook(t, tmp, shellModeAllowlist, command)
			if code != 0 {
				t.Fatalf("hook exit = %d stderr = %s", code, stderr)
			}
			if stdout != "" {
				t.Fatalf("allowlisted command emitted approval output: %s", stdout)
			}
			if receipts := globReceipts(t, tmp); len(receipts) != 0 {
				t.Fatalf("allowlisted command wrote receipts: %v", receipts)
			}
		})
	}
}

func TestHookAllowlistModeDeniesUnrecognizedCommand(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	// Not destructive by the 0.7.x denylist, and not recognized as read-only.
	// Denylist mode lets this through silently; allowlist mode is the whole
	// point of the change.
	code, stdout, stderr := runShellHook(t, tmp, shellModeAllowlist, "npm publish --access public")
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, `"permissionDecision":"deny"`) {
		t.Fatalf("unrecognized command should be denied, output = %s", stdout)
	}
	if reason := soleReceiptReason(t, tmp); reason != "OPERATE_PERMISSIONS_EMPTY" {
		t.Fatalf("receipt reason = %s, want OPERATE_PERMISSIONS_EMPTY", reason)
	}
}

func TestHookAllowlistModeDeniesEvasionCorpus(t *testing.T) {
	// wantReason separates the two denial grounds: a command that cannot be
	// analyzed at all, versus one that is analyzable but unauthorized. The
	// distinction lives in the signed receipt, not just the console line.
	cases := []struct {
		name       string
		command    string
		wantReason string
	}{
		{"chained after allowlisted", "git status && rm -rf /", "SHELL_COMMAND_NOT_STATICALLY_ANALYZABLE"},
		{"command substitution", "$(echo rm) -rf /tmp/x", "SHELL_COMMAND_NOT_STATICALLY_ANALYZABLE"},
		{"base64 pipe to shell", "echo cm0gLXJmIC8= | base64 -d | sh", "SHELL_COMMAND_NOT_STATICALLY_ANALYZABLE"},
		{"redirect from allowlisted", "git show HEAD > /tmp/authorized_keys", "SHELL_COMMAND_NOT_STATICALLY_ANALYZABLE"},
		{"newline chaining", "git status\nrm -rf /", "SHELL_COMMAND_NOT_STATICALLY_ANALYZABLE"},
		{"whitespace padding", "rm  -rf /tmp/x", "OPERATE_PERMISSIONS_EMPTY"},
		{"uppercase", "RM -RF /tmp/x", "OPERATE_PERMISSIONS_EMPTY"},
		{"quote splitting", "r''m -rf /tmp/x", "OPERATE_PERMISSIONS_EMPTY"},
		{"mutating git subcommand", "git push --force origin main", "OPERATE_PERMISSIONS_EMPTY"},
		{"absolute path bypass", "/bin/rm -rf /tmp/x", "OPERATE_PERMISSIONS_EMPTY"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			restoreHookClock(t)
			code, stdout, stderr := runShellHook(t, tmp, shellModeAllowlist, tc.command)
			if code != 0 {
				t.Fatalf("hook exit = %d stderr = %s", code, stderr)
			}
			if !strings.Contains(stdout, `"permissionDecision":"deny"`) {
				t.Fatalf("%q must be denied in allowlist mode, output = %s", tc.command, stdout)
			}
			if reason := soleReceiptReason(t, tmp); reason != tc.wantReason {
				t.Fatalf("%q receipt reason = %s, want %s", tc.command, reason, tc.wantReason)
			}
		})
	}
}

func TestHookDenylistModeIsUnchanged(t *testing.T) {
	t.Run("destructive still denied", func(t *testing.T) {
		tmp := t.TempDir()
		restoreHookClock(t)
		code, stdout, stderr := runShellHook(t, tmp, shellModeDenylist, "rm -rf /tmp/helm-demo")
		if code != 0 {
			t.Fatalf("hook exit = %d stderr = %s", code, stderr)
		}
		if !strings.Contains(stdout, `"permissionDecision":"deny"`) {
			t.Fatalf("destructive command should be denied, output = %s", stdout)
		}
	})

	// This records the 0.7.x gap the flag preserves rather than fixes: in
	// denylist mode an unrecognized mutation proceeds with no verdict, no
	// receipt, and no record that HELM saw it. Allowlist mode is the fix; this
	// asserts the default did not silently change under existing installs.
	t.Run("unrecognized mutation still passes silently", func(t *testing.T) {
		tmp := t.TempDir()
		restoreHookClock(t)
		code, stdout, stderr := runShellHook(t, tmp, shellModeDenylist, "npm publish --access public")
		if code != 0 {
			t.Fatalf("hook exit = %d stderr = %s", code, stderr)
		}
		if stdout != "" {
			t.Fatalf("denylist mode changed behavior for an unrecognized command: %s", stdout)
		}
		if receipts := globReceipts(t, tmp); len(receipts) != 0 {
			t.Fatalf("denylist mode wrote a receipt it did not write before: %v", receipts)
		}
	})
}

func TestHookDefaultShellModeIsDenylist(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	// No --shell-mode flag at all, which is what an 0.7.x baked command line
	// looks like after an upgrade.
	code, stdout, stderr := runShellHook(t, tmp, "", "npm publish --access public")
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("default mode must remain denylist through 0.7.x, got output: %s", stdout)
	}
}

func TestHookRejectsUnknownShellMode(t *testing.T) {
	code, stdout, stderr := runShellHook(t, t.TempDir(), "permissive", "ls -la")
	if code != 2 {
		t.Fatalf("unknown --shell-mode exit = %d, want blocking exit 2 (stdout=%s stderr=%s)", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "unknown --shell-mode") {
		t.Fatalf("stderr missing the mode error: %s", stderr)
	}
}

func helmHookCommands(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hook config: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("parse hook config: %v", err)
	}
	hooks, _ := root["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	var found []string
	forEachHookCommand(pre, func(_ map[string]any, command string) {
		if isHelmHookCommand(command) {
			found = append(found, command)
		}
	})
	return found
}

// TestSetupHookUpsertReplacesChangedCommandLine pins the dedup fix. Before it,
// hook identity was the exact command string, so installing after a flag change
// appended a second PreToolUse entry and left both hooks firing — and uninstall
// then matched neither.
func TestSetupHookUpsertReplacesChangedCommandLine(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, ".claude"), 0o750); err != nil {
		t.Fatal(err)
	}
	opts := setupOptions{Target: "claude-code", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
	bin := filepath.Join(tmp, "helm-ai-kernel")
	path := setupHookConfigPath(opts)

	if err := installSetupHook(opts, bin); err != nil {
		t.Fatalf("install flagless hook: %v", err)
	}
	if commands := helmHookCommands(t, path); len(commands) != 1 {
		t.Fatalf("after first install, HELM hooks = %v, want exactly one", commands)
	}

	upgraded := opts
	upgraded.ShellMode = shellModeAllowlist
	if err := installSetupHook(upgraded, bin); err != nil {
		t.Fatalf("install hook with changed command line: %v", err)
	}
	commands := helmHookCommands(t, path)
	if len(commands) != 1 {
		t.Fatalf("changed command line installed %d HELM hooks, want exactly one: %v", len(commands), commands)
	}
	if !strings.Contains(commands[0], "--shell-mode=allowlist") {
		t.Fatalf("hook command was not rewritten: %s", commands[0])
	}
	if !setupHookInstalled(path) {
		t.Fatal("setupHookInstalled must recognize a hook whose flags changed")
	}

	// Removal must also match on identity rather than the exact string, or the
	// rewritten entry would be orphaned.
	if err := removeSetupHook(upgraded); err != nil {
		t.Fatalf("remove rewritten hook: %v", err)
	}
	if commands := helmHookCommands(t, path); len(commands) != 0 {
		t.Fatalf("removal left HELM hooks behind: %v", commands)
	}
}
