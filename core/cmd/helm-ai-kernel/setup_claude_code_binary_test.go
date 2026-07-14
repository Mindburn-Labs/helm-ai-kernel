package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveSetupClaudeCodeBinaryUsesExecutableOverride(t *testing.T) {
	claude := writeSetupExecutable(t, filepath.Join(t.TempDir(), "direct-claude"))
	t.Setenv(setupClaudeCodeBinaryEnv, claude)

	oldLookPath := setupClaudeCodeLookPath
	setupClaudeCodeLookPath = func(string) (string, error) {
		return "", errors.New("PATH lookup must not run when CLAUDE_CODE_BIN is set")
	}
	t.Cleanup(func() { setupClaudeCodeLookPath = oldLookPath })

	binary, err := resolveSetupClaudeCodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	if binary != claude {
		t.Fatalf("binary = %q, want %q", binary, claude)
	}
}

func TestResolveSetupClaudeCodeBinaryRejectsMiseShimFromPATH(t *testing.T) {
	shim := writeSetupExecutable(t, filepath.Join(t.TempDir(), "mise", "shims", "claude"))
	t.Setenv(setupClaudeCodeBinaryEnv, "")

	oldLookPath := setupClaudeCodeLookPath
	setupClaudeCodeLookPath = func(string) (string, error) { return shim, nil }
	t.Cleanup(func() { setupClaudeCodeLookPath = oldLookPath })

	_, err := resolveSetupClaudeCodeBinary()
	if err == nil || !strings.Contains(err.Error(), "mise shim") || !strings.Contains(err.Error(), setupClaudeCodeBinaryEnv) {
		t.Fatalf("expected mise shim guidance, got %v", err)
	}
}

func TestResolveSetupClaudeCodeBinaryUsesDirectPATHExecutable(t *testing.T) {
	claude := writeSetupExecutable(t, filepath.Join(t.TempDir(), "bin", "claude"))
	t.Setenv(setupClaudeCodeBinaryEnv, "")

	oldLookPath := setupClaudeCodeLookPath
	setupClaudeCodeLookPath = func(string) (string, error) { return claude, nil }
	t.Cleanup(func() { setupClaudeCodeLookPath = oldLookPath })

	binary, err := resolveSetupClaudeCodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	if binary != claude {
		t.Fatalf("binary = %q, want %q", binary, claude)
	}
}

func TestInstallSetupMCPUsesResolvedClaudeCodeBinary(t *testing.T) {
	claude := writeSetupExecutable(t, filepath.Join(t.TempDir(), "direct-claude"))
	t.Setenv(setupClaudeCodeBinaryEnv, claude)

	oldExec := setupExecCommand
	var got []string
	setupExecCommand = func(name string, args ...string) error {
		got = append([]string{name}, args...)
		return nil
	}
	t.Cleanup(func() { setupExecCommand = oldExec })

	err := installSetupMCP(setupOptions{Target: "claude-code", Scope: "project", DataDir: t.TempDir()}, "/tmp/helm-ai-kernel")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0] != claude || !strings.Contains(strings.Join(got[1:], " "), "mcp add") {
		t.Fatalf("Claude MCP command = %#v", got)
	}
}

func writeSetupExecutable(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}
