package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const setupClaudeCodeBinaryEnv = "CLAUDE_CODE_BIN"

var setupClaudeCodeLookPath = exec.LookPath

// resolveSetupClaudeCodeBinary chooses the client executable without reading
// any client configuration. An explicit path is required for the override so
// it cannot silently fall back to a different PATH entry at execution time.
func resolveSetupClaudeCodeBinary() (string, error) {
	if override := strings.TrimSpace(os.Getenv(setupClaudeCodeBinaryEnv)); override != "" {
		if !filepath.IsAbs(override) && !strings.ContainsRune(override, os.PathSeparator) {
			return "", fmt.Errorf("%s must be an executable path, not a command name", setupClaudeCodeBinaryEnv)
		}
		binary, err := resolveSetupClaudeCodeExecutable(override)
		if err != nil {
			return "", fmt.Errorf("%s must point to an executable file: %w", setupClaudeCodeBinaryEnv, err)
		}
		return binary, nil
	}

	path, err := setupClaudeCodeLookPath("claude")
	if err != nil {
		return "", fmt.Errorf("locate Claude Code CLI: %w; set %s to its executable path", err, setupClaudeCodeBinaryEnv)
	}
	binary, err := resolveSetupClaudeCodeExecutable(path)
	if err != nil {
		return "", fmt.Errorf("resolve Claude Code CLI from PATH: %w; set %s to its executable path", err, setupClaudeCodeBinaryEnv)
	}
	if isSetupMiseShim(path) || isSetupMiseShim(binary) {
		return "", fmt.Errorf("refusing Claude Code CLI resolved through a mise shim; set %s to a direct executable path", setupClaudeCodeBinaryEnv)
	}
	return binary, nil
}

func resolveSetupClaudeCodeExecutable(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	binary, err := exec.LookPath(absolute)
	if err != nil {
		return "", err
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(binary)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	return binary, nil
}

func isSetupMiseShim(path string) bool {
	return strings.Contains(filepath.ToSlash(filepath.Clean(path)), "/mise/shims/")
}
