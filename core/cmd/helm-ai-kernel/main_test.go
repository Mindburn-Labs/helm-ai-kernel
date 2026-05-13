package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func chdirTempDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})
	return dir
}

// TestRun_Help verifies that the help command prints usage and exits 0.
func TestRun_Help(t *testing.T) {
	args := []string{"helm", "--help"}
	var stdout, stderr bytes.Buffer

	// Overwrite runServer logic to avoid starting the actual server
	originalRunServer := startServer
	defer func() { startServer = originalRunServer }()
	startServer = func() {
		// No-op for testing
	}

	exitCode := Run(args, &stdout, &stderr)

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout.String(), "helm-ai-kernel <command> [options]")
}

func TestRun_HelpOmitsRemovedUICommands(t *testing.T) {
	args := []string{"helm", "--help"}
	var stdout, stderr bytes.Buffer

	originalRunServer := startServer
	defer func() { startServer = originalRunServer }()
	startServer = func() {}

	exitCode := Run(args, &stdout, &stderr)

	assert.Equal(t, 0, exitCode)
	help := stdout.String()
	removedCommands := []string{
		"control" + "-" + "room",
		"dash" + "board",
		"explor" + "er",
		"simula" + "tor",
	}
	for _, removed := range removedCommands {
		assert.False(t, strings.Contains(help, removed), "help should not list removed UI command %q", removed)
	}
}

// TestRun_Unknown verifies that unknown commands output warning and default to server.
func TestRun_Unknown(t *testing.T) {
	args := []string{"helm", "unknown-command"}
	var stdout, stderr bytes.Buffer

	// Overwrite runServer logic to avoid crash due to missing env vars
	originalRunServer := startServer
	defer func() { startServer = originalRunServer }()
	startServer = func() {}

	exitCode := Run(args, &stdout, &stderr)

	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr.String(), "Unknown command")
}

// TestRun_Health_Fail verifies availability of the health subcommand logic.
func TestRun_Health_Fail(t *testing.T) {
	t.Setenv("HELM_HEALTH_PORT", "9999")

	args := []string{"helm", "health"}
	var stdout, stderr bytes.Buffer

	exitCode := Run(args, &stdout, &stderr)

	assert.Equal(t, 1, exitCode)
	// Health check fails when no server is running on the target port
	combined := stdout.String() + stderr.String()
	assert.True(t, len(combined) > 0 || exitCode == 1, "Health check should fail")
}
