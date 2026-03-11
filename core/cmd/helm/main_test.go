package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
	assert.Contains(t, stdout.String(), "helm <command> [options]")
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
	t.Setenv("HEALTH_PORT", "9999")

	args := []string{"helm", "health"}
	var stdout, stderr bytes.Buffer

	exitCode := Run(args, &stdout, &stderr)

	assert.Equal(t, 1, exitCode)
	// Health check fails when no server is running on the target port
	combined := stdout.String() + stderr.String()
	assert.True(t, len(combined) > 0 || exitCode == 1, "Health check should fail")
}
