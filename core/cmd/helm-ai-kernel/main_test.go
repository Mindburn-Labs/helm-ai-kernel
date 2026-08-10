package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func chdirTempDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// Isolate HELM data dir so dev-local evidence sealing (auto-generated
	// signing keys, trust config) never touches the real ~/.helm.
	t.Setenv("HELM_DATA_DIR", t.TempDir())
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
	startServer = func() error {
		// No-op for testing
		return nil
	}

	exitCode := Run(args, &stdout, &stderr)

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout.String(), "Your first governed-agent run")
	assert.Contains(t, stdout.String(), "Launch local Kernel and browser Console")
	assert.Contains(t, stdout.String(), "Review live decisions when they need you")
	assert.Contains(t, stdout.String(), "helm-ai-kernel help --all")
}

func TestRunNoArgsPrintsFrontDoor(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"helm"}, &stdout, &stderr)

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout.String(), "helm-ai-kernel quickstart --console")
	assert.Contains(t, stdout.String(), "requires a Console-including package")
	assert.Contains(t, stdout.String(), "helm-ai-kernel setup claude-code")
	assert.Contains(t, stdout.String(), "helm-ai-kernel setup codex")
	assert.Contains(t, stdout.String(), "helm-ai-kernel watch")
	assert.Contains(t, stdout.String(), "helm-ai-kernel help --json")
	assert.Empty(t, stderr.String())
}

func TestRunQuickstartAndConsoleHelpPointToLocalConsole(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "quickstart",
			args: []string{"quickstart", "--help"},
			want: []string{
				"Usage: helm-ai-kernel quickstart",
				"helm-ai-kernel quickstart --console",
				"loopback-only Kernel",
				"Console-including packaged layout",
				"helm-ai-kernel-<os>-<arch>-console.tar.gz",
				"Homebrew and raw release binaries are headless",
			},
		},
		{
			name: "console topic",
			args: []string{"help", "console"},
			want: []string{
				"The local browser Console is launched by Quickstart",
				"helm-ai-kernel quickstart --console",
				"loopback-only Kernel",
				"Console-including packaged layout",
				"helm-ai-kernel-<os>-<arch>-console.tar.gz",
				"Homebrew and raw release binaries are headless",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(append([]string{"helm"}, tc.args...), &stdout, &stderr); code != 0 {
				t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
			}
			assert.Empty(t, stderr.String())
			for _, want := range tc.want {
				assert.Contains(t, stdout.String(), want)
			}
		})
	}
}

func TestRunHelpAllPrintsFullCommandList(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"helm", "help", "--all"}, &stdout, &stderr)

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout.String(), "Usage: helm-ai-kernel <command> [options]")
	assert.Contains(t, stdout.String(), "Commands:")
}

func TestRun_HelpOmitsRemovedUICommands(t *testing.T) {
	args := []string{"helm", "--help"}
	var stdout, stderr bytes.Buffer

	originalRunServer := startServer
	defer func() { startServer = originalRunServer }()
	startServer = func() error { return nil }

	exitCode := Run(args, &stdout, &stderr)

	assert.Equal(t, 0, exitCode)
	help := stdout.String()
	assert.NotContains(t, help, "Launchpad")
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
	startServer = func() error { return nil }

	exitCode := Run(args, &stdout, &stderr)

	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr.String(), "Unknown command")
}

func TestRunServerCommandReportsStartupFailure(t *testing.T) {
	t.Setenv("HELM_LOG_FORMAT", "")
	originalRunServer := startServer
	defer func() { startServer = originalRunServer }()
	startServer = func() error { return errors.New("bind failed") }

	var stdout, stderr bytes.Buffer
	exitCode := runServerCommand("server", nil, &stdout, &stderr)

	assert.Equal(t, 1, exitCode)
	var record map[string]any
	assert.NoError(t, json.Unmarshal(stderr.Bytes(), &record))
	assert.Equal(t, "ERROR", record["level"])
	assert.Equal(t, "server command failed", record["msg"])
	assert.Contains(t, record["error"], "bind failed")
}

func TestServerLogFormatDefaultsAndOverrides(t *testing.T) {
	for _, test := range []struct {
		name, mode, env, want string
	}{
		{name: "daemon defaults to json", mode: "serve", want: "json"},
		{name: "server defaults to json", mode: "server", want: "json"},
		{name: "quickstart defaults to text", mode: "quickstart", want: "text"},
		{name: "quickstart json override", mode: "quickstart", env: "json", want: "json"},
		{name: "daemon text override", mode: "serve", env: "text", want: "text"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HELM_LOG_FORMAT", test.env)
			got, err := resolveServerLogFormat(test.mode)
			if err != nil || got != test.want {
				t.Fatalf("resolveServerLogFormat(%q) = %q, %v; want %q", test.mode, got, err, test.want)
			}
		})
	}
}

func TestDaemonNarrationAndReadinessAreStructured(t *testing.T) {
	var stdout, stderr bytes.Buffer
	logger := slog.New(newServerLogHandler(&stderr, "json"))
	writeServerNarration(logger, "json", &stdout, "human startup narration", "kernel starting")
	if err := writeServerReady(serverOptions{Mode: "serve", Stdout: &stdout}, logger, "json", "127.0.0.1", 7714); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("structured daemon wrote plain stdout: %q", stdout.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("daemon emitted non-JSON line %q: %v", line, err)
		}
		for _, key := range []string{"timestamp", "level", "msg"} {
			if record[key] == nil {
				t.Fatalf("daemon record lacks %s: %v", key, record)
			}
		}
		if strings.Contains(line, "\x1b") {
			t.Fatalf("daemon record contains ANSI: %q", line)
		}
	}
}

func TestServerLogHandler(t *testing.T) {
	traceID := oteltrace.TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	spanID := oteltrace.SpanID{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	ctx := oteltrace.ContextWithSpanContext(context.Background(), oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID: traceID,
		SpanID:  spanID,
	}))

	t.Run("json by default", func(t *testing.T) {
		t.Setenv("HELM_LOG_FORMAT", "")
		var output bytes.Buffer
		format, err := resolveServerLogFormat("serve")
		if err != nil {
			t.Fatal(err)
		}
		handler := newServerLogHandler(&output, format)
		slog.New(handler).InfoContext(ctx, "request served", "status", http.StatusOK)

		var record map[string]any
		if err := json.Unmarshal(output.Bytes(), &record); err != nil {
			t.Fatalf("decode JSON log %q: %v", output.String(), err)
		}
		timestamp, ok := record["timestamp"].(string)
		if !ok {
			t.Fatalf("JSON log has no string timestamp: %v", record)
		}
		if _, err := time.Parse("2006-01-02T15:04:05.999Z07:00", timestamp); err != nil {
			t.Fatalf("timestamp %q does not match the collector contract: %v", timestamp, err)
		}
		assert.NotContains(t, record, "time")
		assert.Equal(t, "INFO", record["level"])
		assert.Equal(t, "request served", record["msg"])
		assert.Equal(t, float64(http.StatusOK), record["status"])
		assert.Equal(t, traceID.String(), record["trace_id"])
		assert.Equal(t, spanID.String(), record["span_id"])
	})

	t.Run("text is an explicit local opt-in", func(t *testing.T) {
		t.Setenv("HELM_LOG_FORMAT", "text")
		var output bytes.Buffer
		format, err := resolveServerLogFormat("serve")
		if err != nil {
			t.Fatal(err)
		}
		handler := newServerLogHandler(&output, format)
		slog.New(handler).InfoContext(ctx, "request served")
		assert.Contains(t, output.String(), "level=INFO")
		assert.Contains(t, output.String(), "trace_id="+traceID.String())
	})

	t.Run("unknown format fails closed", func(t *testing.T) {
		t.Setenv("HELM_LOG_FORMAT", "yaml")
		_, err := resolveServerLogFormat("serve")
		assert.EqualError(t, err, `invalid HELM_LOG_FORMAT "yaml": expected json or text`)
	})
}

// TestRunUnknownFlagDoesNotStartTheServer replaces the former
// TestRunLegacyServerFlagsReportStartupFailure, which pinned the opposite
// behaviour: any unrecognized flag fell through to startServer as a
// backward-compatible way to spell `serve`. The test's own fixture flag
// (--legacy-server-flag) shows the breadth of it — every typo started a
// listener and generated a persistent trust root in the working directory,
// with the guardian roster empty. This is a deliberate breaking change; the
// error names the flag and the explicit command that does start the server.
func TestRunUnknownFlagDoesNotStartTheServer(t *testing.T) {
	originalRunServer := startServer
	defer func() { startServer = originalRunServer }()
	started := false
	startServer = func() error {
		started = true
		return nil
	}

	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"helm", "--legacy-server-flag"}, &stdout, &stderr)

	assert.Equal(t, 2, exitCode)
	assert.False(t, started, "an unknown flag must not start the server")
	assert.Contains(t, stderr.String(), "Unknown flag: --legacy-server-flag")
	assert.Contains(t, stderr.String(), "helm-ai-kernel serve")
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

func TestRuntimeRateClassForRequest(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "/api/v1/evaluate", nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, string(RouteRateKernel), runtimeRateClassForRequest(req))

	req, err = http.NewRequest(http.MethodGet, "/unknown", nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, string(RouteRatePublic), runtimeRateClassForRequest(req))
}

func TestEnvIntFallback(t *testing.T) {
	t.Setenv("HELM_LIMIT_GLOBAL_RPS", "bad")
	assert.Equal(t, 60, envInt("HELM_LIMIT_GLOBAL_RPS", 60))
}

func TestConfigurePostgresPoolFromEnv(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	t.Setenv("HELM_DB_MAX_OPEN_CONNS", "7")
	t.Setenv("HELM_DB_MAX_IDLE_CONNS", "12")
	t.Setenv("HELM_DB_CONN_MAX_LIFETIME", "2m")
	configurePostgresPool(db)

	assert.Equal(t, 7, db.Stats().MaxOpenConnections)
}
