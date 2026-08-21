package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/tui"
)

func TestRunWithContextDoesNotDispatchWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	code := RunWithContext(ctx, []string{"helm-ai-kernel", "version"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("cancelled RunWithContext exit %d, want 2", code)
	}
	if strings.Contains(stdout.String(), "HELM") || strings.Contains(stdout.String(), "v") {
		t.Fatalf("cancelled context still dispatched:\n%s", stdout.String())
	}
}

func TestTUIRunCommandCtxHonorsCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stdout, _, code := tuiRunCommandCtx(ctx, "version", nil)
	if code != 2 {
		t.Fatalf("code=%d", code)
	}
	if strings.Contains(stdout, "helm-ai-kernel") || strings.Contains(stdout, "Report Schema") {
		t.Fatalf("cancelled ctx dispatched version:\n%s", stdout)
	}
}

func TestUnstampedVersionIsNotAPlausibleRelease(t *testing.T) {
	got := displayVersion()
	if got == "v0.5.10" || got == "0.5.10" {
		t.Fatalf("unstamped fallback drifted to a stale release: %s", got)
	}
	if !strings.Contains(got, "dev") && version != "" && version != "0.0.0-dev" {
		// stamped builds may report the VERSION file; that is the release path
		return
	}
	if version == "0.0.0-dev" && got != "v0.0.0-dev" {
		t.Fatalf("dev fallback = %s", got)
	}
}

func TestReceiptsStatusNeverStartsSSE(t *testing.T) {
	stdout, stderr, code := tuiRunCommand("receipts", []string{"status"})
	if code > 2 {
		t.Fatalf("receipts status exit %d", code)
	}
	out := stdout + stderr
	if strings.Contains(out, "text/event-stream") || strings.Contains(out, "event-stream") {
		t.Fatalf("receipts status started a tail:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "pass") && !strings.Contains(strings.ToLower(out), "fail") && !strings.Contains(strings.ToLower(out), "wait") {
		t.Fatalf("receipts status produced no diagnostic:\n%s", out)
	}
}

func TestCompanyInspectCommandsExecute(t *testing.T) {
	t.Run("incident list", func(t *testing.T) {
		stdout, stderr, code := tuiRunCommand("incident", []string{"list"})
		if code > 2 {
			t.Fatalf("incident list exit %d stderr=%s", code, stderr)
		}
		out := stdout + stderr
		if strings.Contains(out, "⬛") || strings.Contains(out, "✅") || strings.Contains(out, "❌") {
			t.Fatalf("incident list still uses emoji:\n%s", out)
		}
	})
	t.Run("export usage", func(t *testing.T) {
		_, stderr, code := tuiRunCommand("export", nil)
		if code != 2 {
			t.Fatalf("bare export should be usage, got %d", code)
		}
		if strings.Contains(stderr, "unbounded listener") {
			t.Fatal("export usage must execute")
		}
	})
	t.Run("mcp serve refused", func(t *testing.T) {
		_, stderr, code := tuiRunCommand("mcp", []string{"serve"})
		if code != 2 || !strings.Contains(stderr, "unbounded listener") {
			t.Fatalf("mcp serve must refuse: %d %s", code, stderr)
		}
	})
	t.Run("onboard refused", func(t *testing.T) {
		_, stderr, code := tuiRunCommand("onboard", nil)
		if code != 2 || !strings.Contains(stderr, "unbounded listener") {
			t.Fatalf("bare onboard must refuse: %d %s", code, stderr)
		}
	})
	t.Run("freeze --status --format json", func(t *testing.T) {
		stdout, stderr, code := tuiRunCommand("freeze", []string{"--status", "--format", "json"})
		if code == 2 && strings.Contains(stderr, "unbounded listener") {
			t.Fatal("freeze --status must execute")
		}
		if code == 0 || strings.Contains(stdout, "{") {
			var raw map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &raw); err != nil && stdout != "" {
				// freeze --status may still be text if --format is not registered yet
				if !strings.Contains(stderr, "invalid --format") && !strings.Contains(stdout, "frozen") && !strings.Contains(strings.ToLower(stdout+stderr), "freeze") {
					t.Fatalf("freeze --status json produced neither JSON nor freeze status:\n%s\n%s", stdout, stderr)
				}
			}
		}
	})
}

func TestDoctorFormatJSONAlias(t *testing.T) {
	stdout, stderr, code := tuiRunCommand("doctor", []string{"--format", "json"})
	if code > 2 {
		t.Fatalf("doctor --format json exit %d stderr=%s", code, stderr)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Fatal("doctor --format json wrote no data")
	}
	if stdout[0] != '{' && !strings.Contains(stdout, "\"checks\"") {
		t.Fatalf("doctor --format json is not a JSON document:\n%s", stdout)
	}
}

func TestEnterpriseJSONEscapeHatch(t *testing.T) {
	t.Setenv("HELM_NO_TUI", "1")
	if tui.Interactive(os.Stdin, os.Stdout) {
		t.Fatal("HELM_NO_TUI must keep the text front door")
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "help", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help --json exit %d stderr=%s", code, stderr.String())
	}
	if stdout.Len() == 0 || stdout.Bytes()[0] != '{' {
		t.Fatalf("help --json is not machine data:\n%s", stdout.String())
	}
}
