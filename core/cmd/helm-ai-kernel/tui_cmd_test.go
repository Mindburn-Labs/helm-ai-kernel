package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/tui"
)

func TestTUICommandsCoverCatalog(t *testing.T) {
	catalog := commandCatalog()
	got := tuiCommandsFromCatalog()
	if len(got) != len(catalog.Commands) {
		t.Fatalf("tui commands %d != catalog %d", len(got), len(catalog.Commands))
	}
	names := map[string]struct{}{}
	for _, cmd := range got {
		names[cmd.Name] = struct{}{}
	}
	for _, cmd := range catalog.Commands {
		if _, ok := names[cmd.Name]; !ok {
			t.Fatalf("catalog command %q missing from TUI host", cmd.Name)
		}
	}
}

func TestTUICatalogPaletteEnterInvokesRunnerOrSurface(t *testing.T) {
	catalog := tuiCommandsFromCatalog()
	if len(catalog) < 20 {
		t.Fatalf("catalog too small to exercise the operator surface: %d", len(catalog))
	}
	var ran []string
	host := tui.Host{
		Commands: catalog,
		Doctor: func() []tui.Check {
			return []tui.Check{{Name: "crypto_keys", Status: "pass", Message: "ok"}}
		},
		Watch: func(ctx context.Context) ([]tui.Approval, error) { return nil, nil },
		RunCommand: func(name string, args []string) (string, string, int) {
			ran = append(ran[:0], name)
			return "RAN " + name, "", 0
		},
	}
	surfaces := map[string]string{
		"doctor":    "Doctor",
		"watch":     "Watch",
		"demo":      "Demo",
		"setup":     "Setup",
		"receipts":  "Receipts",
		"tui":       "Commands",
		"ui":        "Commands",
		"dashboard": "Commands",
		"policy":    "Policy",
		"threat":    "Threat",
		"incident":  "Incident",
	}
	for _, cmd := range catalog {
		ran = ran[:0]
		view := tui.PaletteEnter(host, cmd.Name)
		if strings.Contains(view, "Run in a shell") || strings.Contains(view, "Next  helm-ai-kernel") {
			t.Errorf("%s left a shell cheat sheet", cmd.Name)
			continue
		}
		if tui.IsListenerVerb(cmd.Name, tui.DefaultArgs(cmd.Name)) {
			if !strings.Contains(view, "unbounded listener") {
				t.Errorf("%s did not refuse listener:\n%s", cmd.Name, view)
			}
			if len(ran) != 0 {
				t.Errorf("%s started a listener via runner: %v", cmd.Name, ran)
			}
			continue
		}
		if title, ok := surfaces[cmd.Name]; ok {
			if !strings.Contains(view, title) {
				t.Errorf("%s missing surface %q", cmd.Name, title)
			}
			continue
		}
		if len(ran) == 0 || ran[0] != cmd.Name {
			t.Errorf("%s did not call runner (ran=%v)", cmd.Name, ran)
			continue
		}
		if !strings.Contains(view, "RAN "+cmd.Name) && !strings.Contains(view, cmd.Name) {
			t.Errorf("%s output overlay missing command", cmd.Name)
		}
	}
}

func TestTUIRunCommandProductionSeams(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Run("version", func(t *testing.T) {
		stdout, stderr, code := tuiRunCommand("version", nil)
		if code != 0 {
			t.Fatalf("version exit %d stderr=%s", code, stderr)
		}
		if !strings.Contains(stdout, "helm-ai-kernel") && !strings.Contains(stdout, "v") {
			t.Fatalf("version produced no data:\n%s", stdout)
		}
	})
	t.Run("help --all", func(t *testing.T) {
		stdout, stderr, code := tuiRunCommand("help", []string{"--all"})
		if code != 0 {
			t.Fatalf("help --all exit %d stderr=%s", code, stderr)
		}
		if !strings.Contains(stdout, "doctor") || !strings.Contains(stdout, "watch") {
			t.Fatalf("help --all missing catalog:\n%s", stdout)
		}
	})
	t.Run("doctor", func(t *testing.T) {
		stdout, stderr, code := tuiRunCommand("doctor", nil)
		if code > 2 {
			t.Fatalf("doctor exit %d stderr=%s", code, stderr)
		}
		out := stdout + stderr
		if !strings.Contains(strings.ToLower(out), "pass") && !strings.Contains(strings.ToLower(out), "fail") && !strings.Contains(strings.ToLower(out), "warn") {
			t.Fatalf("doctor produced no diagnostic:\n%s", out)
		}
	})
	t.Run("freeze --status", func(t *testing.T) {
		_, stderr, code := tuiRunCommand("freeze", []string{"--status"})
		if code == 0 && strings.Contains(stderr, "unbounded listener") {
			t.Fatal("status inspect was refused as a listener")
		}
		if code == 2 && strings.Contains(stderr, "unbounded listener") {
			t.Fatal("freeze --status must execute")
		}
	})
	t.Run("setup status", func(t *testing.T) {
		stdout, stderr, code := tuiRunCommand("setup", []string{"status"})
		if code != 0 && code != 1 && code != 2 {
			t.Fatalf("setup status exit %d", code)
		}
		if strings.Contains(stdout+stderr, "unbounded listener") {
			t.Fatal("setup status must not be treated as a listener")
		}
	})
	t.Run("server refused", func(t *testing.T) {
		_, stderr, code := tuiRunCommand("server", nil)
		if code != 2 {
			t.Fatalf("server exit %d, want 2", code)
		}
		if !strings.Contains(stderr, "unbounded listener") {
			t.Fatalf("server must be fail-closed:\n%s", stderr)
		}
	})
	t.Run("serve --policy refused", func(t *testing.T) {
		_, stderr, code := tuiRunCommand("serve", []string{"--policy", "p.toml"})
		if code != 2 || !strings.Contains(stderr, "unbounded listener") {
			t.Fatalf("serve --policy must refuse: %d %s", code, stderr)
		}
	})
	t.Run("scan without help refused", func(t *testing.T) {
		for _, args := range [][]string{nil, {"--path", "."}} {
			stdout, stderr, code := tuiRunCommand("scan", args)
			if code != 2 || !strings.Contains(stderr, "unbounded listener") {
				t.Fatalf("scan %v must refuse: %d %s", args, code, stderr)
			}
			if strings.Contains(stdout+stderr, "Content hash:") || strings.Contains(stdout+stderr, "MCP servers detected:") {
				t.Fatalf("scan %v started a walk:\n%s\n%s", args, stdout, stderr)
			}
		}
	})
	t.Run("injection stays argv", func(t *testing.T) {
		stdout, stderr, _ := tuiRunCommand("help", []string{` --all; echo pwned`})
		if strings.Contains(stdout+stderr, "pwned") && !strings.Contains(stdout+stderr, ` --all; echo pwned`) {
			t.Fatalf("injection produced a shell side effect:\n%s\n%s", stdout, stderr)
		}
	})
	t.Run("tui re-entry", func(t *testing.T) {
		stdout, _, code := tuiRunCommand("tui", nil)
		if code != 0 || !strings.Contains(stdout, "Already in the operator TUI") {
			t.Fatalf("tui re-entry: %d %s", code, stdout)
		}
	})
}

func TestShouldLaunchTUIEscapeHatches(t *testing.T) {
	var buf bytes.Buffer
	if shouldLaunchTUI([]string{"helm-ai-kernel"}, &buf) {
		t.Fatal("non-file stdout must not launch TUI")
	}
	t.Setenv("HELM_NO_TUI", "1")
	if shouldLaunchTUI([]string{"helm-ai-kernel"}, os.Stdout) {
		t.Fatal("HELM_NO_TUI must keep the text front door")
	}
	t.Setenv("HELM_NO_TUI", "")
	t.Setenv("TERM", "dumb")
	if tui.Interactive(os.Stdin, os.Stdout) {
		t.Fatal("TERM=dumb must not be interactive")
	}
}

func TestTUIDecideRejectsBadToken(t *testing.T) {
	_, stderr, code := tuiDecide(context.Background(), "a1", "yes")
	if code != 2 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stderr, "APPROVE or DENY") {
		t.Fatalf("stderr=%s", stderr)
	}
}
