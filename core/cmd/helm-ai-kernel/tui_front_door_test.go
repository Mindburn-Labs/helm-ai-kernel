package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/tui"
)

// TestCatalogDefaultInvocationIsBounded is the production catalog loop:
// every commandCatalog() name is reachable through the real TUI runner
// (Dispatch / RunWithContext), finishes without hanging, and is either
// listener-refused or executable. A mock RunCommand would not catch a
// fake front door or a cwd walk.
func TestCatalogDefaultInvocationIsBounded(t *testing.T) {
	t.Chdir(t.TempDir())
	seen := make(map[string]struct{}, 80)
	catalog := commandCatalog()
	if len(catalog.Commands) < 20 {
		t.Fatalf("catalog too small to be the product front door: %d", len(catalog.Commands))
	}
	for _, cmd := range catalog.Commands {
		if _, ok := seen[cmd.Name]; ok {
			t.Errorf("duplicate catalog name %q", cmd.Name)
			continue
		}
		seen[cmd.Name] = struct{}{}
		cmd := cmd
		t.Run(cmd.Name, func(t *testing.T) {
			args := tui.DefaultArgs(cmd.Name)
			type result struct {
				stdout, stderr string
				code           int
			}
			done := make(chan result, 1)
			go func() {
				stdout, stderr, code := tuiRunCommand(cmd.Name, args)
				done <- result{stdout, stderr, code}
			}()
			var got result
			select {
			case got = <-done:
			case <-time.After(8 * time.Second):
				t.Fatalf("tuiRunCommand(%q, %v) hung — palette default must stay bounded", cmd.Name, args)
			}
			out := got.stdout + got.stderr
			if strings.Contains(out, "Run in a shell") || strings.Contains(out, "Next  helm-ai-kernel") {
				t.Fatalf("%s left a shell cheat sheet:\n%s", cmd.Name, out)
			}
			if tui.IsListenerVerb(cmd.Name, args) {
				if got.code != 2 || !strings.Contains(got.stderr, "unbounded listener") {
					t.Fatalf("listener %s %v must refuse: code=%d stderr=%s", cmd.Name, args, got.code, got.stderr)
				}
				return
			}
			if strings.Contains(got.stderr, "Unknown command") {
				t.Fatalf("catalog %s is not Dispatch-reachable:\n%s", cmd.Name, got.stderr)
			}
			if got.code > 2 {
				t.Fatalf("catalog %s crashed: code=%d stderr=%s", cmd.Name, got.code, got.stderr)
			}
			if looksLikeStartedListener(got.stdout) {
				t.Fatalf("catalog %s started a listener:\n%s", cmd.Name, got.stdout)
			}
		})
	}
}

func TestProductionTUISmokeVersionDoctorScan(t *testing.T) {
	t.Chdir(t.TempDir())
	host := tui.Host{
		Version:          displayVersion(),
		Commit:           displayCommit(),
		Commands:         tuiCommandsFromCatalog(),
		Doctor:           tuiDoctorSnapshot,
		Watch:            func(ctx context.Context) ([]tui.Approval, error) { return nil, nil },
		RunCommand:       tuiRunCommand,
		RunCommandCtx:    tuiRunCommandCtx,
		SetupSnapshot:    tuiSetupSnapshot,
		ReceiptsSnapshot: tuiReceiptsSnapshot,
	}

	t.Run("version executes through Host.RunCommand", func(t *testing.T) {
		done := make(chan string, 1)
		go func() { done <- tui.PaletteEnter(host, "version") }()
		var view string
		select {
		case view = <-done:
		case <-time.After(8 * time.Second):
			t.Fatal("palette version hung")
		}
		if strings.Contains(view, "Run in a shell") {
			t.Fatal("version left a cheat sheet")
		}
		if !strings.Contains(view, "helm-ai-kernel") && !strings.Contains(view, "v") && !strings.Contains(view, "0.8") {
			t.Fatalf("production version overlay missing Kernel identity:\n%s", view)
		}
	})

	t.Run("doctor opens the live doctor surface", func(t *testing.T) {
		done := make(chan string, 1)
		go func() { done <- tui.PaletteEnter(host, "doctor") }()
		var view string
		select {
		case view = <-done:
		case <-time.After(8 * time.Second):
			t.Fatal("palette doctor hung")
		}
		if !strings.Contains(view, "Doctor") {
			t.Fatalf("doctor surface missing:\n%s", view)
		}
		if strings.Contains(view, "Run in a shell") {
			t.Fatal("doctor left a cheat sheet")
		}
	})

	t.Run("scan palette default is help not a cwd walk", func(t *testing.T) {
		done := make(chan string, 1)
		go func() { done <- tui.PaletteEnter(host, "scan") }()
		var view string
		select {
		case view = <-done:
		case <-time.After(8 * time.Second):
			t.Fatal("palette scan hung — DefaultArgs must be --help")
		}
		if !strings.Contains(view, "helm-ai-kernel scan --help") {
			t.Fatalf("palette scan must run --help:\n%s", view)
		}
		if strings.Contains(view, "Content hash:") || strings.Contains(view, "MCP servers detected:") || strings.Contains(view, "Boundary grade:") {
			t.Fatalf("palette scan started a walk:\n%s", view)
		}
		if !strings.Contains(view, "Usage:") {
			t.Fatalf("palette scan produced no help:\n%s", view)
		}
	})
}
