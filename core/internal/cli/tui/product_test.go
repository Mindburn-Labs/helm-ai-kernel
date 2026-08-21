package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestEscAbortDiscardsLateRunResult(t *testing.T) {
	started := make(chan struct{})
	host := Host{
		RunCommandCtx: func(ctx context.Context, name string, args []string) (string, string, int) {
			close(started)
			<-ctx.Done()
			return "SHOULD-NOT-SHOW late stdout", "SHOULD-NOT-SHOW late stderr", 0
		},
	}
	m := New(host)
	m.width, m.height = 100, 32
	next, cmd := m.startRun("version", nil)
	m = next.(model)
	if !m.running {
		t.Fatal("run did not start")
	}
	next, _ = m.abortRun()
	m = next.(model)
	if m.running {
		t.Fatal("abort left running=true")
	}
	if cmd == nil {
		t.Fatal("startRun returned no cmd")
	}
	msg := cmd()
	next, _ = m.Update(msg)
	m = next.(model)
	view := m.View()
	if strings.Contains(view, "SHOULD-NOT-SHOW") {
		t.Fatalf("late Run result leaked into the overlay:\n%s", view)
	}
	if !strings.Contains(view, "cancelled") {
		t.Fatalf("abort did not record a discarded result:\n%s", view)
	}
}

func TestSetupOverlayShowsLiveClientSnapshot(t *testing.T) {
	host := Host{
		Commands: []Command{{Name: "setup", Usage: "Install a local agent", Group: "Get started"}},
		SetupSnapshot: func() []SnapshotRow {
			return []SnapshotRow{{Name: "claude-code", Status: "WAIT", Message: "absent"}}
		},
	}
	m := drivePaletteEnter(host, "setup")
	if !strings.Contains(m.View(), "[WAIT]") {
		t.Fatalf("setup first paint must not be blank:\n%s", m.View())
	}
	next, _ := m.Update(setupMsg{rows: []SnapshotRow{{Name: "claude-code", Status: "WAIT", Message: "absent"}}})
	got := next.(model)
	view := got.View()
	for _, want := range []string{"claude-code", "[WAIT]", "absent"} {
		if !strings.Contains(view, want) {
			t.Fatalf("setup snapshot missing %q\n%s", want, view)
		}
	}
}

func TestReceiptsOverlayShowsLiveSnapshot(t *testing.T) {
	host := Host{
		Commands: []Command{{Name: "receipts", Usage: "Tail signed receipts", Group: "Use HELM"}},
		ReceiptsSnapshot: func() []SnapshotRow {
			return []SnapshotRow{{Name: "edge", Status: "FAIL", Message: "receipt stream unavailable"}}
		},
	}
	m := drivePaletteEnter(host, "receipts")
	if !strings.Contains(m.View(), "[WAIT]") && !strings.Contains(m.View(), "Receipts") {
		t.Fatalf("receipts first paint must not be blank:\n%s", m.View())
	}
	next, _ := m.Update(receiptsMsg{rows: []SnapshotRow{{Name: "edge", Status: "FAIL", Message: "receipt stream unavailable"}}})
	got := next.(model)
	view := got.View()
	for _, want := range []string{"[FAIL]", "receipt stream unavailable"} {
		if !strings.Contains(view, want) {
			t.Fatalf("receipts snapshot missing %q\n%s", want, view)
		}
	}
	if strings.Contains(view, "event-stream") || strings.Contains(view, "text/event-stream") {
		t.Fatal("receipts preload must not start SSE tail")
	}
}

func TestOnboardAndSetupQuickstartAreListenersWithoutDryRun(t *testing.T) {
	if !IsListenerVerb("onboard", nil) {
		t.Fatal("bare onboard forwards to quickstart and must be refused")
	}
	if IsListenerVerb("onboard", []string{"--dry-run"}) {
		t.Fatal("onboard --dry-run is a preview")
	}
	if !IsListenerVerb("setup", []string{"--quickstart"}) {
		t.Fatal("setup --quickstart binds unless --dry-run")
	}
	if IsListenerVerb("setup", []string{"--quickstart", "--dry-run"}) {
		t.Fatal("setup --quickstart --dry-run is a preview")
	}
	if !IsListenerVerb("mcp", []string{"serve"}) {
		t.Fatal("mcp serve must stay refused")
	}
	if IsListenerVerb("mcp", []string{"scan"}) {
		t.Fatal("mcp scan is inspect and must not be listener-refused")
	}
	if IsListenerVerb("mcp", DefaultArgs("mcp")) {
		t.Fatal("palette default mcp scan must not be listener-refused")
	}
	if !IsListenerVerb("receipts", []string{"tail"}) {
		t.Fatal("receipts tail must stay listener-refused")
	}
}

func TestVibecoderJourneyOpensDemoSetupDoctorWatch(t *testing.T) {
	var ran [][]string
	host := Host{
		Commands: fixtureCatalog(),
		Doctor: func() []Check {
			return []Check{{Name: "crypto_keys", Status: "pass", Message: "Ed25519 key present"}}
		},
		Watch: func(ctx context.Context) ([]Approval, error) { return nil, nil },
		SetupSnapshot: func() []SnapshotRow {
			return []SnapshotRow{{Name: "codex", Status: "WAIT", Message: "absent"}}
		},
		RunCommand: func(name string, args []string) (string, string, int) {
			ran = append(ran, append([]string{name}, args...))
			return "RAN " + name, "", 0
		},
	}
	demo := drivePaletteEnter(host, "demo")
	if !strings.Contains(demo.View(), "organization") {
		t.Fatalf("demo picker missing:\n%s", demo.View())
	}
	demo.cursor = 0
	next, cmd := demo.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if cmd != nil {
		if msg := cmd(); msg != nil {
			next, _ = got.Update(msg)
			got = next.(model)
		}
	}
	if len(ran) == 0 || ran[len(ran)-1][0] != "demo" {
		t.Fatalf("demo row did not execute: %v", ran)
	}
	if hasArg(ran[len(ran)-1], "--yes") {
		t.Fatalf("demo defaulted to --yes: %v", ran[len(ran)-1])
	}

	setup := drivePaletteEnter(host, "setup")
	if !strings.Contains(setup.View(), "claude-code") {
		t.Fatalf("setup journey missing clients:\n%s", setup.View())
	}

	doctor := drivePaletteEnter(host, "doctor")
	if !strings.Contains(doctor.View(), "crypto_keys") {
		t.Fatalf("doctor journey missing live checks:\n%s", doctor.View())
	}

	watch := drivePaletteEnter(host, "watch")
	if !strings.Contains(watch.View(), "Watch") {
		t.Fatalf("watch journey missing:\n%s", watch.View())
	}
}

func TestCompanyJourneyInspectsWithoutMutating(t *testing.T) {
	var ran [][]string
	host := Host{
		Commands: append(fixtureCatalog(),
			Command{Name: "incident", Usage: "Manage incidents", Group: "Operate"},
			Command{Name: "export", Usage: "Export EvidencePack sections", Group: "Evidence"},
			Command{Name: "threat", Usage: "Run a threat scan", Group: "Operate"},
		),
		RunCommand: func(name string, args []string) (string, string, int) {
			ran = append(ran, append([]string{name}, args...))
			return "RAN " + name, "", 0
		},
	}
	for _, name := range []string{"policy", "threat", "incident", "freeze"} {
		view := PaletteEnter(host, name)
		if strings.Contains(view, "Run in a shell") {
			t.Fatalf("%s left a cheat sheet", name)
		}
	}
	if !strings.Contains(PaletteEnter(host, "incident"), "Incident") && !strings.Contains(PaletteEnter(host, "incident"), "list") {
		t.Fatalf("incident missing inspect surface:\n%s", PaletteEnter(host, "incident"))
	}
	freeze := drivePaletteEnter(host, "freeze")
	if freeze.activeOverlay() == overlayConfirm {
		t.Fatal("freeze default must inspect, not confirm a mutation")
	}
}

func TestEnterpriseEscapeHatchesStayHeadless(t *testing.T) {
	if Interactive(nil, nil) {
		t.Fatal("nil streams must not be interactive")
	}
}
