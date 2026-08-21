package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestPaletteRanksDoctorAndOperateBeforeGetStarted(t *testing.T) {
	m := New(Host{
		Commands: []Command{
			{Name: "demo", Usage: "Run governed demonstrations", Group: "Get started"},
			{Name: "freeze", Usage: "Inspect freeze status", Group: "Operate"},
			{Name: "doctor", Usage: "Diagnose HELM setup", Group: "Get started"},
		},
	})
	m.width, m.height = 100, 32
	m.screen = ScreenPalette
	got := m.View()
	doc, freeze, demo := strings.Index(got, "doctor"), strings.Index(got, "freeze"), strings.Index(got, "demo")
	if doc < 0 || freeze < 0 || demo < 0 {
		t.Fatalf("palette missing doctor/freeze/demo:\n%s", got)
	}
	if doc > freeze {
		t.Fatalf("doctor must rank before freeze:\n%s", got)
	}
	if freeze > demo {
		t.Fatalf("Operate freeze must rank before Get started demo:\n%s", got)
	}
}

func TestHeaderNamesPendingAsCeremonyQueue(t *testing.T) {
	m := New(Host{Version: "v0.8.4", Commit: "abc123"})
	m.width, m.height = 100, 32
	m.approvals = []Approval{{ID: "a1", Subject: "deploy"}}
	got := m.View()
	if !strings.Contains(got, "1 pending ceremony") {
		t.Fatalf("header must name the ceremony queue:\n%s", got)
	}
	if strings.Count(strings.Split(got, "\n")[0], "·") > 1 {
		t.Fatalf("header line uses too many middle-dots:\n%s", strings.Split(got, "\n")[0])
	}
}

func TestComposerIdleHintsArgvOnly(t *testing.T) {
	m := New(Host{})
	m.width, m.height = 100, 32
	got := m.View()
	if !strings.Contains(got, ">") {
		t.Fatalf("composer prompt missing:\n%s", got)
	}
	if !strings.Contains(got, "Kernel verb") {
		t.Fatalf("idle composer must hint argv, not a chat box:\n%s", got)
	}
}

func TestPaletteEmptyStateExplainsFilter(t *testing.T) {
	m := New(Host{
		Commands: []Command{{Name: "doctor", Usage: "Diagnose HELM setup", Group: "Get started"}},
	})
	m.width, m.height = 100, 32
	m.setOverlay(overlayPalette)
	m.filter = "zzzz-no-match"
	got := m.View()
	if strings.Contains(got, "doctor") && strings.Contains(got, "Diagnose") {
		t.Fatalf("filtered palette leaked unmatched command:\n%s", got)
	}
	if !strings.Contains(got, "No match") {
		t.Fatalf("empty palette missing operator empty state:\n%s", got)
	}
}

func TestLoadedEmptySetupIsNotLoadingTheater(t *testing.T) {
	m := New(Host{})
	m.width, m.height = 100, 36
	m.setOverlay(overlaySetup)
	m.setupLoaded = true
	m.setupRows = nil
	got := m.View()
	if strings.Contains(got, "loading client status") {
		t.Fatalf("loaded empty setup still says loading:\n%s", got)
	}
	if !strings.Contains(got, "--dry-run") {
		t.Fatalf("empty setup must say how to populate without --yes:\n%s", got)
	}
}

func TestLoadedEmptyReceiptsIsNotLoadingTheater(t *testing.T) {
	m := New(Host{})
	m.width, m.height = 100, 36
	m.setOverlay(overlayReceipts)
	m.receiptsLoaded = true
	m.receiptRows = nil
	got := m.View()
	if strings.Contains(got, "loading receipts edge") {
		t.Fatalf("loaded empty receipts still says loading:\n%s", got)
	}
	if !strings.Contains(got, "bounded HTTP") {
		t.Fatalf("empty receipts must say how to populate without SSE:\n%s", got)
	}
}

func TestCeremonyEmptyStateStaysTyped(t *testing.T) {
	m := New(Host{})
	m.width, m.height = 100, 32
	m.setOverlay(overlayCeremony)
	got := m.View()
	if !strings.Contains(got, "APPROVE") || !strings.Contains(got, "DENY") {
		t.Fatalf("empty ceremony must keep typed tokens:\n%s", got)
	}
	if strings.Contains(got, "click to APPROVE") || strings.Contains(got, "press 1-9 to approve") {
		t.Fatalf("ceremony empty state must stay typed:\n%s", got)
	}
}

func TestOutputEmptyNamesKernelSilence(t *testing.T) {
	m := New(Host{})
	m.width, m.height = 100, 32
	m.run = commandRun{Name: "version", Code: 0}
	m.setOverlay(overlayOutput)
	got := m.View()
	if strings.Contains(got, "(no output)") {
		t.Fatalf("output empty state is still a stub:\n%s", got)
	}
	if !strings.Contains(got, "no stdout") {
		t.Fatalf("output empty state missing Kernel silence copy:\n%s", got)
	}
}

func TestEscalateTokenIsNotPurple(t *testing.T) {
	p := helmPalette()
	if p.escalate.Light != "#C2410C" || p.escalate.Dark != "#FB923C" {
		t.Fatalf("escalate=%+v, want burnt orange not purple", p.escalate)
	}
}

func TestDemoHasNoAcme(t *testing.T) {
	m := New(Host{})
	m.width, m.height = 100, 40
	m.screen = ScreenDemo
	m.demoAt = len(demoBeats()) - 1
	got := m.View()
	if strings.Contains(got, "Acme") {
		t.Fatalf("demo still uses Acme:\n%s", got)
	}
	if !strings.Contains(got, "mock") {
		t.Fatalf("demo must name the mock organization, not a fake firm:\n%s", got)
	}
}

func TestChromeHasNoEmDash(t *testing.T) {
	m := New(Host{
		Commands: []Command{
			{Name: "doctor", Usage: "Diagnose HELM setup", Group: "Get started"},
			{Name: "demo", Usage: "Run governed demonstrations", Group: "Get started"},
		},
		Doctor: func() []Check {
			return []Check{{Name: "crypto_keys", Status: "fail", Message: "missing", Suggestion: "setup --dry-run"}}
		},
	})
	m.width, m.height = 100, 36
	m.approvals = []Approval{{ID: "a1", Subject: "deploy"}}
	views := []string{m.View()}
	m.screen = ScreenDemo
	m.demoAt = len(demoBeats()) - 1
	views = append(views, m.View())
	m.screen = ScreenWatch
	views = append(views, m.View())
	m.setOverlay(overlayPalette)
	views = append(views, m.View())
	m.setOverlay(overlayCeremony)
	views = append(views, m.View())
	m.setOverlay(overlayOutput)
	m.run = commandRun{Name: "version"}
	views = append(views, m.View())
	for _, got := range views {
		if strings.Contains(got, "—") || strings.Contains(got, "–") {
			t.Fatalf("visible chrome still uses em/en-dash:\n%s", got)
		}
	}
}

func TestClickPendingStillOpensWatchAfterCeremonyLabel(t *testing.T) {
	m := New(Host{})
	m.width, m.height = 100, 32
	m.approvals = []Approval{{ID: "a1", Subject: "deploy"}}
	_ = m.View()
	h, ok := m.hit(hitPending, 0)
	if !ok {
		t.Fatalf("header has no ceremony-queue hit; hits=%v", m.layout.hits)
	}
	next, _ := m.Update(tea.MouseMsg{
		X: h.x, Y: h.y,
		Action: tea.MouseActionPress,
		Button: tea.MouseButtonLeft,
	})
	got := next.(model)
	if !strings.Contains(got.View(), "Watch") {
		t.Fatalf("click ceremony queue did not open watch:\n%s", got.View())
	}
}
