package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestHomeViewContainsWedgeAndMenu(t *testing.T) {
	m := New(Host{
		Version: "v0.0.0-dev",
		Commit:  "abc123",
		Commands: []Command{
			{Name: "doctor", Usage: "Diagnose HELM setup", Group: "Get started"},
			{Name: "watch", Usage: "Review live decisions", Group: "Use HELM"},
		},
	})
	m.width, m.height = 100, 32
	got := m.View()
	for _, want := range []string{
		"HELM",
		wedge,
		"Doctor",
		"Watch queue",
		"Policy",
		"Freeze",
		"Threat",
		"All commands",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("home view missing %q\n%s", want, got)
		}
	}
}

func TestPaletteFiltersCatalog(t *testing.T) {
	m := New(Host{
		Commands: []Command{
			{Name: "doctor", Usage: "Diagnose HELM setup", Group: "Get started"},
			{Name: "watch", Usage: "Review live decisions", Group: "Use HELM"},
			{Name: "verify", Usage: "Verify EvidencePack", Group: "Evidence"},
		},
	})
	m.width, m.height = 100, 32
	m.screen = ScreenPalette
	m.filter = "ver"
	got := m.View()
	if !strings.Contains(got, "verify") {
		t.Fatalf("palette missing verify:\n%s", got)
	}
	if strings.Contains(got, "watch") {
		t.Fatalf("palette leaked unmatched command:\n%s", got)
	}
}

func TestDoctorViewKeepsStatusWords(t *testing.T) {
	m := New(Host{})
	m.width, m.height = 100, 32
	m.screen = ScreenDoctor
	m.doctor = []Check{
		{Name: "crypto_keys", Status: "pass", Message: "Ed25519 key present"},
		{Name: "policy_bundles", Status: "fail", Message: "No policy bundle found", Suggestion: "helm-ai-kernel setup --quickstart --yes"},
	}
	got := m.View()
	for _, want := range []string{"[PASS]", "[FAIL]", "crypto_keys", "policy_bundles", "Next"} {
		if !strings.Contains(got, want) {
			t.Fatalf("doctor view missing %q\n%s", want, got)
		}
	}
}

func TestDemoViewShowsDenyWithoutEmoji(t *testing.T) {
	m := New(Host{})
	m.width, m.height = 100, 40
	m.screen = ScreenDemo
	m.demoAt = len(demoBeats()) - 1
	got := m.View()
	for _, want := range []string{"[ALLOW]", "[DENY]", "Deny Details", "ERR_TOOL_NOT_ALLOWED", "EvidencePack"} {
		if !strings.Contains(got, want) {
			t.Fatalf("demo view missing %q\n%s", want, got)
		}
	}
	for _, bad := range []string{"✅", "❌", "🎉"} {
		if strings.Contains(got, bad) {
			t.Fatalf("demo view still uses emoji %q", bad)
		}
	}
}

func TestHomeHeaderShowsKernelAndPending(t *testing.T) {
	m := New(Host{Version: "v0.8.4", Commit: "abc123"})
	m.width, m.height = 100, 32
	m.approvals = []Approval{{ID: "a1", Subject: "deploy"}}
	got := m.View()
	for _, want := range []string{"HELM", "1 pending", "[WAIT]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("header missing %q\n%s", want, got)
		}
	}
	if !strings.Contains(got, ">") {
		t.Fatalf("composer prompt missing:\n%s", got)
	}
}

func TestSlashOpensCommandsOverlayWithCloseAffordance(t *testing.T) {
	m := New(Host{
		Commands: []Command{
			{Name: "doctor", Usage: "Diagnose HELM setup", Group: "Get started"},
			{Name: "watch", Usage: "Review live decisions", Group: "Use HELM"},
		},
	})
	m.width, m.height = 100, 32
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	got := next.(model)
	view := got.View()
	for _, want := range []string{"Commands", "[x]", "HELM", ">"} {
		if !strings.Contains(view, want) {
			t.Fatalf("commands overlay missing %q\n%s", want, view)
		}
	}
}

func TestEnterOnDoctorCommandOpensDoctorOverlay(t *testing.T) {
	m := New(Host{
		Commands: []Command{
			{Name: "doctor", Usage: "Diagnose HELM setup", Group: "Get started"},
		},
		Doctor: func() []Check {
			return []Check{{Name: "crypto_keys", Status: "fail", Message: "No keypair found", Suggestion: "setup --yes"}}
		},
	})
	m.width, m.height = 100, 32
	m.screen = ScreenPalette
	m.cursor = 0
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	view := got.View()
	if strings.Contains(view, "Run in a shell") {
		t.Fatalf("palette still a cheat sheet:\n%s", view)
	}
	for _, want := range []string{"Doctor", "[FAIL]", "crypto_keys", "[x]"} {
		if !strings.Contains(view, want) {
			t.Fatalf("doctor overlay missing %q\n%s", want, view)
		}
	}
}

func TestClickCloseDismissesCommandsOverlay(t *testing.T) {
	m := New(Host{Commands: []Command{{Name: "doctor", Usage: "Diagnose", Group: "Get started"}}})
	m.width, m.height = 100, 32
	m.screen = ScreenPalette
	_ = m.View()
	h, ok := m.hit(hitClose, 0)
	if !ok {
		t.Fatalf("commands overlay has no close hit; hits=%v", m.layout.hits)
	}
	next, _ := m.Update(tea.MouseMsg{
		X: h.x, Y: h.y,
		Action: tea.MouseActionPress,
		Button: tea.MouseButtonLeft,
	})
	got := next.(model)
	view := got.View()
	if strings.Contains(view, "Commands") && strings.Contains(view, "[x]") && got.activeOverlay() != overlayNone {
		t.Fatalf("click [x] did not close overlay:\n%s", view)
	}
	if !strings.Contains(view, "Doctor") || !strings.Contains(view, "Watch queue") {
		t.Fatalf("home missing after close:\n%s", view)
	}
}

func TestClickHomeRowOpensWatch(t *testing.T) {
	m := New(Host{})
	m.width, m.height = 100, 32
	_ = m.View()
	h, ok := m.hit(hitMenu, 1)
	if !ok {
		t.Fatalf("home has no watch row hit; hits=%v", m.layout.hits)
	}
	next, _ := m.Update(tea.MouseMsg{
		X: h.x, Y: h.y,
		Action: tea.MouseActionPress,
		Button: tea.MouseButtonLeft,
	})
	got := next.(model)
	view := got.View()
	if !strings.Contains(view, "Watch") {
		t.Fatalf("click watch row did not open watch:\n%s", view)
	}
}

func TestClickPendingOpensWatch(t *testing.T) {
	m := New(Host{})
	m.width, m.height = 100, 32
	m.approvals = []Approval{{ID: "a1", Subject: "deploy"}}
	_ = m.View()
	h, ok := m.hit(hitPending, 0)
	if !ok {
		t.Fatalf("header has no pending hit; hits=%v", m.layout.hits)
	}
	next, _ := m.Update(tea.MouseMsg{
		X: h.x, Y: h.y,
		Action: tea.MouseActionPress,
		Button: tea.MouseButtonLeft,
	})
	got := next.(model)
	if !strings.Contains(got.View(), "Watch") {
		t.Fatalf("click pending did not open watch:\n%s", got.View())
	}
}

func TestHeaderKernelPassOnlyAfterWatchSucceeds(t *testing.T) {
	m := New(Host{
		Watch: func(ctx context.Context) ([]Approval, error) {
			return []Approval{{ID: "a1"}}, nil
		},
	})
	m.width, m.height = 100, 32
	if !strings.Contains(m.View(), "[WAIT]") {
		t.Fatalf("header must stay WAIT until watch returns:\n%s", m.View())
	}
	next, _ := m.Update(watchMsg{items: []Approval{{ID: "a1"}}})
	got := next.(model)
	view := got.View()
	if !strings.Contains(view, "[PASS]") {
		t.Fatalf("reachable kernel missing [PASS]:\n%s", view)
	}
	if !strings.Contains(view, "1 pending") {
		t.Fatalf("pending count missing:\n%s", view)
	}
}

func TestDoctorOverlayKeepsGroups(t *testing.T) {
	m := New(Host{})
	m.width, m.height = 100, 36
	m.screen = ScreenDoctor
	m.doctor = []Check{
		{Name: "go_version", Status: "pass", Message: "go1.25"},
		{Name: "crypto_keys", Status: "fail", Message: "missing", Suggestion: "setup --yes"},
		{Name: "policy_bundles", Status: "warn", Message: "none"},
	}
	got := m.View()
	for _, want := range []string{"Environment", "Store", "Policy", "[PASS]", "[FAIL]", "[WARN]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("doctor groups missing %q\n%s", want, got)
		}
	}
}

func fixtureCatalog() []Command {
	return []Command{
		{Name: "doctor", Usage: "Diagnose HELM setup", Group: "Get started"},
		{Name: "watch", Usage: "Review live decisions", Group: "Use HELM"},
		{Name: "demo", Usage: "Run governed demonstrations", Group: "Get started"},
		{Name: "setup", Usage: "Install a local agent", Group: "Get started"},
		{Name: "receipts", Usage: "Tail signed receipts", Group: "Use HELM"},
		{Name: "help", Usage: "Show command help", Group: "Get started"},
		{Name: "tui", Usage: "Open the operator TUI", Group: "Get started"},
		{Name: "verify", Usage: "Verify EvidencePack", Group: "Evidence"},
		{Name: "freeze", Usage: "Activate global freeze", Group: "Operate"},
		{Name: "teardown", Usage: "Cascade teardown a run", Group: "Operate"},
		{Name: "policy", Usage: "Policy compilation", Group: "Operate"},
		{Name: "version", Usage: "Print version", Group: "Get started"},
	}
}

func trackingHost(cmds []Command, ran *[]string) Host {
	return Host{
		Commands: cmds,
		Doctor: func() []Check {
			return []Check{{Name: "crypto_keys", Status: "pass", Message: "Ed25519 key present"}}
		},
		Watch: func(ctx context.Context) ([]Approval, error) { return nil, nil },
		RunCommand: func(name string, args []string) (string, string, int) {
			*ran = append(*ran, name)
			return "RAN " + name + " " + strings.Join(args, " "), "err-" + name, 0
		},
	}
}

func TestPaletteEnterRunsEveryFixtureCommand(t *testing.T) {
	cmds := fixtureCatalog()
	var ran []string
	host := trackingHost(cmds, &ran)
	surfaces := map[string]string{
		"doctor":   "Doctor",
		"watch":    "Watch",
		"demo":     "Demo",
		"setup":    "Setup",
		"receipts": "Receipts",
		"tui":      "Commands",
		"policy":   "Policy",
	}
	for _, cmd := range cmds {
		ran = ran[:0]
		view := PaletteEnter(host, cmd.Name)
		if strings.Contains(view, "Run in a shell") || strings.Contains(view, "Next  helm-ai-kernel") {
			t.Fatalf("%s left a shell cheat sheet:\n%s", cmd.Name, view)
		}
		if title, ok := surfaces[cmd.Name]; ok {
			if !strings.Contains(view, title) {
				t.Fatalf("%s missing surface %q\n%s", cmd.Name, title, view)
			}
			continue
		}
		if len(ran) == 0 || ran[0] != cmd.Name {
			t.Fatalf("%s did not call runner (ran=%v)\n%s", cmd.Name, ran, view)
		}
		if !strings.Contains(view, "RAN "+cmd.Name) {
			t.Fatalf("%s output overlay missing runner stdout:\n%s", cmd.Name, view)
		}
	}
}

func TestClickPaletteRowRunsCommand(t *testing.T) {
	var ran []string
	host := trackingHost([]Command{
		{Name: "verify", Usage: "Verify EvidencePack", Group: "Evidence"},
	}, &ran)
	m := New(host)
	m.width, m.height = 100, 32
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = next.(model)
	_ = m.View()
	h, ok := m.hit(hitPalette, 0)
	if !ok {
		t.Fatalf("palette has no row hit; hits=%v", m.layout.hits)
	}
	next, cmd := m.Update(tea.MouseMsg{
		X: h.x, Y: h.y,
		Action: tea.MouseActionPress,
		Button: tea.MouseButtonLeft,
	})
	got := next.(model)
	if cmd != nil {
		if msg := cmd(); msg != nil {
			next, _ = got.Update(msg)
			got = next.(model)
		}
	}
	if len(ran) == 0 || ran[0] != "verify" {
		t.Fatalf("click did not run verify: ran=%v", ran)
	}
	if !strings.Contains(got.View(), "RAN verify") {
		t.Fatalf("click did not open output:\n%s", got.View())
	}
}

func TestComposerDestructiveRequiresFullArgv(t *testing.T) {
	var ran [][]string
	host := Host{
		Commands: []Command{{Name: "freeze", Usage: "Activate global freeze", Group: "Operate"}},
		RunCommand: func(name string, args []string) (string, string, int) {
			ran = append(ran, append([]string{name}, args...))
			return "ok", "", 0
		},
	}
	m := drivePaletteEnter(host, "freeze")
	m.composer = "freeze --principal alice"
	m.composing = true
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if got.activeOverlay() != overlayConfirm {
		t.Fatalf("destructive freeze opened %v, want confirm", got.activeOverlay())
	}
	if len(ran) > 1 {
		t.Fatalf("mutation ran before confirm: %v", ran)
	}
	got.confirmBuf = "freeze --principal alice"
	next, cmd := got.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if cmd != nil {
		if msg := cmd(); msg != nil {
			next, _ = got.Update(msg)
			got = next.(model)
		}
	}
	if len(ran) < 2 {
		t.Fatalf("confirmed freeze did not run: %v", ran)
	}
	last := ran[len(ran)-1]
	if last[0] != "freeze" || last[1] != "--principal" {
		t.Fatalf("confirmed args: %v", last)
	}
}

func TestSlashAfterRunOpensPaletteAgain(t *testing.T) {
	var ran []string
	host := trackingHost([]Command{{Name: "version", Usage: "Print version", Group: "Get started"}}, &ran)
	m := drivePaletteEnter(host, "version")
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	got := next.(model)
	if got.activeOverlay() != overlayPalette {
		t.Fatalf("slash after run did not reopen Commands: overlay=%v\n%s", got.activeOverlay(), got.View())
	}
	if !strings.Contains(got.View(), "Commands") {
		t.Fatalf("slash after run missing Commands overlay:\n%s", got.View())
	}
}

func TestOutputOverlayScrollsWithoutApproving(t *testing.T) {
	host := Host{
		Commands: []Command{{Name: "version", Usage: "Print version", Group: "Get started"}},
		RunCommand: func(name string, args []string) (string, string, int) {
			var b strings.Builder
			for i := 0; i < 40; i++ {
				b.WriteString(fmt.Sprintf("line-%d\n", i))
			}
			return b.String(), "", 0
		},
	}
	m := drivePaletteEnter(host, "version")
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	got := next.(model)
	if got.runScroll < 1 {
		t.Fatalf("j did not scroll output: scroll=%d", got.runScroll)
	}
	next, _ = got.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got = next.(model)
	if strings.Contains(got.View(), "APPROVE") && got.composer == "a" {
		// composer may contain "a"; watch ceremony must not fire
	}
	if strings.Contains(strings.ToLower(got.status), "approve") {
		t.Fatalf("output overlay treated a as APPROVE: %q", got.status)
	}
}

func TestHomeKeysOpenSurfaces(t *testing.T) {
	var ran []string
	m := New(trackingHost(fixtureCatalog(), &ran))
	m.width, m.height = 100, 36
	cases := []struct {
		key  string
		want string
	}{
		{"1", "Doctor"},
		{"2", "Watch"},
		{"3", "Policy"},
		{"4", "freeze"},
		{"5", "Threat"},
		{"6", "Commands"},
	}
	for _, tc := range cases {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tc.key)})
		got := next.(model)
		if !strings.Contains(got.View(), tc.want) {
			t.Fatalf("home %s missing %q\n%s", tc.key, tc.want, got.View())
		}
		m = New(trackingHost(fixtureCatalog(), &ran))
		m.width, m.height = 100, 36
	}
}

func TestWatchHasNoApproveHotkey(t *testing.T) {
	m := New(Host{
		Watch: func(ctx context.Context) ([]Approval, error) {
			return []Approval{{ID: "a1", Subject: "deploy"}}, nil
		},
	})
	m.width, m.height = 100, 32
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	got := next.(model)
	next, _ = got.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got = next.(model)
	view := got.View()
	if !strings.Contains(view, "Watch") {
		t.Fatalf("left watch after a:\n%s", view)
	}
	if strings.Contains(view, "approved") || strings.Contains(got.status, "APPROVE") {
		t.Fatalf("watch hotkeyed APPROVE:\n%s", view)
	}
}

func TestSetupRowExecutesClient(t *testing.T) {
	var ran [][]string
	host := Host{
		Commands: []Command{{Name: "setup", Usage: "Install a local agent", Group: "Get started"}},
		RunCommand: func(name string, args []string) (string, string, int) {
			ran = append(ran, append([]string{name}, args...))
			return "setup-ran", "", 0
		},
	}
	m := drivePaletteEnter(host, "setup")
	if !strings.Contains(m.View(), "claude-code") {
		t.Fatalf("setup overlay missing clients:\n%s", m.View())
	}
	m.cursor = 0
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if cmd != nil {
		if msg := cmd(); msg != nil {
			next, _ = got.Update(msg)
			got = next.(model)
		}
	}
	if len(ran) < 1 {
		t.Fatalf("setup row did not execute: %v", ran)
	}
	last := ran[len(ran)-1]
	if last[0] != "setup" || (len(last) > 1 && last[1] == "--yes") {
		t.Fatalf("setup row invoked mutating --yes: %v", last)
	}
	if !hasArg(last, "--dry-run") && last[1] != "status" && last[1] != "--client" {
		t.Fatalf("setup row should preview or inspect, got %v", last)
	}
	if !strings.Contains(got.View(), "setup-ran") && !strings.Contains(got.View(), "claude-code") {
		t.Fatalf("setup row did nothing:\n%s", got.View())
	}
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestClickPendingDoesNotApprove(t *testing.T) {
	var decided []string
	m := New(Host{
		Watch: func(ctx context.Context) ([]Approval, error) {
			return []Approval{{ID: "a1", Subject: "deploy"}}, nil
		},
		Decide: func(ctx context.Context, id, token string) (string, string, int) {
			decided = append(decided, id+":"+token)
			return "approved", "", 0
		},
	})
	m.width, m.height = 100, 32
	m.approvals = []Approval{{ID: "a1", Subject: "deploy"}}
	_ = m.View()
	h, ok := m.hit(hitPending, 0)
	if !ok {
		t.Fatalf("no pending hit")
	}
	next, _ := m.Update(tea.MouseMsg{X: h.x, Y: h.y, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	got := next.(model)
	next, _ = got.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	next, _ = got.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	got = next.(model)
	if len(decided) != 0 {
		t.Fatalf("click/enter/digit approved: %v", decided)
	}
	if strings.Contains(strings.ToLower(got.status), "approved") && !strings.Contains(got.View(), "APPROVE") {
		t.Fatalf("status claimed approval:\n%s", got.status)
	}
}

func TestCeremonyTokenDispatchesDecide(t *testing.T) {
	var decided []string
	m := New(Host{
		Decide: func(ctx context.Context, id, token string) (string, string, int) {
			decided = append(decided, id+":"+token)
			return "state=approved", "", 0
		},
	})
	m.width, m.height = 100, 32
	m.approvals = []Approval{{ID: "a1", Subject: "deploy", Summary: "prod"}}
	next, _ := m.openCeremony(0)
	got := next.(model)
	got.ceremonyToken = "APPROVE"
	next, cmd := got.submitCeremony()
	got = next.(model)
	if cmd != nil {
		if msg := cmd(); msg != nil {
			next, _ = got.Update(msg)
			got = next.(model)
		}
	}
	if len(decided) != 1 || decided[0] != "a1:APPROVE" {
		t.Fatalf("decide=%v", decided)
	}
}

func TestInjectionStaysArgv(t *testing.T) {
	var ran [][]string
	host := Host{
		Commands: []Command{{Name: "verify", Usage: "Verify", Group: "Evidence"}},
		RunCommand: func(name string, args []string) (string, string, int) {
			ran = append(ran, append([]string{name}, args...))
			return "ok", "", 0
		},
	}
	m := New(host)
	m.width, m.height = 100, 32
	m.composer = `verify "; echo pwned"`
	m.composing = true
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if cmd != nil {
		if msg := cmd(); msg != nil {
			next, _ = got.Update(msg)
			got = next.(model)
		}
	}
	if len(ran) != 1 || ran[0][0] != "verify" || ran[0][1] != `"; echo pwned"` {
		t.Fatalf("argv was not preserved: %v", ran)
	}
}

func TestNoShellCheatSheetOnFirstClassViews(t *testing.T) {
	var ran []string
	host := trackingHost(fixtureCatalog(), &ran)
	for _, name := range []string{"doctor", "watch", "demo", "setup", "receipts"} {
		view := PaletteEnter(host, name)
		if strings.Contains(view, "Run in a shell") || strings.Contains(view, "Next  helm-ai-kernel") {
			t.Fatalf("%s still a cheat sheet:\n%s", name, view)
		}
	}
}
