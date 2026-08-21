package tui

// quantum_posture: TUI chrome tells operators to trust only Ed25519/SHA-256/JCS
// receipts; the TUI is not a verifier and claims no post-quantum control.

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type commandRun struct {
	Name   string
	Args   []string
	Stdout string
	Stderr string
	Code   int
}

type actionRow struct {
	label  string
	detail string
	name   string
	args   []string
}

type runDoneMsg struct {
	seq int
	run commandRun
}

type refreshTickMsg time.Time

// DefaultArgs is the fail-closed invocation used when a catalog command is
// selected with no extra composer text. Never --yes, never a listener bind,
// never a write (init stays --help).
func DefaultArgs(name string) []string {
	switch name {
	case "demo":
		return nil
	case "help":
		return []string{"--all"}
	case "watch":
		return []string{"--once"}
	case "setup":
		return []string{"status"}
	case "onboard":
		return []string{"--dry-run"}
	case "incident":
		return []string{"list"}
	case "freeze", "unfreeze":
		return []string{"--status"}
	case "quickstart":
		return []string{"--dry-run"}
	case "mcp":
		return []string{"scan"}
	case "init", "scaffold":
		return []string{"--help"}
	case "scan":
		// Bare scan walks --path . and writes a salt file. Palette must
		// not start an unbounded walk the TUI cannot abort.
		return []string{"--help"}
	default:
		return nil
	}
}

func setupActions() []actionRow {
	return []actionRow{
		{label: "claude-code", detail: "Preview MCP + hook setup", name: "setup", args: []string{"claude-code", "--dry-run"}},
		{label: "codex", detail: "Preview MCP + hook setup", name: "setup", args: []string{"codex", "--dry-run"}},
		{label: "hermes", detail: "Preview fail-closed hook setup", name: "setup", args: []string{"hermes", "--dry-run"}},
		{label: "deepseek", detail: "Preview fail-closed hook setup", name: "setup", args: []string{"deepseek", "--dry-run"}},
		{label: "cursor", detail: "Print config only", name: "setup", args: []string{"--client", "cursor", "--print-config"}},
		{label: "windsurf", detail: "Print config only", name: "setup", args: []string{"--client", "windsurf", "--print-config"}},
		{label: "vscode", detail: "Print config only", name: "setup", args: []string{"--client", "vscode", "--print-config"}},
		{label: "status", detail: "Inspect installed clients", name: "setup", args: []string{"status"}},
		{label: "repair", detail: "Preview repair", name: "setup", args: []string{"repair", "claude-code", "--dry-run"}},
		{label: "remove", detail: "Preview removal", name: "setup", args: []string{"remove", "claude-code", "--dry-run"}},
	}
}

func receiptActions() []actionRow {
	return []actionRow{
		{label: "status", detail: "bounded edge check, never SSE", name: "receipts", args: []string{"status"}},
		{label: "list", detail: "bounded HTTP list, never SSE", name: "receipts", args: []string{"list"}},
		{label: "show", detail: "usage, needs an id", name: "receipts", args: []string{"show"}},
		{label: "verify", detail: "alias of verify receipt", name: "receipts", args: []string{"verify"}},
		{label: "export", detail: "alias of export", name: "receipts", args: []string{"export"}},
		{label: "catalog", detail: "help --json", name: "help", args: []string{"--json"}},
	}
}

func incidentActions() []actionRow {
	return []actionRow{
		{label: "list", detail: "inspect open incidents", name: "incident", args: []string{"list"}},
		{label: "show", detail: "usage, needs an id", name: "incident", args: []string{"show"}},
	}
}

func mcpActions() []actionRow {
	return []actionRow{
		{label: "list", detail: "local registry", name: "mcp", args: []string{"list"}},
		{label: "print-config", detail: "print client config", name: "mcp", args: []string{"print-config"}},
		{label: "scan", detail: "static catalog scan", name: "mcp", args: []string{"scan"}},
	}
}

func demoActions() []actionRow {
	return []actionRow{
		{label: "organization", detail: "Canonical starter demo (mock provider)", name: "demo", args: []string{"organization", "--provider", "mock"}},
		{label: "research-lab", detail: "Research-lab reference", name: "demo", args: []string{"research-lab"}},
		{label: "finance", detail: "Payment-approval escalation", name: "demo", args: []string{"finance"}},
		{label: "mcp", detail: "MCP governance proofs", name: "demo", args: []string{"mcp"}},
	}
}

func policyActions() []actionRow {
	return []actionRow{
		{label: "test", detail: "policy test", name: "policy", args: []string{"test"}},
		{label: "templates", detail: "list templates", name: "policy", args: []string{"templates"}},
		{label: "init", detail: "usage, writes policies/ unless you type the full argv", name: "policy", args: []string{"init", "--help"}},
		{label: "simulate", detail: "usage for simulate", name: "policy", args: []string{"simulate"}},
		{label: "export cedar", detail: "view, not source of truth", name: "policy", args: []string{"export", "--dialect", "cedar"}},
	}
}

func threatActions() []actionRow {
	return []actionRow{
		{label: "scan", detail: "threat scan", name: "threat", args: []string{"scan"}},
		{label: "test", detail: "threat test", name: "threat", args: []string{"test"}},
	}
}

func sameArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func pickerFor(name string) (title string, rows []actionRow, ok bool) {
	switch name {
	case "setup":
		return "Setup", setupActions(), true
	case "receipts":
		return "Receipts", receiptActions(), true
	case "demo":
		return "Demo", demoActions(), true
	case "policy":
		return "Policy", policyActions(), true
	case "threat":
		return "Threat", threatActions(), true
	case "incident":
		return "Incident", incidentActions(), true
	case "mcp":
		return "MCP", mcpActions(), true
	default:
		return "", nil, false
	}
}

// PaletteEnter filters Commands to name and presses Enter. Used by tests at
// the View/Update seam.
func PaletteEnter(host Host, name string) string {
	return drivePaletteEnter(host, name).View()
}

func drivePaletteEnter(host Host, name string) model {
	m := New(host)
	m.width, m.height = 120, 40
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = next.(model)
	m.filter = name
	m.filtering = true
	for i, c := range m.filteredCommands() {
		if c.Name == name {
			m.cursor = i
			break
		}
	}
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(model)
	if cmd != nil {
		if msg := cmd(); msg != nil {
			next, _ = m.Update(msg)
			m = next.(model)
		}
	}
	return m
}

func (m model) openPaletteSelection() (tea.Model, tea.Cmd) {
	cmds := m.filteredCommands()
	if m.cursor < 0 || m.cursor >= len(cmds) {
		return m, nil
	}
	name := cmds[m.cursor].Name
	return m.activateCommand(name, DefaultArgs(name))
}

func (m model) activateCommand(name string, args []string) (tea.Model, tea.Cmd) {
	m.filtering = false
	m.filter = ""
	m.composing = true
	m.composer = strings.TrimSpace(name + " " + strings.Join(args, " "))
	m.runScroll = 0

	if IsListenerVerb(name, args) {
		m.run = commandRun{
			Name:   name,
			Args:   append([]string(nil), args...),
			Stderr: ListenerRefuseMessage,
			Code:   2,
		}
		m.setOverlay(overlayOutput)
		m.status = "listener refused. Fail-closed"
		return m, nil
	}

	if IsDestructive(name, args) {
		m.pendingName = name
		m.pendingArgs = append([]string(nil), args...)
		m.confirmBuf = ""
		m.setOverlay(overlayConfirm)
		m.status = "type the full invocation to mutate"
		return m, nil
	}

	switch name {
	case "doctor":
		m.setOverlay(overlayDoctor)
		if m.host.Doctor != nil {
			m.doctor = m.host.Doctor()
		}
		return m, m.loadDoctor()
	case "setup":
		if title, rows, ok := pickerFor(name); ok && (len(args) == 0 || sameArgs(args, DefaultArgs(name))) {
			m.pickerTitle = title
			m.picker = rows
			m.cursor = 0
			m.setOverlay(overlaySetup)
			if m.host.SetupSnapshot != nil && !m.setupLoaded {
				m.setupRows = m.host.SetupSnapshot()
				m.setupLoaded = true
			}
			return m, m.loadSetup()
		}
	case "receipts":
		if title, rows, ok := pickerFor(name); ok && (len(args) == 0 || sameArgs(args, DefaultArgs(name))) {
			m.pickerTitle = title
			m.picker = rows
			m.cursor = 0
			m.setOverlay(overlayReceipts)
			if m.host.ReceiptsSnapshot != nil && !m.receiptsLoaded {
				m.receiptRows = m.host.ReceiptsSnapshot()
				m.receiptsLoaded = true
			}
			return m, m.loadReceipts()
		}
	case "watch":
		m.overlay = overlayNone
		m.screen = ScreenWatch
		m.cursor = 0
		m.ceremonyToken = ""
		return m, m.loadWatch()
	case "tui", "ui", "dashboard":
		m.setOverlay(overlayPalette)
		m.cursor = 0
		return m, nil
	}

	if title, rows, ok := pickerFor(name); ok && (len(args) == 0 || sameArgs(args, DefaultArgs(name))) {
		// mcp scan is inspect: palette default runs it. Empty `mcp` still
		// opens the picker. Listener-refuse does not apply to scan.
		if name == "mcp" && sameArgs(args, DefaultArgs("mcp")) {
			return m.startRun(name, args)
		}
		m.pickerTitle = title
		m.picker = rows
		m.cursor = 0
		if name == "setup" {
			m.setOverlay(overlaySetup)
		} else if name == "receipts" {
			m.setOverlay(overlayReceipts)
		} else {
			m.setOverlay(overlayPicker)
		}
		return m, nil
	}

	return m.startRun(name, args)
}

func (m model) executeComposer() (tea.Model, tea.Cmd) {
	name, args := ParseArgv(m.composer)
	if name == "" {
		return m, nil
	}
	if len(args) == 0 {
		args = DefaultArgs(name)
	}
	return m.activateCommand(name, args)
}

func (m model) activateAction(rows []actionRow) (tea.Model, tea.Cmd) {
	if m.cursor < 0 || m.cursor >= len(rows) {
		return m, nil
	}
	row := rows[m.cursor]
	return m.activateCommand(row.name, row.args)
}

func (m model) startRun(name string, args []string) (tea.Model, tea.Cmd) {
	m.runSeq++
	seq := m.runSeq
	if m.runCancel != nil {
		m.runCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.runCancel = cancel
	m.running = true
	m.run = commandRun{Name: name, Args: append([]string(nil), args...)}
	m.setOverlay(overlayOutput)
	m.status = "running. Esc aborts this session result"
	host := m.host
	return m, func() tea.Msg {
		out, errOut, code := host.run(ctx, name, args)
		return runDoneMsg{seq: seq, run: commandRun{
			Name:   name,
			Args:   append([]string(nil), args...),
			Stdout: RedactSecrets(out),
			Stderr: RedactSecrets(errOut),
			Code:   code,
		}}
	}
}

func (h Host) run(ctx context.Context, name string, args []string) (string, string, int) {
	if h.RunCommandCtx != nil {
		return h.RunCommandCtx(ctx, name, args)
	}
	if h.RunCommand != nil {
		return h.RunCommand(name, args)
	}
	return "", "runner is not wired", 2
}

func (m model) abortRun() (tea.Model, tea.Cmd) {
	if m.runCancel != nil {
		m.runCancel()
		m.runCancel = nil
	}
	m.running = false
	m.runSeq++
	if m.run.Stderr != "" {
		m.run.Stderr += "\n"
	}
	m.run.Stderr += "cancelled. Result discarded; no background listener was started"
	m.run.Code = 2
	m.status = "run aborted"
	return m, nil
}

func (m model) applyRunDone(msg runDoneMsg) (tea.Model, tea.Cmd) {
	if msg.seq != m.runSeq {
		return m, nil
	}
	m.running = false
	m.runCancel = nil
	m.run = msg.run
	m.status = fmt.Sprintf("exit %d", msg.run.Code)
	return m, tea.Batch(m.loadDoctor(), m.loadWatch())
}

func (m model) submitDestructive() (tea.Model, tea.Cmd) {
	want := Invocation(m.pendingName, m.pendingArgs)
	got := strings.TrimSpace(m.confirmBuf)
	if got != want && got != strings.TrimPrefix(want, "helm-ai-kernel ") {
		m.status = "invocation did not match. No mutation"
		return m, nil
	}
	name, args := m.pendingName, m.pendingArgs
	m.pendingName = ""
	m.pendingArgs = nil
	m.confirmBuf = ""
	return m.startRun(name, args)
}

func (m model) pinnedCeremony() (Approval, bool) {
	if m.ceremonyID == "" {
		return Approval{}, false
	}
	for _, item := range m.approvals {
		if item.ID == m.ceremonyID {
			if m.ceremonyHash != "" && item.Hash != "" && item.Hash != m.ceremonyHash {
				return Approval{}, false
			}
			return item, true
		}
	}
	return Approval{}, false
}

func (m model) submitCeremony() (tea.Model, tea.Cmd) {
	if _, ok := MatchCeremonyToken(m.ceremonyToken); !ok {
		m.status = "ceremony requires APPROVE or DENY. No state change"
		m.ceremonyToken = ""
		return m, nil
	}
	item, ok := m.pinnedCeremony()
	if !ok {
		m.status = "ceremony changed. No state change"
		m.ceremonyToken = ""
		return m, nil
	}
	if m.host.Decide == nil {
		m.status = "Decide is not wired. Fail-closed"
		return m, nil
	}
	token := m.ceremonyToken
	m.ceremonyToken = ""
	m.setOverlay(overlayOutput)
	m.running = true
	m.runSeq++
	seq := m.runSeq
	return m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		out, errOut, code := m.host.Decide(ctx, item.ID, token)
		return runDoneMsg{seq: seq, run: commandRun{
			Name:   "watch",
			Args:   []string{"decide", item.ID},
			Stdout: RedactSecrets(out),
			Stderr: RedactSecrets(errOut),
			Code:   code,
		}}
	}
}

func (m model) openCeremony(idx int) (tea.Model, tea.Cmd) {
	if idx < 0 || idx >= len(m.approvals) {
		return m, nil
	}
	item := m.approvals[idx]
	m.ceremonyIdx = idx
	m.ceremonyID = item.ID
	m.ceremonyHash = item.Hash
	m.ceremonyToken = ""
	m.setOverlay(overlayCeremony)
	m.status = "type APPROVE or DENY. Click and Enter do not decide"
	return m, nil
}

func (m model) pickerRows() []actionRow {
	switch m.activeOverlay() {
	case overlaySetup:
		return setupActions()
	case overlayReceipts:
		return receiptActions()
	case overlayPicker:
		return m.picker
	default:
		return nil
	}
}

func (m model) viewOutputInner() string {
	s := m.styles
	inv := Invocation(m.run.Name, m.run.Args)
	var b strings.Builder
	if m.running {
		b.WriteString(s.mark("WAIT") + "  Running…  Esc / [x] abort\n")
	} else {
		st := "PASS"
		if m.run.Code != 0 {
			st = "FAIL"
		}
		b.WriteString(s.mark(st) + "  " + s.muted.Render(fmt.Sprintf("exit %d", m.run.Code)) + "\n")
	}
	b.WriteString(s.muted.Render(inv) + "\n\n")
	body := strings.TrimRight(m.run.Stdout, "\n")
	if strings.TrimSpace(m.run.Stderr) != "" {
		if body != "" {
			body += "\n\n"
		}
		body += strings.TrimRight(m.run.Stderr, "\n")
	}
	if body == "" && !m.running {
		body = "Kernel returned no stdout or stderr."
	}
	lines := strings.Split(body, "\n")
	start := m.runScroll
	if start < 0 {
		start = 0
	}
	if start >= len(lines) {
		start = max(len(lines)-1, 0)
	}
	limit := m.height - 16
	if limit < 6 {
		limit = 6
	}
	end := start + limit
	if end > len(lines) {
		end = len(lines)
	}
	for _, line := range lines[start:end] {
		b.WriteString(line + "\n")
	}
	if next := ProofNextActions(m.run.Stdout, m.run.Stderr); len(next) > 0 && !m.running {
		b.WriteString("\n" + s.accent.Render("Kernel evidence next") + "\n")
		for _, n := range next {
			b.WriteString("  " + n + "\n")
		}
	}
	return b.String()
}

func (m model) viewActionList(rows []actionRow, originY, originX int) string {
	s := m.styles
	var b strings.Builder
	localY := 0
	for i, row := range rows {
		line := padRight(row.label, 16) + "  " + row.detail
		if i == m.cursor {
			b.WriteString(s.cursor.Render("❯ "+line) + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
		m.addHit(hitAction, i, originX, originY+localY, 64, 1)
		localY++
	}
	return b.String()
}

func (m model) viewSnapshotRows(rows []SnapshotRow, loaded bool, loading, empty string) string {
	s := m.styles
	var b strings.Builder
	if !loaded {
		b.WriteString("  " + s.mark("WAIT") + "  " + loading + "\n")
		return b.String()
	}
	if len(rows) == 0 {
		b.WriteString("  " + s.mark("WAIT") + "  " + empty + "\n")
		return b.String()
	}
	for _, row := range rows {
		st := strings.ToUpper(strings.TrimSpace(row.Status))
		if st == "" {
			st = "WAIT"
		}
		line := row.Name
		if row.Message != "" {
			line += "  " + row.Message
		}
		b.WriteString("  " + s.mark(st) + "  " + line + "\n")
	}
	return b.String()
}

func (m model) viewSetupInner(originY, originX int) string {
	s := m.styles
	var b strings.Builder
	b.WriteString(s.muted.Render("Live clients. --yes is composer-confirmed, never a row default.") + "\n")
	b.WriteString(m.viewSnapshotRows(m.setupRows, m.setupLoaded, "loading client status", "No clients reported. Rows below stay --dry-run."))
	b.WriteString("\n")
	offset := 2 + 1
	if m.setupLoaded && len(m.setupRows) > 0 {
		offset += len(m.setupRows)
	} else {
		offset++
	}
	b.WriteString(m.viewActionList(setupActions(), originY+offset, originX))
	return b.String()
}

func (m model) viewReceiptsInner(originY, originX int) string {
	s := m.styles
	var b strings.Builder
	b.WriteString(s.muted.Render("Trust only Ed25519, SHA-256, and JCS. Never the TUI. No SSE preload.") + "\n")
	if m.receiptErr != "" {
		b.WriteString("  " + s.mark("FAIL") + "  " + RedactSecrets(m.receiptErr) + "\n")
	} else {
		b.WriteString(m.viewSnapshotRows(m.receiptRows, m.receiptsLoaded, "loading receipts edge", "No receipt edge yet. status is bounded HTTP, never SSE."))
	}
	b.WriteString("\n")
	offset := 3
	if m.receiptsLoaded && len(m.receiptRows) > 0 {
		offset += len(m.receiptRows)
	}
	b.WriteString(m.viewActionList(receiptActions(), originY+offset, originX))
	return b.String()
}

func (m model) viewPickerInner(originY, originX int) string {
	s := m.styles
	var b strings.Builder
	b.WriteString(s.muted.Render("Enter or click executes in-TUI. Composer keeps extra args.") + "\n\n")
	b.WriteString(m.viewActionList(m.picker, originY+2, originX))
	return b.String()
}

func (m model) viewConfirmInner() string {
	s := m.styles
	want := Invocation(m.pendingName, m.pendingArgs)
	return strings.Join([]string{
		s.mark("WAIT") + "  Destructive invocation",
		"",
		DestructivePrompt,
		"",
		s.muted.Render(want),
		"",
		"> " + m.confirmBuf + "▌",
	}, "\n")
}

func (m model) viewCeremonyInner() string {
	s := m.styles
	a, ok := m.pinnedCeremony()
	if !ok {
		if m.ceremonyIdx >= 0 && m.ceremonyIdx < len(m.approvals) && m.ceremonyID == "" {
			a = m.approvals[m.ceremonyIdx]
			ok = true
		}
	}
	if !ok {
		return s.muted.Render("Select a Watch row, then type APPROVE or DENY.")
	}
	return strings.Join([]string{
		s.mark("WAIT") + "  Review required",
		"",
		"Action       type APPROVE or DENY",
		"Subject      " + a.Subject,
		"Summary      " + a.Summary,
		"ID           " + a.ID,
		"",
		s.muted.Render("Click, 1-9, Enter-on-row, and Ctrl+O never change state."),
		"",
		"> " + m.ceremonyToken + "▌",
	}, "\n")
}
