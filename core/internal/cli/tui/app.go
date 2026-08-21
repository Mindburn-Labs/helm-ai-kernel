package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
)

// Screen is a first-class TUI surface. The palette can open any catalog
// command; these screens own the interactive journeys.
type Screen int

const (
	ScreenHome Screen = iota
	ScreenPalette
	ScreenDoctor
	ScreenDemo
	ScreenWatch
	ScreenSetup
	ScreenReceipts
	ScreenHelp
	ScreenShortcuts
	ScreenOutput
)

// Command is one catalog entry shown in the palette.
type Command struct {
	Name    string
	Usage   string
	Group   string
	Aliases []string
}

// Check is one doctor row.
type Check struct {
	Name       string
	Status     string
	Message    string
	Detail     string
	Suggestion string
}

// Approval is a pending ceremony for the watch screen.
type Approval struct {
	ID      string
	Subject string
	Summary string
	State   string
	Hash    string
}

// SnapshotRow is one live inspect row for setup clients or receipts.
type SnapshotRow struct {
	Name    string
	Status  string
	Message string
}

// Host is how the Kernel CLI feeds live data into the TUI without the TUI
// importing command internals.
type Host struct {
	Version          string
	Commit           string
	Commands         []Command
	Doctor           func() []Check
	Watch            func(ctx context.Context) ([]Approval, error)
	Decide           func(ctx context.Context, id, token string) (stdout, stderr string, code int)
	RunCommand       func(name string, args []string) (stdout, stderr string, code int)
	RunCommandCtx    func(ctx context.Context, name string, args []string) (stdout, stderr string, code int)
	SetupSnapshot    func() []SnapshotRow
	ReceiptsSnapshot func() []SnapshotRow
	Stdin            io.Reader
	Stdout           io.Writer
}

type menuItem struct {
	key     string
	title   string
	detail  string
	screen  Screen
	command string
}

type demoBeat struct {
	kind    string
	status  string
	actor   string
	action  string
	detail  string
	section string
}

type model struct {
	host           Host
	styles         styles
	width          int
	height         int
	screen         Screen
	prev           Screen
	cursor         int
	filter         string
	filtering      bool
	doctor         []Check
	demoAt         int
	playing        bool
	approvals      []Approval
	watchErr       string
	quitting       bool
	status         string
	overlay        overlayKind
	layout         *chromeLayout
	watchLoaded    bool
	composer       string
	composing      bool
	run            commandRun
	runScroll      int
	running        bool
	runCancel      context.CancelFunc
	runSeq         int
	picker         []actionRow
	pickerTitle    string
	pendingName    string
	pendingArgs    []string
	confirmBuf     string
	ceremonyIdx    int
	ceremonyID     string
	ceremonyHash   string
	ceremonyToken  string
	setupRows      []SnapshotRow
	setupLoaded    bool
	receiptRows    []SnapshotRow
	receiptErr     string
	receiptsLoaded bool
}

type doctorMsg []Check
type watchMsg struct {
	items []Approval
	err   error
}
type setupMsg struct {
	rows []SnapshotRow
}
type receiptsMsg struct {
	rows []SnapshotRow
	err  error
}
type demoTickMsg time.Time

func menu() []menuItem {
	return []menuItem{
		{key: "1", title: "Doctor", detail: "Keys, policy, store. FAIL ranks the queue", screen: ScreenDoctor, command: "doctor"},
		{key: "2", title: "Watch queue", detail: "Pending ceremonies. Typed APPROVE/DENY only", screen: ScreenWatch, command: "watch"},
		{key: "3", title: "Policy", detail: "Compile and test the boundary", command: "policy"},
		{key: "4", title: "Freeze", detail: "Inspect freeze status (mutate needs full argv)", command: "freeze"},
		{key: "5", title: "Threat", detail: "Scan or test the threat surface", command: "threat"},
		{key: "6", title: "All commands", detail: "Every Kernel verb. Runner, not a cheat sheet", screen: ScreenPalette, command: "help"},
	}
}

func demoBeats() []demoBeat {
	return []demoBeat{
		{kind: "section", section: "Deploy v2.4 API to Production"},
		{kind: "event", status: "ALLOW", actor: "Product Manager", action: "DEFINE_REQUIREMENTS", detail: "PRD: v2.4 rate limiting + embeddings endpoint"},
		{kind: "event", status: "ALLOW", actor: "CTO", action: "PLAN_INITIATIVE", detail: "Created INIT-2847"},
		{kind: "event", status: "ALLOW", actor: "Security Engineer", action: "AUDIT_REVIEW", detail: "0 critical, 0 high, 2 low (accepted)"},
		{kind: "event", status: "WAIT", actor: "Backend Engineer", action: "REQUEST_APPROVAL", detail: "PR #1482 merged, requesting prod deploy"},
		{kind: "event", status: "ALLOW", actor: "CTO", action: "APPROVE_EXECUTION", detail: "LGTM, staging verified, deploy to prod"},
		{kind: "event", status: "ALLOW", actor: "Backend Engineer", action: "SANDBOX_EXEC", detail: "247 checks passed, 0 failed"},
		{kind: "event", status: "DENY", actor: "Backend Engineer", action: "EXECUTE_TOOL", detail: "DROP TABLE users - not in allowlist"},
		{kind: "deny", status: "DENY", action: "ERR_TOOL_NOT_ALLOWED", detail: "Add psql_drop_table only if the authority scope permits it"},
		{kind: "event", status: "ALLOW", actor: "System", action: "MAINTENANCE_RUN", detail: "GC tuning patch, memory stable at 380Mi"},
		{kind: "complete"},
	}
}

// New constructs the root TUI model.
func New(host Host) model {
	if host.Version == "" {
		host.Version = "v0.0.0-dev"
	}
	return model{
		host:   host,
		styles: newStyles(),
		width:  80,
		height: 24,
		screen: ScreenHome,
		status: "fail-closed   j/k   /   ?   q",
		layout: &chromeLayout{},
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.loadDoctor(), m.loadWatch(), m.loadSetup(), m.loadReceipts(), m.refreshTick())
}

func (m model) refreshTick() tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg { return refreshTickMsg(t) })
}

func (m model) loadDoctor() tea.Cmd {
	if m.host.Doctor == nil {
		return nil
	}
	return func() tea.Msg { return doctorMsg(m.host.Doctor()) }
}

func (m model) loadWatch() tea.Cmd {
	if m.host.Watch == nil {
		return nil
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		items, err := m.host.Watch(ctx)
		return watchMsg{items: items, err: err}
	}
}

func (m model) loadSetup() tea.Cmd {
	if m.host.SetupSnapshot == nil {
		return nil
	}
	return func() tea.Msg { return setupMsg{rows: m.host.SetupSnapshot()} }
}

func (m model) loadReceipts() tea.Cmd {
	if m.host.ReceiptsSnapshot == nil {
		return nil
	}
	return func() tea.Msg { return receiptsMsg{rows: m.host.ReceiptsSnapshot()} }
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case doctorMsg:
		m.doctor = []Check(msg)
		return m, nil
	case watchMsg:
		m.watchLoaded = true
		m.approvals = msg.items
		if msg.err != nil {
			m.watchErr = msg.err.Error()
		} else {
			m.watchErr = ""
		}
		return m, nil
	case setupMsg:
		m.setupLoaded = true
		m.setupRows = msg.rows
		return m, nil
	case receiptsMsg:
		m.receiptsLoaded = true
		m.receiptRows = msg.rows
		if msg.err != nil {
			m.receiptErr = msg.err.Error()
		} else {
			m.receiptErr = ""
		}
		return m, nil
	case demoTickMsg:
		if m.playing && m.demoAt < len(demoBeats())-1 {
			m.demoAt++
			return m, tea.Tick(110*time.Millisecond, func(t time.Time) tea.Msg { return demoTickMsg(t) })
		}
		m.playing = false
		return m, nil
	case runDoneMsg:
		return m.applyRunDone(msg)
	case refreshTickMsg:
		cmds := []tea.Cmd{m.loadDoctor(), m.loadWatch(), m.refreshTick()}
		if m.activeOverlay() == overlaySetup {
			cmds = append(cmds, m.loadSetup())
		}
		if m.activeOverlay() == overlayReceipts {
			cmds = append(cmds, m.loadReceipts())
		}
		return m, tea.Batch(cmds...)
	case tea.MouseMsg:
		return m.handleMouse(msg)
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.activeOverlay() == overlayShortcuts && msg.String() != "ctrl+c" && msg.String() != "ctrl+d" && msg.String() != "q" {
		m.setOverlay(overlayNone)
		return m, nil
	}
	if m.running && (msg.String() == "esc" || msg.Type == tea.KeyEsc) {
		return m.abortRun()
	}
	if m.activeOverlay() == overlayConfirm {
		switch msg.Type {
		case tea.KeyEsc:
			m.setOverlay(overlayNone)
			m.confirmBuf = ""
			return m, nil
		case tea.KeyBackspace:
			rs := []rune(m.confirmBuf)
			if len(rs) > 0 {
				m.confirmBuf = string(rs[:len(rs)-1])
			}
			return m, nil
		case tea.KeyEnter:
			return m.submitDestructive()
		}
		if msg.Type == tea.KeyRunes {
			m.confirmBuf += string(msg.Runes)
		}
		return m, nil
	}
	if m.activeOverlay() == overlayCeremony {
		switch msg.String() {
		case "ctrl+c", "ctrl+d":
			m.quitting = true
			return m, tea.Quit
		case "ctrl+o", "1", "2", "3", "4", "5", "6", "7", "8", "9":
			m.status = "ceremony ignores hotkeys. Type APPROVE or DENY"
			return m, nil
		}
		switch msg.Type {
		case tea.KeyEsc:
			m.setOverlay(overlayNone)
			m.screen = ScreenWatch
			m.ceremonyToken = ""
			return m, nil
		case tea.KeyBackspace:
			rs := []rune(m.ceremonyToken)
			if len(rs) > 0 {
				m.ceremonyToken = string(rs[:len(rs)-1])
			}
			return m, nil
		case tea.KeyEnter:
			return m.submitCeremony()
		}
		if msg.Type == tea.KeyRunes {
			m.ceremonyToken += string(msg.Runes)
		}
		return m, nil
	}
	if m.filtering {
		switch msg.Type {
		case tea.KeyEsc:
			m.filtering = false
			m.filter = ""
			return m, nil
		case tea.KeyBackspace:
			rs := []rune(m.filter)
			if len(rs) > 0 {
				m.filter = string(rs[:len(rs)-1])
			}
			return m, nil
		case tea.KeyEnter:
			m.filtering = false
			return m.openPaletteSelection()
		}
		if msg.Type == tea.KeyRunes {
			m.filter += string(msg.Runes)
			m.cursor = 0
		}
		return m, nil
	}

	switch msg.String() {
	case "ctrl+c", "ctrl+d":
		m.quitting = true
		return m, tea.Quit
	case "q":
		if m.composing {
			m.composer += "q"
			return m, nil
		}
		m.quitting = true
		return m, tea.Quit
	case "?":
		m.prev = m.screen
		m.setOverlay(overlayShortcuts)
		return m, nil
	case "/":
		m.setOverlay(overlayPalette)
		m.filtering = true
		m.filter = ""
		m.cursor = 0
		m.composing = false
		return m, nil
	case "esc":
		if m.running {
			return m.abortRun()
		}
		if m.activeOverlay() != overlayNone {
			m.setOverlay(overlayNone)
			return m, nil
		}
		if m.screen != ScreenHome {
			m.screen = ScreenHome
			m.cursor = 0
			m.playing = false
		}
		return m, nil
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		if m.screen == ScreenWatch && m.activeOverlay() == overlayNone {
			m.status = "digits do not approve. Select a row, then type APPROVE or DENY"
			return m, nil
		}
		if m.screen == ScreenHome && m.activeOverlay() == overlayNone {
			idx := int(msg.String()[0] - '1')
			return m.openMenu(idx)
		}
		if m.composing {
			m.composer += msg.String()
			return m, nil
		}
	case "j", "down":
		if m.activeOverlay() == overlayOutput {
			m.runScroll++
			return m, nil
		}
		m.cursor++
		m.clampCursor()
		return m, nil
	case "k", "up":
		if m.activeOverlay() == overlayOutput {
			if m.runScroll > 0 {
				m.runScroll--
			}
			return m, nil
		}
		m.cursor--
		m.clampCursor()
		return m, nil
	case "enter":
		if rows := m.pickerRows(); len(rows) > 0 {
			return m.activateAction(rows)
		}
		if m.composing && strings.TrimSpace(m.composer) != "" && m.activeOverlay() != overlayPalette &&
			m.activeOverlay() != overlaySetup && m.activeOverlay() != overlayReceipts &&
			m.activeOverlay() != overlayPicker {
			return m.executeComposer()
		}
		if m.screen == ScreenHome && m.activeOverlay() == overlayNone {
			return m.openMenu(m.cursor)
		}
		if m.activeOverlay() == overlayPalette {
			return m.openPaletteSelection()
		}
		if m.composing && strings.TrimSpace(m.composer) != "" {
			return m.executeComposer()
		}
		if m.screen == ScreenDemo && !m.playing {
			m.demoAt = 0
			m.playing = true
			return m, tea.Tick(80*time.Millisecond, func(t time.Time) tea.Msg { return demoTickMsg(t) })
		}
		if m.activeOverlay() == overlayDoctor {
			return m, m.loadDoctor()
		}
		if m.screen == ScreenWatch {
			return m.openCeremony(m.cursor)
		}
	case "l":
		if m.composing {
			m.composer += "l"
			return m, nil
		}
		if m.screen == ScreenHome && m.activeOverlay() == overlayNone {
			return m.openMenu(m.cursor)
		}
		if m.activeOverlay() == overlayPalette {
			return m.openPaletteSelection()
		}
	case "r":
		if m.activeOverlay() == overlayDoctor {
			return m, m.loadDoctor()
		}
		if m.screen == ScreenWatch {
			return m, m.loadWatch()
		}
		if m.composing {
			m.composer += "r"
			return m, nil
		}
	case " ":
		if m.screen == ScreenDemo && m.activeOverlay() == overlayNone {
			m.playing = !m.playing
			if m.playing {
				return m, tea.Tick(80*time.Millisecond, func(t time.Time) tea.Msg { return demoTickMsg(t) })
			}
			return m, nil
		}
		if m.composing {
			m.composer += " "
			return m, nil
		}
	case "backspace":
		if m.composing {
			rs := []rune(m.composer)
			if len(rs) > 0 {
				m.composer = string(rs[:len(rs)-1])
			}
			return m, nil
		}
	}
	if msg.Type == tea.KeyRunes {
		if m.activeOverlay() == overlayPalette {
			m.filtering = true
			m.filter += string(msg.Runes)
			m.cursor = 0
			return m, nil
		}
		m.composing = true
		m.composer += string(msg.Runes)
	}
	return m, nil
}

func (m model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if tea.MouseEvent(msg).IsWheel() {
		if m.activeOverlay() == overlayOutput {
			if msg.Button == tea.MouseButtonWheelDown {
				m.runScroll++
			} else if msg.Button == tea.MouseButtonWheelUp && m.runScroll > 0 {
				m.runScroll--
			}
			return m, nil
		}
		if m.activeOverlay() == overlayPalette || m.activeOverlay() == overlaySetup || m.activeOverlay() == overlayReceipts || (m.screen == ScreenHome && m.activeOverlay() == overlayNone) {
			if msg.Button == tea.MouseButtonWheelDown {
				m.cursor++
			} else if msg.Button == tea.MouseButtonWheelUp {
				m.cursor--
			}
			m.clampCursor()
		}
		return m, nil
	}
	if msg.Action != tea.MouseActionPress || msg.Button != tea.MouseButtonLeft {
		return m, nil
	}
	if ov := m.activeOverlay(); ov == overlayCeremony || ov == overlayConfirm {
		h, ok := m.hitAt(msg.X, msg.Y)
		if ok && h.kind == hitClose {
			m.setOverlay(overlayNone)
			m.confirmBuf = ""
			m.ceremonyToken = ""
			return m, nil
		}
		m.status = "click does not decide. Type the required word"
		return m, nil
	}
	h, ok := m.hitAt(msg.X, msg.Y)
	if !ok {
		return m, nil
	}
	switch h.kind {
	case hitClose:
		m.setOverlay(overlayNone)
		return m, nil
	case hitMenu:
		return m.openMenu(h.index)
	case hitPalette:
		m.cursor = h.index
		return m.openPaletteSelection()
	case hitAction:
		m.cursor = h.index
		if rows := m.pickerRows(); len(rows) > 0 {
			return m.activateAction(rows)
		}
		if m.screen == ScreenWatch {
			return m.openCeremony(h.index)
		}
	case hitPending:
		m.overlay = overlayNone
		m.filtering = false
		m.filter = ""
		m.screen = ScreenWatch
		m.cursor = 0
		m.status = "pending opened. Typing APPROVE/DENY is still required"
		return m, m.loadWatch()
	case hitComposer:
		m.setOverlay(overlayPalette)
		m.filtering = true
		m.filter = ""
		return m, nil
	}
	return m, nil
}

func (m model) openMenu(idx int) (tea.Model, tea.Cmd) {
	items := menu()
	if idx < 0 || idx >= len(items) {
		return m, nil
	}
	m.cursor = 0
	if items[idx].screen == ScreenPalette {
		m.setOverlay(overlayPalette)
		return m, nil
	}
	return m.activateCommand(items[idx].command, DefaultArgs(items[idx].command))
}

func (m *model) clampCursor() {
	max := 0
	switch m.activeOverlay() {
	case overlayPalette:
		max = len(m.filteredCommands()) - 1
	case overlaySetup:
		max = len(setupActions()) - 1
	case overlayReceipts:
		max = len(receiptActions()) - 1
	case overlayPicker:
		max = len(m.picker) - 1
	default:
		if m.screen == ScreenHome {
			max = len(menu()) - 1
		} else if m.screen == ScreenWatch {
			max = len(m.approvals) - 1
		}
	}
	if max < 0 {
		max = 0
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor > max {
		m.cursor = max
	}
}

func (m model) filteredCommands() []Command {
	q := strings.ToLower(strings.TrimSpace(m.filter))
	var src []Command
	if q == "" {
		src = m.host.Commands
	} else {
		for _, c := range m.host.Commands {
			blob := strings.ToLower(c.Name + " " + c.Usage + " " + c.Group + " " + strings.Join(c.Aliases, " "))
			if strings.Contains(blob, q) {
				src = append(src, c)
			}
		}
	}
	return sortCommands(src)
}

func (m model) View() string {
	if m.quitting {
		return ""
	}
	if m.layout == nil {
		m.layout = &chromeLayout{}
	}
	m.layout.hits = m.layout.hits[:0]

	header := m.viewHeader()
	m.registerHeaderHits(header)

	originY := lipgloss.Height(header) + 1
	var workspace string
	if ov := m.activeOverlay(); ov != overlayNone {
		workspace = m.viewOverlay(ov, originY)
	} else {
		switch m.screen {
		case ScreenDemo:
			workspace = m.viewDemo()
		case ScreenWatch:
			workspace = m.viewWatch()
		default:
			workspace = m.viewHome(originY)
		}
	}

	composer := m.viewComposer()
	footer := m.styles.footer.Render(m.status)
	top := lipgloss.JoinVertical(lipgloss.Left, header, "", workspace)
	bottom := lipgloss.JoinVertical(lipgloss.Left, composer, footer)
	gap := m.height - lipgloss.Height(top) - lipgloss.Height(bottom)
	if gap < 1 {
		gap = 1
	}
	out := lipgloss.JoinVertical(lipgloss.Left, top, strings.Repeat("\n", gap-1), bottom)
	composerY := lipgloss.Height(top) + gap
	m.addHit(hitComposer, 0, 0, composerY, max(m.width, 1), lipgloss.Height(composer))
	if m.width > 0 {
		return m.styles.app.Width(m.width).MaxHeight(max(m.height, 1)).Render(out)
	}
	return out
}

func (m model) registerHeaderHits(header string) {
	pending := pendingQueueLabel(len(m.approvals))
	first := strings.Split(header, "\n")[0]
	idx := strings.LastIndex(first, pending)
	if idx < 0 {
		idx = strings.LastIndex(stripAnsi(first), pending)
	}
	plain := stripAnsi(first)
	at := strings.LastIndex(plain, pending)
	if at >= 0 {
		m.addHit(hitPending, 0, at, 0, len(pending), 1)
	}
}

func stripAnsi(s string) string {
	var b strings.Builder
	esc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x1b {
			esc = true
			continue
		}
		if esc {
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				esc = false
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func (m model) viewHome(originY int) string {
	s := m.styles
	var rows []string
	cardW := m.width - 2
	if cardW > 88 {
		cardW = 88
	}
	if cardW < 48 {
		cardW = 48
	}
	pass, warn, fail := m.doctorCounts()
	next := "doctor"
	if fail > 0 {
		next = "doctor   FAIL findings first"
	} else if len(m.approvals) > 0 {
		next = "watch   pending ceremony queue"
	} else if !m.watchLoaded {
		next = "wait   Kernel reachability still loading"
	}
	preamble := []string{
		s.accent.Render("Constitution → Boundary → Permit → Receipt → Proof"),
		s.muted.Render(fmt.Sprintf("Doctor  PASS %d  WARN %d  FAIL %d", pass, warn, fail)),
		s.muted.Render("Queue   " + pendingQueueLabel(len(m.approvals))),
		s.muted.Render("Next    " + next),
		"",
	}
	contentX := 3
	contentY := originY + 2 + len(preamble)
	contentW := cardW - 6
	for i, item := range menu() {
		label := fmt.Sprintf("%s  %s", item.key, item.title)
		line := padRight(label, 22) + "  " + item.detail
		if i == m.cursor {
			rows = append(rows, s.cursor.Render("❯ "+line))
		} else {
			rows = append(rows, "  "+s.muted.Render(line))
		}
		m.addHit(hitMenu, i, contentX, contentY+i, contentW, 1)
	}
	body := append(preamble, rows...)
	body = append(body, "", s.muted.Render("Not the boundary. The proof that the boundary is on."))
	inner := lipgloss.JoinVertical(lipgloss.Left, body...)
	return s.card.Width(cardW).Render(inner)
}

func (m model) viewPalette(originY, originX int) string {
	s := m.styles
	cmds := m.filteredCommands()
	var b strings.Builder
	b.WriteString(s.muted.Render(fmt.Sprintf("%d", len(cmds))) + "\n")
	localY := 1
	start := 0
	limit := m.height - 14
	if limit < 8 {
		limit = 8
	}
	if m.cursor >= limit {
		start = m.cursor - limit + 1
	}
	end := start + limit
	if end > len(cmds) {
		end = len(cmds)
	}
	group := ""
	for i := start; i < end; i++ {
		c := cmds[i]
		if displayGroup(c) != group {
			group = displayGroup(c)
			b.WriteString("\n" + s.accent.Render(group) + "\n")
			localY += 2
		}
		line := padRight(c.Name, 18) + "  " + c.Usage
		if i == m.cursor {
			b.WriteString(s.cursor.Render("❯ "+line) + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
		m.addHit(hitPalette, i, originX, originY+localY, 60, 1)
		localY++
	}
	if len(cmds) == 0 {
		b.WriteString(s.muted.Render("No match. Clear the filter or type a catalog verb.") + "\n")
	}
	return b.String()
}

func (m model) viewDoctor() string {
	s := m.styles
	var b strings.Builder
	if len(m.doctor) == 0 {
		b.WriteString(s.muted.Render("Running checks…") + "\n")
		return b.String()
	}
	order := []string{"Environment", "Store", "Policy", "Findings"}
	grouped := map[string][]Check{}
	for _, c := range m.doctor {
		grouped[doctorSection(c.Name)] = append(grouped[doctorSection(c.Name)], c)
	}
	pass, warn, fail := m.doctorCounts()
	for _, sec := range order {
		checks := grouped[sec]
		if len(checks) == 0 {
			continue
		}
		b.WriteString(s.accent.Render(sec) + "\n")
		for _, c := range checks {
			st := strings.ToUpper(c.Status)
			switch st {
			case "PASS", "INFO", "OK":
				st = "PASS"
			case "WARN":
			default:
				st = "FAIL"
			}
			b.WriteString("  " + s.mark(st) + "  " + c.Name + "\n")
			b.WriteString("         " + s.muted.Render(c.Message) + "\n")
			if c.Suggestion != "" && (st == "FAIL" || st == "WARN") {
				b.WriteString("         " + s.muted.Render("Next  "+c.Suggestion) + "\n")
			}
		}
		b.WriteString("\n")
	}
	b.WriteString(s.muted.Render(fmt.Sprintf("Summary  PASS %d   WARN %d   FAIL %d", pass, warn, fail)) + "\n")
	return b.String()
}

func (m model) viewDemo() string {
	s := m.styles
	beats := demoBeats()
	at := m.demoAt
	if at >= len(beats) {
		at = len(beats) - 1
	}
	var b strings.Builder
	b.WriteString(s.accent.Render("HELM Demo  mock organization") + "  " + s.muted.Render("space pauses") + "\n\n")
	for i, beat := range beats {
		if i > at {
			break
		}
		switch beat.kind {
		case "section":
			b.WriteString(s.title.Render(beat.section) + "\n")
		case "event":
			b.WriteString("  " + s.mark(beat.status) + "  " + beat.actor + "  " + s.title.Render(beat.action) + "\n")
			if beat.detail != "" {
				b.WriteString("         " + s.muted.Render(beat.detail) + "\n")
			}
		case "deny":
			b.WriteString("\n" + s.card.BorderForeground(s.p.deny).Render(
				s.statusDeny.Render("[DENY]")+"  Deny Details\n"+
					"Reason       "+beat.action+"\n"+
					"Fix          "+beat.detail,
			) + "\n")
		case "complete":
			b.WriteString("\n" + s.muted.Render("EvidencePack sealed. Verify from Receipts or the composer.") + "\n")
		}
	}
	width := m.width - 6
	if width > 100 {
		width = 100
	}
	return s.card.Width(width).Render(b.String())
}

func (m model) viewWatch() string {
	s := m.styles
	var b strings.Builder
	b.WriteString(s.accent.Render("Watch") + "  " + s.muted.Render("security queue   r refreshes") + "\n\n")
	if m.watchErr != "" {
		b.WriteString("  " + s.mark("FAIL") + "  Kernel not reachable\n")
		b.WriteString("         " + s.muted.Render(RedactSecrets(m.watchErr)) + "\n")
		b.WriteString("         " + s.muted.Render("Open Doctor. The queue is unavailable until the Kernel answers.") + "\n")
	} else if len(m.approvals) == 0 {
		b.WriteString("  " + s.mark("PASS") + "  No pending ceremonies\n")
		b.WriteString("         " + s.muted.Render("Empty queue. A click or digit still cannot invent an approval.") + "\n")
	} else {
		for i, a := range m.approvals {
			line := a.ID + "  " + a.Subject
			if i == m.cursor {
				b.WriteString(s.cursor.Render("❯ "+s.mark("WAIT")+"  "+line) + "\n")
			} else {
				b.WriteString("  " + s.mark("WAIT") + "  " + line + "\n")
			}
			if a.Summary != "" {
				b.WriteString("         " + s.muted.Render(a.Summary) + "\n")
			}
			m.addHit(hitAction, i, 3, 6+i*2, 64, 1)
		}
		b.WriteString("\n" + s.muted.Render("Select a row, then type APPROVE or DENY. Click never decides.") + "\n")
	}
	width := m.width - 6
	if width > 100 {
		width = 100
	}
	return s.card.Width(width).Render(b.String())
}

func (m model) viewShortcutsInner() string {
	s := m.styles
	return lipgloss.JoinVertical(lipgloss.Left,
		"  j / k     Move",
		"  1-6       Doctor / Watch / Policy / Freeze / Threat / Catalog",
		"  enter     Open, run, or open ceremony (does not APPROVE)",
		"  /         Command catalog",
		"  r         Refresh doctor or watch",
		"  esc       Close overlay or abort a run",
		"  click     Select row or [x] - never APPROVE",
		"  q         Quit",
		"",
		s.muted.Render("Ceremony: type APPROVE or DENY. Click, 1-9, and Ctrl+O do not decide."),
	)
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// Preview renders a TUI screen without entering the alt-screen. Used for
// local screenshots and View() tests that need a populated doctor/demo pane.
func Preview(host Host, screen Screen, width, height int) string {
	m := New(host)
	if width > 0 {
		m.width = width
	}
	if height > 0 {
		m.height = height
	}
	m.screen = screen
	if host.Doctor != nil {
		m.doctor = host.Doctor()
	}
	if host.Watch != nil && screen == ScreenWatch {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		items, err := host.Watch(ctx)
		m.approvals = items
		if err != nil {
			m.watchErr = err.Error()
		}
	}
	if screen == ScreenDemo {
		m.demoAt = len(demoBeats()) - 1
	}
	if screen == ScreenShortcuts {
		m.prev = ScreenHome
	}
	return m.View()
}

// Interactive reports whether stdin and stdout can host a full-screen TUI.
func Interactive(stdin, stdout *os.File) bool {
	if os.Getenv("HELM_NO_TUI") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	if stdin == nil || stdout == nil {
		return false
	}
	return (isatty.IsTerminal(stdin.Fd()) || isatty.IsCygwinTerminal(stdin.Fd())) &&
		(isatty.IsTerminal(stdout.Fd()) || isatty.IsCygwinTerminal(stdout.Fd()))
}

// Run launches the full-screen Kernel TUI.
func Run(host Host) error {
	opts := []tea.ProgramOption{tea.WithAltScreen(), tea.WithMouseCellMotion()}
	if host.Stdin != nil {
		opts = append(opts, tea.WithInput(host.Stdin))
	}
	if host.Stdout != nil {
		opts = append(opts, tea.WithOutput(host.Stdout))
	}
	_, err := tea.NewProgram(New(host), opts...).Run()
	return err
}
