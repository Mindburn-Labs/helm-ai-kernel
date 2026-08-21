package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type overlayKind int

const (
	overlayNone overlayKind = iota
	overlayPalette
	overlayShortcuts
	overlayDoctor
	overlaySetup
	overlayReceipts
	overlayOutput
	overlayPicker
	overlayConfirm
	overlayCeremony
)

type hitKind string

const (
	hitClose    hitKind = "close"
	hitMenu     hitKind = "menu"
	hitPalette  hitKind = "palette"
	hitPending  hitKind = "pending"
	hitComposer hitKind = "composer"
	hitAction   hitKind = "action"
)

type hitRect struct {
	kind       hitKind
	index      int
	x, y, w, h int
}

type chromeLayout struct {
	hits []hitRect
}

var catalogGroupOrder = []string{"Operate", "Evidence", "Use HELM", "Get started"}

func displayGroup(c Command) string {
	switch c.Name {
	case "doctor", "watch", "threat":
		return "Operate"
	default:
		if c.Group == "" {
			return "Operate"
		}
		return c.Group
	}
}

func verbRank(name string) int {
	switch name {
	case "doctor":
		return 0
	case "watch":
		return 1
	case "policy":
		return 2
	case "freeze":
		return 3
	case "threat":
		return 4
	case "incident":
		return 5
	default:
		return 10
	}
}

func pendingQueueLabel(n int) string {
	if n == 1 {
		return "1 pending ceremony"
	}
	return fmt.Sprintf("%d pending ceremonies", n)
}

func (m *model) addHit(kind hitKind, index, x, y, w, h int) {
	if m.layout == nil || w <= 0 || h <= 0 {
		return
	}
	m.layout.hits = append(m.layout.hits, hitRect{kind: kind, index: index, x: x, y: y, w: w, h: h})
}

func (m model) hit(kind hitKind, index int) (hitRect, bool) {
	if m.layout == nil {
		return hitRect{}, false
	}
	for _, h := range m.layout.hits {
		if h.kind == kind && h.index == index {
			return h, true
		}
	}
	return hitRect{}, false
}

func (m model) hitAt(x, y int) (hitRect, bool) {
	if m.layout == nil {
		return hitRect{}, false
	}
	for i := len(m.layout.hits) - 1; i >= 0; i-- {
		h := m.layout.hits[i]
		if x >= h.x && x < h.x+h.w && y >= h.y && y < h.y+h.h {
			return h, true
		}
	}
	return hitRect{}, false
}

func (m model) activeOverlay() overlayKind {
	if m.overlay != overlayNone {
		return m.overlay
	}
	switch m.screen {
	case ScreenPalette, ScreenHelp:
		return overlayPalette
	case ScreenShortcuts:
		return overlayShortcuts
	case ScreenDoctor:
		return overlayDoctor
	case ScreenSetup:
		return overlaySetup
	case ScreenReceipts:
		return overlayReceipts
	case ScreenOutput:
		return overlayOutput
	default:
		return overlayNone
	}
}

func (m *model) setOverlay(kind overlayKind) {
	m.overlay = kind
	switch kind {
	case overlayNone:
		m.screen = ScreenHome
		m.filtering = false
		m.filter = ""
	case overlayPalette:
		m.screen = ScreenPalette
	case overlayShortcuts:
		m.screen = ScreenShortcuts
	case overlayDoctor:
		m.screen = ScreenDoctor
	case overlaySetup:
		m.screen = ScreenSetup
	case overlayReceipts:
		m.screen = ScreenReceipts
	case overlayOutput:
		m.screen = ScreenOutput
	case overlayPicker:
		m.screen = ScreenHome
	case overlayConfirm, overlayCeremony:
		// stay on current workspace
	}
}

func groupRank(group string) int {
	for i, name := range catalogGroupOrder {
		if group == name {
			return i
		}
	}
	return len(catalogGroupOrder)
}

func doctorSection(name string) string {
	switch name {
	case "go_version", "helm_version", "disk_space", "port_8080", "port_availability":
		return "Environment"
	case "crypto_keys", "data_directory", "database", "evidence_store":
		return "Store"
	case "config", "configuration", "policy_bundles":
		return "Policy"
	default:
		return "Findings"
	}
}

func (m model) kernelMark() string {
	if m.host.Watch == nil {
		return "WAIT"
	}
	if !m.watchLoaded {
		return "WAIT"
	}
	if m.watchErr != "" {
		return "FAIL"
	}
	return "PASS"
}

func (m model) doctorCounts() (pass, warn, fail int) {
	for _, c := range m.doctor {
		switch strings.ToUpper(c.Status) {
		case "PASS", "INFO", "OK":
			pass++
		case "WARN":
			warn++
		default:
			fail++
		}
	}
	return pass, warn, fail
}

func (m model) viewHeader() string {
	s := m.styles
	pending := len(m.approvals)
	meta := strings.TrimSpace(m.host.Version)
	if m.host.Commit != "" && m.host.Commit != "unknown" {
		if meta != "" {
			meta += "  "
		}
		meta += m.host.Commit
	}
	left := s.title.Render("HELM")
	if meta != "" {
		left += "  " + s.muted.Render(meta)
	}
	right := s.mark(m.kernelMark()) + "  Kernel   " + pendingQueueLabel(pending)
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 2 {
		gap = 2
	}
	line := left + strings.Repeat(" ", gap) + right
	return line + "\n" + s.muted.Render(wedge)
}

func (m model) viewComposer() string {
	s := m.styles
	prompt := "> "
	if m.filtering {
		prompt = "> /" + m.filter + "▌"
	} else if m.composing || strings.TrimSpace(m.composer) != "" {
		prompt = "> " + m.composer + "▌"
	} else {
		prompt = "> " + s.muted.Render("type a Kernel verb")
	}
	pass, warn, fail := m.doctorCounts()
	rail := ""
	if pass+warn+fail > 0 {
		rail = fmt.Sprintf("%s %d   %s %d   %s %d",
			s.mark("PASS"), pass, s.mark("WARN"), warn, s.mark("FAIL"), fail)
	}
	inner := prompt
	if rail != "" {
		pad := m.width - 6 - lipgloss.Width(prompt) - lipgloss.Width(rail)
		if pad < 1 {
			pad = 1
		}
		inner = prompt + strings.Repeat(" ", pad) + rail
	}
	box := s.composer.Width(m.width - 2).Render(inner)
	return box
}

func (m model) overlayHeading(kind overlayKind) string {
	switch kind {
	case overlayPalette:
		return "Commands"
	case overlayShortcuts:
		return "Shortcuts"
	case overlayDoctor:
		return "Doctor"
	case overlaySetup:
		return "Setup"
	case overlayReceipts:
		return "Receipts"
	case overlayOutput:
		if m.run.Name != "" {
			return m.run.Name
		}
		return "Output"
	case overlayPicker:
		if m.pickerTitle != "" {
			return m.pickerTitle
		}
		return "Commands"
	case overlayConfirm:
		return "Confirm"
	case overlayCeremony:
		return "Ceremony"
	default:
		return ""
	}
}

func overlayLegend(kind overlayKind) string {
	switch kind {
	case overlayPalette:
		return "↑/↓ nav   Enter open   / filter   Esc close"
	case overlayDoctor:
		return "r refresh   Esc close"
	case overlayOutput:
		return "j/k scroll   Enter run   / commands   Esc close"
	case overlaySetup, overlayReceipts, overlayPicker:
		return "↑/↓ nav   Enter run   Esc close"
	case overlayConfirm:
		return "type full argv   Esc cancel"
	case overlayCeremony:
		return "type APPROVE or DENY   Esc cancel"
	default:
		return "Esc close   click [x]"
	}
}

func sortCommands(cmds []Command) []Command {
	out := append([]Command(nil), cmds...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := groupRank(displayGroup(out[i])), groupRank(displayGroup(out[j]))
		if ri != rj {
			return ri < rj
		}
		vi, vj := verbRank(out[i].Name), verbRank(out[j].Name)
		if vi != vj {
			return vi < vj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (m model) viewOverlay(kind overlayKind, originY int) string {
	s := m.styles
	cardW := m.width - 2
	if cardW > 100 {
		cardW = 100
	}
	if cardW < 48 {
		cardW = 48
	}
	contentW := cardW - 6
	if contentW < 20 {
		contentW = 20
	}
	title := m.overlayHeading(kind)
	closeLabel := "[x]"
	pad := contentW - lipgloss.Width(title) - lipgloss.Width(closeLabel)
	if pad < 1 {
		pad = 1
	}
	titleRow := s.accent.Render(title) + strings.Repeat(" ", pad) + closeLabel
	closeX := 1 + 2 + lipgloss.Width(title) + pad
	closeY := originY + 1 + 1
	m.addHit(hitClose, 0, closeX, closeY, 3, 1)

	bodyOrigin := originY + 4
	var body string
	switch kind {
	case overlayPalette:
		body = m.viewPalette(bodyOrigin, 1+2)
	case overlayDoctor:
		body = m.viewDoctor()
	case overlaySetup:
		body = m.viewSetupInner(bodyOrigin, 1+2)
	case overlayReceipts:
		body = m.viewReceiptsInner(bodyOrigin, 1+2)
	case overlayOutput:
		body = m.viewOutputInner()
	case overlayPicker:
		body = m.viewPickerInner(bodyOrigin, 1+2)
	case overlayConfirm:
		body = m.viewConfirmInner()
	case overlayCeremony:
		body = m.viewCeremonyInner()
	case overlayShortcuts:
		body = m.viewShortcutsInner()
	}
	inner := titleRow + "\n\n" + body + "\n" + s.muted.Render(overlayLegend(kind))
	return s.card.Width(cardW).Render(inner)
}
