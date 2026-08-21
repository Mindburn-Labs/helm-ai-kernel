package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const wedge = "Fail-closed execution firewall for AI agents."

type palette struct {
	text     lipgloss.AdaptiveColor
	muted    lipgloss.AdaptiveColor
	accent   lipgloss.AdaptiveColor
	allow    lipgloss.AdaptiveColor
	deny     lipgloss.AdaptiveColor
	wait     lipgloss.AdaptiveColor
	escalate lipgloss.AdaptiveColor
	border   lipgloss.AdaptiveColor
	cursorBg lipgloss.AdaptiveColor
}

func helmPalette() palette {
	return palette{
		text:     lipgloss.AdaptiveColor{Light: "#0F172A", Dark: "#E2E8F0"},
		muted:    lipgloss.AdaptiveColor{Light: "#64748B", Dark: "#94A3B8"},
		accent:   lipgloss.AdaptiveColor{Light: "#0F766E", Dark: "#5EEAD4"},
		allow:    lipgloss.AdaptiveColor{Light: "#15803D", Dark: "#4ADE80"},
		deny:     lipgloss.AdaptiveColor{Light: "#B91C1C", Dark: "#F87171"},
		wait:     lipgloss.AdaptiveColor{Light: "#A16207", Dark: "#FBBF24"},
		escalate: lipgloss.AdaptiveColor{Light: "#C2410C", Dark: "#FB923C"},
		border:   lipgloss.AdaptiveColor{Light: "#0F766E", Dark: "#2DD4BF"},
		cursorBg: lipgloss.AdaptiveColor{Light: "#CCFBF1", Dark: "#134E4A"},
	}
}

type styles struct {
	p          palette
	app        lipgloss.Style
	card       lipgloss.Style
	title      lipgloss.Style
	muted      lipgloss.Style
	accent     lipgloss.Style
	cursor     lipgloss.Style
	footer     lipgloss.Style
	composer   lipgloss.Style
	statusPass lipgloss.Style
	statusDeny lipgloss.Style
	statusWait lipgloss.Style
	statusEsc  lipgloss.Style
}

func newStyles() styles {
	p := helmPalette()
	return styles{
		p: p,
		app: lipgloss.NewStyle().
			Foreground(p.text),
		card: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(p.border).
			Padding(1, 2).
			Foreground(p.text),
		title: lipgloss.NewStyle().
			Bold(true).
			Foreground(p.text),
		muted: lipgloss.NewStyle().
			Foreground(p.muted),
		accent: lipgloss.NewStyle().
			Bold(true).
			Foreground(p.accent),
		cursor: lipgloss.NewStyle().
			Foreground(p.text).
			Background(p.cursorBg).
			Bold(true).
			Padding(0, 1),
		footer: lipgloss.NewStyle().
			Foreground(p.muted),
		composer: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(p.border).
			Padding(0, 1).
			Foreground(p.text),
		statusPass: lipgloss.NewStyle().Foreground(p.allow).Bold(true),
		statusDeny: lipgloss.NewStyle().Foreground(p.deny).Bold(true),
		statusWait: lipgloss.NewStyle().Foreground(p.wait).Bold(true),
		statusEsc:  lipgloss.NewStyle().Foreground(p.escalate).Bold(true),
	}
}

func (s styles) status(label string) lipgloss.Style {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "ALLOW", "PASS", "OK":
		return s.statusPass
	case "DENY", "FAIL":
		return s.statusDeny
	case "ESCALATE":
		return s.statusEsc
	default:
		return s.statusWait
	}
}

func (s styles) mark(label string) string {
	word := "[" + strings.ToUpper(label) + "]"
	return s.status(label).Render(word)
}
