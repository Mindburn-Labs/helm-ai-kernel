package ui

import (
	"io"
	"strings"
	"unicode/utf8"
)

// Status is a visible decision state. Its label is always rendered, including
// in no-color and ASCII modes.
type Status string

const (
	StatusPass     Status = "pass"
	StatusWarn     Status = "warn"
	StatusFail     Status = "fail"
	StatusDeny     Status = "deny"
	StatusEscalate Status = "escalate"
	StatusWait     Status = "wait"
)

// Label returns the stable, color-independent status word.
func (s Status) Label() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusWarn:
		return "WARN"
	case StatusFail:
		return "FAIL"
	case StatusDeny:
		return "DENY"
	case StatusEscalate:
		return "ESCALATE"
	case StatusWait:
		return "WAIT"
	default:
		return "WARN"
	}
}

// Step is one guided timeline entry.
type Step struct {
	Status Status
	Title  string
	Detail string
}

// KeyValue is an item in a completion or decision review card.
type KeyValue struct {
	Key   string
	Value string
}

// CompletionCard summarizes a completed human journey. It has no effect on
// command data: it is rendered only through a Renderer bound to Chrome.
type CompletionCard struct {
	Title      string
	Fields     []KeyValue
	NextAction string
}

// Renderer writes human-oriented terminal chrome. Commands keep structured
// data on Streams.Data and construct the renderer with Streams.Chrome.
type Renderer struct {
	chrome io.Writer
	caps   Capabilities
}

// NewRenderer binds a renderer to the command's Chrome (stderr) stream.
func NewRenderer(chrome io.Writer, caps Capabilities) Renderer {
	return Renderer{chrome: chrome, caps: caps}
}

// Capabilities returns the renderer's fixed capabilities.
func (r Renderer) Capabilities() Capabilities { return r.caps }

// Status renders a semantic status marker with an optional decorative glyph.
func (r Renderer) Status(status Status) string {
	return r.style(r.statusMarker(status), statusANSI(status))
}

// Timeline renders compact guided progress without cursor controls or a
// full-screen session. Every title and detail remains present after wrapping.
func (r Renderer) Timeline(title string, steps []Step) string {
	var b strings.Builder
	if strings.TrimSpace(title) != "" {
		appendWrapped(&b, "", "", title, r.width())
	}

	prefix, continuation := "", "  "
	if !r.caps.Compact() {
		if r.caps.Unicode {
			prefix, continuation = "│ ", "│   "
		} else {
			prefix, continuation = "| ", "|   "
		}
	}
	for _, step := range steps {
		// Keep ANSI out of the wrapped text. The standalone Status helper is
		// colored when supported; timeline labels stay equally legible in all
		// layouts without control-sequence width accounting.
		line := strings.TrimSpace(r.statusMarker(step.Status) + " " + step.Title)
		appendWrapped(&b, prefix, continuation, line, r.width())
		if strings.TrimSpace(step.Detail) != "" {
			appendWrapped(&b, continuation, continuation, step.Detail, r.width())
		}
	}
	return b.String()
}

func (r Renderer) statusMarker(status Status) string {
	label := "[" + status.Label() + "]"
	if r.caps.Unicode {
		label = statusGlyph(status) + " " + label
	}
	return label
}

// WriteTimeline writes Timeline to Chrome only.
func (r Renderer) WriteTimeline(title string, steps []Step) {
	if r.chrome != nil {
		_, _ = io.WriteString(r.chrome, r.Timeline(title, steps))
	}
}

// Completion renders a width-aware end-state card. ASCII terminals get the
// same state and next action with ASCII borders.
func (r Renderer) Completion(card CompletionCard) string {
	var b strings.Builder
	title := strings.TrimSpace(card.Title)
	if title == "" {
		title = "Complete"
	}

	if r.caps.Compact() {
		appendWrapped(&b, "", "", title, r.width())
		for _, field := range card.Fields {
			appendWrapped(&b, "", "  ", keyValueText(field), r.width())
		}
		if strings.TrimSpace(card.NextAction) != "" {
			appendWrapped(&b, "", "  ", "Next: "+card.NextAction, r.width())
		}
		return b.String()
	}

	open, line, close := "+ ", "| ", "+\n"
	if r.caps.Unicode {
		open, line, close = "┌ ", "│ ", "└\n"
	}
	appendWrapped(&b, open, line, title, r.width())
	for _, field := range card.Fields {
		appendWrapped(&b, line, line, keyValueText(field), r.width())
	}
	if strings.TrimSpace(card.NextAction) != "" {
		appendWrapped(&b, line, line, "Next: "+card.NextAction, r.width())
	}
	b.WriteString(close)
	return b.String()
}

// WriteCompletion writes Completion to Chrome only.
func (r Renderer) WriteCompletion(card CompletionCard) {
	if r.chrome != nil {
		_, _ = io.WriteString(r.chrome, r.Completion(card))
	}
}

func (r Renderer) width() int {
	if r.caps.Width <= 0 {
		return DefaultTerminalWidth
	}
	return r.caps.Width
}

func (r Renderer) style(value, ansi string) string {
	if !r.caps.Color {
		return value
	}
	return ansi + value + "\x1b[0m"
}

func statusGlyph(status Status) string {
	switch status {
	case StatusPass:
		return "✓"
	case StatusWarn:
		return "!"
	case StatusFail, StatusDeny:
		return "×"
	case StatusEscalate:
		return "↑"
	case StatusWait:
		return "…"
	default:
		return "!"
	}
}

func statusANSI(status Status) string {
	switch status {
	case StatusPass:
		return "\x1b[32m"
	case StatusWarn, StatusWait:
		return "\x1b[33m"
	case StatusFail, StatusDeny:
		return "\x1b[31m"
	case StatusEscalate:
		return "\x1b[35m"
	default:
		return "\x1b[33m"
	}
}

func keyValueText(field KeyValue) string {
	key := strings.TrimSpace(field.Key)
	if key == "" {
		key = "Detail"
	}
	value := strings.TrimSpace(field.Value)
	if value == "" {
		value = "(not supplied)"
	}
	return key + ": " + value
}

func appendWrapped(b *strings.Builder, firstPrefix, continuationPrefix, text string, width int) {
	lines := wrapText(text, width-runeWidth(firstPrefix))
	for i, line := range lines {
		prefix := firstPrefix
		if i > 0 {
			prefix = continuationPrefix
			lineWidth := width - runeWidth(prefix)
			if runeWidth(line) > lineWidth {
				// The first pass uses firstPrefix's width; rewrap continuation
				// lines if it is narrower.
				for _, part := range wrapText(line, lineWidth) {
					b.WriteString(prefix)
					b.WriteString(part)
					b.WriteByte('\n')
				}
				continue
			}
		}
		b.WriteString(prefix)
		b.WriteString(line)
		b.WriteByte('\n')
	}
}

func wrapText(text string, width int) []string {
	if width < 1 {
		width = 1
	}
	var lines []string
	for _, paragraph := range strings.Split(text, "\n") {
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}
		line := ""
		for _, word := range words {
			if line == "" {
				line = word
			} else if runeWidth(line)+1+runeWidth(word) <= width {
				line += " " + word
			} else {
				lines = append(lines, line)
				line = word
			}
			for runeWidth(line) > width {
				part, remainder := splitRunes(line, width)
				lines = append(lines, part)
				line = remainder
			}
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func splitRunes(value string, width int) (string, string) {
	runes := []rune(value)
	if len(runes) <= width {
		return value, ""
	}
	return string(runes[:width]), string(runes[width:])
}

func runeWidth(value string) int { return utf8.RuneCountInString(value) }
