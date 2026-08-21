package ui

import (
	"io"
	"strings"
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
	StatusAllow    Status = "allow"
)

// Label returns the stable, color-independent status word.
func (s Status) Label() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusAllow:
		return "ALLOW"
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

// StatusFromVerdict maps HELM decision words onto the shared status set.
func StatusFromVerdict(verdict string) Status {
	switch strings.ToUpper(strings.TrimSpace(verdict)) {
	case "ALLOW", "ALLOWED", "PASS", "OK", "VERIFIED":
		return StatusAllow
	case "DENY", "DENIED", "FAIL", "FAILED":
		return StatusDeny
	case "ESCALATE", "ESCALATED":
		return StatusEscalate
	case "PENDING", "WAIT", "WAITING":
		return StatusWait
	case "WARN", "WARNING":
		return StatusWarn
	default:
		return StatusWarn
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

// BrandHeader is the compact identity block used by the front door, help, and TUI.
type BrandHeader struct {
	Name    string
	Tagline string
	Version string
	Commit  string
	Context string
	Hint    string
}

// CommandRow is one aligned catalog entry (gh / Grok inspect language).
type CommandRow struct {
	Name    string
	Usage   string
	Aliases []string
}

// EventLine is one Grok-style tool-call / receipt row.
type EventLine struct {
	Status Status
	Actor  string
	Action string
	Detail string
	Meta   string
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

// Section renders a Grok-style heading. Words stay intact without color.
func (r Renderer) Section(title string) string {
	t := strings.TrimSpace(title)
	if t == "" {
		return ""
	}
	if r.caps.Color {
		return r.paint(t, ansiBold+ansiFgCyan) + "\n"
	}
	return t + "\n"
}

// Timeline renders compact guided progress without cursor controls or a
// full-screen session. Every title and detail remains present after wrapping.
func (r Renderer) Timeline(title string, steps []Step) string {
	var b strings.Builder
	if strings.TrimSpace(title) != "" {
		appendWrapped(&b, "", "", r.Bold(strings.TrimSpace(title)), r.width())
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
		line := strings.TrimSpace(r.statusMarker(step.Status) + " " + step.Title)
		appendWrapped(&b, prefix, continuation, line, r.width())
		if strings.TrimSpace(step.Detail) != "" {
			appendWrapped(&b, continuation, continuation, r.Dim(step.Detail), r.width())
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
	r.Write(r.Timeline(title, steps))
}

// Brand renders the Grok welcome-card analog: closed panel, identity inside.
func (r Renderer) Brand(h BrandHeader) string {
	name := strings.TrimSpace(h.Name)
	if name == "" {
		name = "HELM"
	}
	title := r.Bold(name)
	if meta := r.Meta(h.Version, h.Commit); meta != "" {
		title += "  " + r.Dim(meta)
	}
	lines := []string{title}
	if t := strings.TrimSpace(h.Tagline); t != "" {
		lines = append(lines, r.Dim(t))
	}
	if c := strings.TrimSpace(h.Context); c != "" {
		lines = append(lines, r.Dim(c))
	}
	if n := strings.TrimSpace(h.Hint); n != "" {
		lines = append(lines, r.Dim(n))
	}
	return r.panel(lines)
}

// CommandTable renders an aligned name/usage list like `gh` and Grok inspect.
func (r Renderer) CommandTable(rows []CommandRow) string {
	nameW := 8
	for _, row := range rows {
		if w := visibleWidth(row.Name); w > nameW {
			nameW = w
		}
	}
	if nameW > 22 {
		nameW = 22
	}
	var b strings.Builder
	indent := "  "
	for _, row := range rows {
		usage := strings.TrimSpace(row.Usage)
		if len(row.Aliases) > 0 {
			usage = strings.TrimSpace(usage + "  (" + strings.Join(row.Aliases, ", ") + ")")
		}
		gap := nameW - visibleWidth(row.Name)
		if gap < 0 {
			gap = 0
		}
		head := indent + r.Bold(row.Name) + strings.Repeat(" ", gap+2)
		if usage == "" {
			b.WriteString(head)
			b.WriteByte('\n')
			continue
		}
		remain := r.width() - visibleWidth(indent) - nameW - 2
		parts := wrapText(usage, remain)
		if len(parts) == 0 {
			parts = []string{""}
		}
		b.WriteString(head)
		b.WriteString(r.Dim(parts[0]))
		b.WriteByte('\n')
		cont := indent + strings.Repeat(" ", nameW+2)
		for _, part := range parts[1:] {
			b.WriteString(cont)
			b.WriteString(r.Dim(part))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// Event renders one streaming tool-call / receipt row.
func (r Renderer) Event(e EventLine) string {
	var b strings.Builder
	head := r.Status(e.Status)
	if a := strings.TrimSpace(e.Actor); a != "" {
		head += "  " + a
	}
	if a := strings.TrimSpace(e.Action); a != "" {
		head += "  " + r.Bold(a)
	}
	if m := strings.TrimSpace(e.Meta); m != "" {
		head += "  " + r.Dim(m)
	}
	appendWrapped(&b, "  ", "         ", head, r.width())
	if d := strings.TrimSpace(e.Detail); d != "" {
		d = strings.TrimPrefix(d, "→ ")
		appendWrapped(&b, "         ", "         ", r.Dim(d), r.width())
	}
	return b.String()
}

// Completion renders a width-aware end-state card. ASCII terminals get the
// same state and next action with ASCII borders. Unicode uses Grok's rounded
// closed panel with the title inside, not hanging off the left edge.
func (r Renderer) Completion(card CompletionCard) string {
	title := strings.TrimSpace(card.Title)
	if title == "" {
		title = "Complete"
	}
	fields := append([]KeyValue(nil), card.Fields...)
	if strings.TrimSpace(card.NextAction) != "" {
		fields = append(fields, KeyValue{Key: "Next", Value: card.NextAction})
	}

	if r.caps.Compact() {
		var b strings.Builder
		appendWrapped(&b, "", "", title, r.width())
		for _, field := range fields {
			appendWrapped(&b, "", "  ", keyValueText(field), r.width())
		}
		return b.String()
	}

	lines := []string{r.Bold(title)}
	for _, field := range fields {
		lines = append(lines, keyValueText(field))
	}
	return r.panel(lines)
}

// WriteCompletion writes Completion to Chrome only.
func (r Renderer) WriteCompletion(card CompletionCard) {
	r.Write(r.Completion(card))
}

// Write emits chrome. Nil writers are ignored.
func (r Renderer) Write(s string) {
	if r.chrome != nil && s != "" {
		_, _ = io.WriteString(r.chrome, s)
	}
}

func (r Renderer) width() int {
	if r.caps.Width <= 0 {
		return DefaultTerminalWidth
	}
	return r.caps.Width
}

func (r Renderer) style(value, ansi string) string {
	return r.paint(value, ansi)
}

type boxGlyphs struct {
	tl, tr, bl, br, h, v string
}

func (r Renderer) glyphs() boxGlyphs {
	if r.caps.Unicode {
		return boxGlyphs{"╭", "╮", "╰", "╯", "─", "│"}
	}
	return boxGlyphs{"+", "+", "+", "+", "-", "|"}
}

func (r Renderer) panel(lines []string) string {
	width := r.width()
	if width < 20 {
		width = 20
	}
	if r.caps.Compact() {
		var b strings.Builder
		for _, line := range lines {
			appendWrapped(&b, "", "  ", line, width)
		}
		return b.String()
	}
	g := r.glyphs()
	inner := width - 2
	if inner < 12 {
		inner = 12
	}
	contentWidth := inner - 2
	if contentWidth < 8 {
		contentWidth = 8
	}

	var body []string
	for _, line := range lines {
		if strings.TrimSpace(stripANSI(line)) == "" {
			body = append(body, "")
			continue
		}
		body = append(body, wrapText(line, contentWidth)...)
	}

	var b strings.Builder
	b.WriteString(g.tl)
	b.WriteString(strings.Repeat(g.h, inner))
	b.WriteString(g.tr)
	b.WriteByte('\n')
	for _, line := range body {
		b.WriteString(g.v)
		b.WriteByte(' ')
		b.WriteString(padVisible(line, contentWidth))
		b.WriteByte(' ')
		b.WriteString(g.v)
		b.WriteByte('\n')
	}
	b.WriteString(g.bl)
	b.WriteString(strings.Repeat(g.h, inner))
	b.WriteString(g.br)
	b.WriteByte('\n')
	return b.String()
}

func statusGlyph(status Status) string {
	switch status {
	case StatusPass, StatusAllow:
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
	case StatusPass, StatusAllow:
		return ansiFgGreen
	case StatusWarn, StatusWait:
		return ansiFgYellow
	case StatusFail, StatusDeny:
		return ansiFgRed
	case StatusEscalate:
		return ansiFgMagenta
	default:
		return ansiFgYellow
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
	lines := wrapText(text, width-visibleWidth(firstPrefix))
	for i, line := range lines {
		prefix := firstPrefix
		if i > 0 {
			prefix = continuationPrefix
			lineWidth := width - visibleWidth(prefix)
			if visibleWidth(line) > lineWidth {
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
			} else if visibleWidth(line)+1+visibleWidth(word) <= width {
				line += " " + word
			} else {
				lines = append(lines, line)
				line = word
			}
			for visibleWidth(line) > width {
				part, remainder := splitVisible(line, width)
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

func splitVisible(value string, width int) (string, string) {
	plain := stripANSI(value)
	runes := []rune(plain)
	if len(runes) <= width {
		return value, ""
	}
	return string(runes[:width]), string(runes[width:])
}
