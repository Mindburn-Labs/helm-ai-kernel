package ui

import (
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	ansiReset     = "\x1b[0m"
	ansiBold      = "\x1b[1m"
	ansiDim       = "\x1b[2m"
	ansiFgRed     = "\x1b[31m"
	ansiFgGreen   = "\x1b[32m"
	ansiFgYellow  = "\x1b[33m"
	ansiFgMagenta = "\x1b[35m"
	ansiFgCyan    = "\x1b[36m"
)

var ansiSequence = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiSequence.ReplaceAllString(s, "")
}

func visibleWidth(s string) int {
	return utf8.RuneCountInString(stripANSI(s))
}

func padVisible(s string, width int) string {
	w := visibleWidth(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

// WriterCapabilities derives presentation from a chrome writer. Buffers,
// JSON, and non-files stay plain so tests and pipes remain parseable.
func WriterCapabilities(chrome io.Writer) Capabilities {
	file, ok := chrome.(*os.File)
	if !ok {
		return Capabilities{Width: DefaultTerminalWidth}
	}
	return DetectCapabilities(os.Stdin, file, TerminalOptions{
		Format: FormatText,
		Color:  ColorAuto,
	})
}

// Meta joins non-empty parts with a Grok-style separator: middle-dot when
// Unicode is available, otherwise a plain pipe.
func (r Renderer) Meta(parts ...string) string {
	sep := " | "
	if r.caps.Unicode {
		sep = " · "
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, sep)
}

// Bold emphasizes a fragment when color is enabled.
func (r Renderer) Bold(s string) string { return r.paint(s, ansiBold) }

// Dim de-emphasizes supporting text when color is enabled.
func (r Renderer) Dim(s string) string { return r.paint(s, ansiDim) }

// Cyan is the HELM accent, used for section titles.
func (r Renderer) Cyan(s string) string { return r.paint(s, ansiFgCyan) }

func (r Renderer) paint(value, ansi string) string {
	if !r.caps.Color || value == "" || ansi == "" {
		return value
	}
	return ansi + value + ansiReset
}
