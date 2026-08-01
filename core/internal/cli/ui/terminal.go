package ui

import (
	"os"
	"strconv"
	"strings"

	"github.com/mattn/go-isatty"
)

const (
	// DefaultTerminalWidth keeps rendering deterministic when the terminal does
	// not expose a width.
	DefaultTerminalWidth = 80
	// CompactTerminalWidth is the single breakpoint used by the renderers.
	CompactTerminalWidth = 72
)

// ColorMode is the requested human-output color policy. It never overrides a
// pipe, JSON output, NO_COLOR, or TERM=dumb.
type ColorMode string

const (
	ColorAuto   ColorMode = "auto"
	ColorAlways ColorMode = "always"
	ColorNever  ColorMode = "never"
)

// TerminalOptions supplies the command's already-parsed output mode. Tests
// pass explicit values rather than relying on the test runner's terminal.
type TerminalOptions struct {
	Format  Format
	Color   ColorMode
	NoColor bool
	Term    string
	Width   int
}

// Capabilities describes the safe presentation features available to a
// command. Renderers use Chrome only; Data is never part of this value.
type Capabilities struct {
	Interactive bool
	Color       bool
	Unicode     bool
	Width       int
}

// Compact reports whether the renderer should use its compact layout.
func (c Capabilities) Compact() bool { return c.Width < CompactTerminalWidth }

// DetectCapabilities derives capabilities from the process terminals and
// environment. It is deliberately conservative: only a terminal Chrome stream
// receives color or Unicode, and JSON receives neither.
func DetectCapabilities(input, chrome *os.File, opts TerminalOptions) Capabilities {
	if !opts.NoColor {
		opts.NoColor = os.Getenv("NO_COLOR") != ""
	}
	if opts.Term == "" {
		opts.Term = os.Getenv("TERM")
	}
	if opts.Width <= 0 {
		opts.Width = terminalWidth(os.Getenv("COLUMNS"))
	}
	return CapabilitiesFor(isTerminal(input), isTerminal(chrome), opts)
}

// CapabilitiesFor is the deterministic counterpart to DetectCapabilities for
// tests and callers that already know the terminal state.
func CapabilitiesFor(inputTTY, chromeTTY bool, opts TerminalOptions) Capabilities {
	term := strings.ToLower(strings.TrimSpace(opts.Term))
	width := opts.Width
	if width <= 0 {
		width = DefaultTerminalWidth
	}

	humanOutput := !opts.Format.IsJSON()
	terminalPresentation := chromeTTY && humanOutput && term != "" && term != "dumb"
	colorRequested := opts.Color == "" || opts.Color == ColorAuto || opts.Color == ColorAlways
	return Capabilities{
		Interactive: inputTTY && chromeTTY && humanOutput,
		Color:       terminalPresentation && !opts.NoColor && colorRequested,
		Unicode:     terminalPresentation,
		Width:       width,
	}
}

func isTerminal(f *os.File) bool {
	return f != nil && (isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()))
}

func terminalWidth(columns string) int {
	width, err := strconv.Atoi(strings.TrimSpace(columns))
	if err != nil || width <= 0 {
		return DefaultTerminalWidth
	}
	return width
}
