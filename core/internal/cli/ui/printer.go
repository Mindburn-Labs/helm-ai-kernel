package ui

import (
	"fmt"
	"io"
	"strings"
)

// Printer is the single chrome surface every command should write through.
// It binds a Renderer to a writer and keeps TTY/plain/JSON policy in one place.
type Printer struct {
	Out io.Writer
	R   Renderer
}

// NewPrinter builds a printer from a chrome writer.
func NewPrinter(out io.Writer) Printer {
	return Printer{Out: out, R: NewRenderer(out, WriterCapabilities(out))}
}

// NewPrinterWithCaps is the testable constructor.
func NewPrinterWithCaps(out io.Writer, caps Capabilities) Printer {
	return Printer{Out: out, R: NewRenderer(out, caps)}
}

func (p Printer) write(s string) {
	if p.Out == nil || s == "" {
		return
	}
	_, _ = io.WriteString(p.Out, s)
}

// Write emits renderer-formatted chrome.
func (p Printer) Write(s string) { p.write(s) }

// Title prints a Grok-style section heading.
func (p Printer) Title(s string) { p.write(p.R.Section(s)) }

// Muted prints de-emphasized supporting text plus a newline.
func (p Printer) Muted(s string) {
	p.write(p.R.Dim(strings.TrimRight(s, "\n")) + "\n")
}

// Line prints a body line.
func (p Printer) Line(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	p.write(s)
	if !strings.HasSuffix(s, "\n") {
		p.write("\n")
	}
}

// StatusLine prints a labeled status row.
func (p Printer) StatusLine(status Status, msg string) {
	p.write("  " + p.R.Status(status) + " " + msg + "\n")
}

// KV prints an aligned key/value row.
func (p Printer) KV(key, value string) {
	p.write("  " + padVisible(key, 12) + "  " + value + "\n")
}

// Event prints one tool-call / receipt line.
func (p Printer) Event(e EventLine) { p.write(p.R.Event(e)) }

// Card prints a closed Grok-style completion panel.
func (p Printer) Card(card CompletionCard) { p.write(p.R.Completion(card)) }

// Brand prints the compact identity panel.
func (p Printer) Brand(h BrandHeader) { p.write(p.R.Brand(h)) }

// Table prints an aligned command or key list.
func (p Printer) Table(rows []CommandRow) { p.write(p.R.CommandTable(rows)) }

// Blank writes a newline.
func (p Printer) Blank() { p.write("\n") }
