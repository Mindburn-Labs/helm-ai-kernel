package ui

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestStatusAlwaysHasPlainLabel(t *testing.T) {
	plain := NewRenderer(nil, Capabilities{Width: 80})
	for _, status := range []Status{StatusPass, StatusWarn, StatusFail, StatusDeny, StatusEscalate} {
		got := plain.Status(status)
		if !strings.Contains(got, "["+status.Label()+"]") {
			t.Fatalf("%s marker = %q, missing visible label", status, got)
		}
		if strings.Contains(got, "\x1b") {
			t.Fatalf("plain %s marker contains ANSI: %q", status, got)
		}
	}

	colored := NewRenderer(nil, Capabilities{Color: true, Unicode: true, Width: 80}).Status(StatusPass)
	if !strings.Contains(colored, "\x1b[") || !strings.Contains(colored, "[PASS]") {
		t.Fatalf("colored status = %q, want ANSI plus PASS label", colored)
	}
}

func TestTimelineUsesCompactASCIIFallbackAndWraps(t *testing.T) {
	renderer := NewRenderer(nil, Capabilities{Width: 34})
	got := renderer.Timeline("Activation", []Step{{
		Status: StatusDeny,
		Title:  "Approval required",
		Detail: "Policy requires a recorded decision before this command can continue.",
	}})
	if strings.Contains(got, "\x1b") || strings.Contains(got, "│") || strings.Contains(got, "✓") {
		t.Fatalf("compact ASCII timeline contains decoration: %q", got)
	}
	for _, want := range []string{"[DENY]", "recorded", "decision", "continue"} {
		if !strings.Contains(got, want) {
			t.Fatalf("compact timeline = %q, missing %q", got, want)
		}
	}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if utf8.RuneCountInString(line) > 34 {
			t.Fatalf("line exceeds width: %q", line)
		}
	}
}

func TestCompletionUsesWideASCIICardAndChromeOnly(t *testing.T) {
	var data, chrome bytes.Buffer
	renderer := NewRenderer(NewStreams(&data, &chrome).Chrome, Capabilities{Width: 80})
	renderer.WriteCompletion(CompletionCard{
		Title:      "HELM is active",
		Fields:     []KeyValue{{Key: "Scope", Value: "this project"}},
		NextAction: "helm-ai-kernel receipts tail",
	})
	got := chrome.String()
	if data.Len() != 0 {
		t.Fatalf("renderer polluted data stream: %q", data.String())
	}
	for _, want := range []string{"+ HELM is active", "| Scope: this project", "Next: helm-ai-kernel receipts tail"} {
		if !strings.Contains(got, want) {
			t.Fatalf("completion = %q, missing %q", got, want)
		}
	}
	if strings.Contains(got, "\x1b") || strings.Contains(got, "┌") {
		t.Fatalf("ASCII completion contains unsupported decoration: %q", got)
	}
}

func TestNoColorAndDumbRendererNeverEmitANSI(t *testing.T) {
	for _, caps := range []Capabilities{
		CapabilitiesFor(true, true, TerminalOptions{NoColor: true, Term: "xterm-256color", Width: 80}),
		CapabilitiesFor(true, true, TerminalOptions{Term: "dumb", Width: 80}),
		CapabilitiesFor(true, true, TerminalOptions{NoColor: true, Term: "dumb", Width: 80}),
		CapabilitiesFor(true, true, TerminalOptions{Format: FormatJSON, Width: 80}),
		CapabilitiesFor(false, false, TerminalOptions{Width: 80}),
	} {
		renderer := NewRenderer(nil, caps)
		got := renderer.Status(StatusFail) + renderer.Timeline("Check", []Step{{Status: StatusDeny, Title: "blocked"}})
		if strings.Contains(got, "\x1b") {
			t.Fatalf("capabilities %#v emitted ANSI: %q", caps, got)
		}
	}
}

func TestTimelineWrapsRunesWithoutCorruption(t *testing.T) {
	got := NewRenderer(nil, Capabilities{Width: 24}).Timeline("Prüfung", []Step{{
		Status: StatusWarn,
		Title:  "café approval",
		Detail: "évidence remains readable",
	}})
	if !utf8.ValidString(got) {
		t.Fatalf("wrapped timeline is not valid UTF-8: %q", got)
	}
	for _, want := range []string{"Prüfung", "café", "évidence"} {
		if !strings.Contains(got, want) {
			t.Fatalf("wrapped timeline = %q, missing %q", got, want)
		}
	}
}
