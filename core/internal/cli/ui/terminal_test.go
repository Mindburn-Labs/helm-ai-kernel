package ui

import (
	"os"
	"testing"
)

func TestCapabilitiesFor(t *testing.T) {
	cases := []struct {
		name                string
		inputTTY, chromeTTY bool
		opts                TerminalOptions
		want                Capabilities
	}{
		{
			name:     "text TTY",
			inputTTY: true, chromeTTY: true,
			opts: TerminalOptions{Term: "xterm-256color", Width: 100},
			want: Capabilities{Interactive: true, Color: true, Unicode: true, Width: 100},
		},
		{
			name:     "pipe",
			inputTTY: false, chromeTTY: false,
			opts: TerminalOptions{Width: 100},
			want: Capabilities{Width: 100},
		},
		{
			name:     "NO_COLOR",
			inputTTY: true, chromeTTY: true,
			opts: TerminalOptions{NoColor: true, Term: "xterm-256color", Width: 100},
			want: Capabilities{Interactive: true, Unicode: true, Width: 100},
		},
		{
			name:     "unknown terminal",
			inputTTY: true, chromeTTY: true,
			opts: TerminalOptions{Width: 100},
			want: Capabilities{Interactive: true, Width: 100},
		},
		{
			name:     "TERM dumb",
			inputTTY: true, chromeTTY: true,
			opts: TerminalOptions{Term: "dumb", Width: 100},
			want: Capabilities{Interactive: true, Width: 100},
		},
		{
			name:     "JSON",
			inputTTY: true, chromeTTY: true,
			opts: TerminalOptions{Format: FormatJSON, Width: 100},
			want: Capabilities{Width: 100},
		},
		{
			name:     "always never colors a pipe",
			inputTTY: true, chromeTTY: false,
			opts: TerminalOptions{Color: ColorAlways, Term: "xterm-256color", Width: 100},
			want: Capabilities{Width: 100},
		},
		{
			name:     "unknown color mode fails closed",
			inputTTY: true, chromeTTY: true,
			opts: TerminalOptions{Color: ColorMode("surprise"), Term: "xterm-256color", Width: 100},
			want: Capabilities{Interactive: true, Unicode: true, Width: 100},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CapabilitiesFor(tc.inputTTY, tc.chromeTTY, tc.opts); got != tc.want {
				t.Fatalf("CapabilitiesFor() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestDetectCapabilitiesTreatsPipesAsNonInteractive(t *testing.T) {
	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inputRead.Close()
	defer inputWrite.Close()
	chromeRead, chromeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer chromeRead.Close()
	defer chromeWrite.Close()

	caps := DetectCapabilities(inputRead, chromeWrite, TerminalOptions{Width: 48})
	if caps.Interactive || caps.Color || caps.Unicode {
		t.Fatalf("pipe capabilities = %#v, want presentation disabled", caps)
	}
	if caps.Width != 48 {
		t.Fatalf("pipe width = %d, want 48", caps.Width)
	}
}

func TestTerminalWidth(t *testing.T) {
	if got := terminalWidth("120"); got != 120 {
		t.Fatalf("terminalWidth valid = %d, want 120", got)
	}
	for _, value := range []string{"", "0", "bad", "-1"} {
		if got := terminalWidth(value); got != DefaultTerminalWidth {
			t.Fatalf("terminalWidth(%q) = %d, want %d", value, got, DefaultTerminalWidth)
		}
	}
}
