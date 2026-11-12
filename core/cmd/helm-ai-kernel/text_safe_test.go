package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// textSafe is the one place pack-controlled strings are made safe to print.
func TestTextSafe(t *testing.T) {
	for in, want := range map[string]string{
		"plain text · with ünïcode": "plain text · with ünïcode",
		"line\nbreak":               `line\nbreak`,
		"carriage\rreturn":          `carriage\rreturn`,
		"tab\tseparated":            `tab\tseparated`,
		"\x1b[31mred\x1b[0m":        `\x1b[31mred\x1b[0m`,
		"bell\x07 and null\x00":     `bell\x07 and null\x00`,
		"delete\x7f":                `delete\x7f`,
		"c1 \u009b control":         `c1 \u009b control`,
		"override \u202e reversed":  `override \u202e reversed`,
		"isolate \u2066 text":       `isolate \u2066 text`,
		"separator \u2028 line":     `separator \u2028 line`,
		"zero width \u200b space":   `zero width \u200b space`,
		"byte order mark \ufeff":    `byte order mark \ufeff`,
		"invalid \xff utf8":         `invalid \xff utf8`,
		// A backslash is escaped too, so an escape in the output can only
		// come from the escaping: `A\nB` and "A\nB" print apart.
		`C:\path\name`: `C:\\path\\name`,
		`literal \n`:   `literal \\n`,
		// F5: the pair the review found printing alike.
		"A\nB": `A\nB`,
		`A\nB`: `A\\nB`,
		// Characters that print as blank space are escaped like the format
		// characters that hide text, and so is a long run of spaces, which
		// can push the rest of a line onto a wrapped line of its own.
		"no-break\u00a0space":              `no-break\u00a0space`,
		"ideographic\u3000space":           `ideographic\u3000space`,
		"hangul\u3164filler":               `hangul\u3164filler`,
		"braille\u2800blank":               `braille\u2800blank`,
		"two  spaces stay":                 "two  spaces stay",
		"a" + strings.Repeat(" ", 8) + "b": "a" + strings.Repeat(`\x20`, 8) + "b",
		// Up to two combining marks on one letter is ordinary text; a stack
		// of them is escaped from the third on.
		"accent e\u0301":                  "accent e\u0301",
		"stacked e\u0301\u0302":           "stacked e\u0301\u0302",
		"tower e\u0301\u0302\u0303\u0304": "tower e\u0301\u0302" + `\u0303\u0304`,
		"":                                "",
	} {
		if got := textSafe(in); got != want {
			t.Errorf("textSafe(%q) = %q, want %q", in, got, want)
		}
	}

	// F5: a real line break and a written backslash-n used to print alike.
	if textSafe("A\nB") == textSafe(`A\nB`) {
		t.Errorf("textSafe prints %q and %q the same: %q", "A\nB", `A\nB`, textSafe("A\nB"))
	}

	// writeText applies it to every argument, whatever its string type.
	type verdict string
	var out bytes.Buffer
	writeText(&out, "%s|%s|%v|%d|%s\n", "a\nb", verdict("c\x1bd"), json.Number("1\n2"), 7, os.ErrNotExist)
	if got, want := out.String(), "a\\nb|c\\x1bd|1\\n2|7|file does not exist\n"; got != want {
		t.Errorf("writeText wrote %q, want %q", got, want)
	}
}

// NF2: textSafe looked at the whole run of spaces around each space it
// escaped, so a run of n spaces cost n*n steps: `verify` took 273 s to print
// an envelope id holding 1,000,000 spaces. Each run is now measured once.
func TestTextSafe_ALongRunOfSpacesTakesLinearTime(t *testing.T) {
	const spaces = 1_000_000
	in := "a" + strings.Repeat(" ", spaces) + "b"
	done := make(chan string, 1)
	go func() { done <- textSafe(in) }()
	select {
	case got := <-done:
		if want := "a" + strings.Repeat(`\x20`, spaces) + "b"; got != want {
			t.Fatalf("textSafe of %d spaces returned %d bytes, want %d", spaces, len(got), len(want))
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("textSafe of a run of %d spaces took longer than 5 s", spaces)
	}
}

// NF4 (N30): three spaces in a row are already a run that is escaped.
func TestTextSafe_ThreeSpacesAreARun(t *testing.T) {
	for in, want := range map[string]string{
		"a  b":    "a  b",
		"a   b":   `a\x20\x20\x20b`,
		"   ":     `\x20\x20\x20`,
		"a   ":    `a\x20\x20\x20`,
		"a  b  c": "a  b  c",
	} {
		if got := textSafe(in); got != want {
			t.Errorf("textSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

// NF6: a combining mark past the second one on a letter is escaped, and one
// above U+FFFF needs all its digits: written as \u%04x, U+E0100 printed as
// `0`, the same as U+E010 followed by the digit 0.
func TestTextSafe_AnEscapedMarkAboveUFFFFKeepsAllItsDigits(t *testing.T) {
	mark := textSafe("á́\U000E0100")
	if want := "á́" + `\U000e0100`; mark != want {
		t.Fatalf("textSafe(third mark U+E0100) = %q, want %q", mark, want)
	}
	if other := textSafe("á́" + "0"); other == mark {
		t.Fatalf("textSafe prints U+E0100 and U+E010 followed by 0 the same: %q", mark)
	}
}
