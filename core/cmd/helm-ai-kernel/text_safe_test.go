package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// textSafe is the one place pack-controlled strings are made safe to print.
func TestTextSafe(t *testing.T) {
	for in, want := range map[string]string{
		"plain text · with ünïcode":   "plain text · with ünïcode",
		"line\nbreak":                 `line\nbreak`,
		"carriage\rreturn":            `carriage\rreturn`,
		"tab\tseparated":              `tab\tseparated`,
		"\x1b[31mred\x1b[0m":          `\x1b[31mred\x1b[0m`,
		"bell\x07 and null\x00":       `bell\x07 and null\x00`,
		"delete\x7f":                  `delete\x7f`,
		"c1 \u009b control":           `c1 \u009b control`,
		"override \u202e reversed":    `override \u202e reversed`,
		"isolate \u2066 text":         `isolate \u2066 text`,
		"separator \u2028 line":       `separator \u2028 line`,
		"zero width \u200b space":     `zero width \u200b space`,
		"byte order mark \ufeff":      `byte order mark \ufeff`,
		"invalid \xff utf8":           `invalid \xff utf8`,
		`C:\path\name stays as it is`: `C:\path\name stays as it is`,
		"":                            "",
	} {
		if got := textSafe(in); got != want {
			t.Errorf("textSafe(%q) = %q, want %q", in, got, want)
		}
	}

	// writeText applies it to every argument, whatever its string type.
	type verdict string
	var out bytes.Buffer
	writeText(&out, "%s|%s|%v|%d|%s\n", "a\nb", verdict("c\x1bd"), json.Number("1\n2"), 7, os.ErrNotExist)
	if got, want := out.String(), "a\\nb|c\\x1bd|1\\n2|7|file does not exist\n"; got != want {
		t.Errorf("writeText wrote %q, want %q", got, want)
	}
}
