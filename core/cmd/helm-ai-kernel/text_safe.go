package main

import (
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"
)

// textSafe makes a string safe to print on one line of text output.
//
// `verify`, `evidence inspect` and `replay` print strings they read out of the
// pack: an envelope id, a run id, file names, check names and reasons. A line
// break in one of them adds a line that reads like the command's own verdict,
// and a terminal escape can erase the real one. textSafe replaces every
// character that is not printable with a visible escape: line breaks, tabs,
// other control characters (which covers the ESC that starts an ANSI
// sequence), invalid UTF-8, and the Unicode format characters that reorder or
// hide text. Printable text, including non-ASCII letters and spaces, is kept.
//
// JSON output does not use it: encoding/json already escapes these characters,
// and a consumer needs the value as the pack states it.
func textSafe(s string) string {
	clean := true
	for _, r := range s {
		if !textSafeRune(r) {
			clean = false
			break
		}
	}
	if clean && utf8.ValidString(s) {
		return s
	}

	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case textSafeRune(r):
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x80:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
		i += size
	}
	return b.String()
}

// textSafeRune reports whether r prints as itself: a graphic character or a
// space. unicode.IsPrint excludes control (Cc) and format (Cf) characters and
// the line and paragraph separators, which are the ones that move the cursor,
// reorder text or hide it.
func textSafeRune(r rune) bool {
	if r == utf8.RuneError {
		return false
	}
	return unicode.IsPrint(r) || unicode.Is(unicode.Zs, r)
}

// writeText formats like fmt.Fprintf after passing every string, error and
// fmt.Stringer argument through textSafe. The text output of `verify`,
// `evidence inspect` and `replay` goes through it, so a string read from a pack
// cannot reach the terminal raw by being added to a new format call. The
// format itself is never pack-controlled.
//
// It looks at each argument, not inside it: pass the elements of a slice or
// the fields of a struct one by one.
func writeText(w io.Writer, format string, args ...any) {
	safe := make([]any, len(args))
	for i, arg := range args {
		safe[i] = textSafeArg(arg)
	}
	_, _ = fmt.Fprintf(w, format, safe...)
}

func textSafeArg(arg any) any {
	switch v := arg.(type) {
	case string:
		return textSafe(v)
	case error:
		return textSafe(v.Error())
	case fmt.Stringer:
		return textSafe(v.String())
	}
	// Named string types such as receiptverify.Verdict.
	if value := reflect.ValueOf(arg); value.IsValid() && value.Kind() == reflect.String {
		return textSafe(value.String())
	}
	return arg
}
