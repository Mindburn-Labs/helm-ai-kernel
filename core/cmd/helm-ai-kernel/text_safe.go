package main

import (
	"fmt"
	"io"
	"reflect"
	"slices"
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
// hide text. Characters that print as blank space are escaped too (space
// separators other than the ASCII space, the Hangul fillers, the blank Braille
// pattern), and so is a run of three or more spaces and every combining mark
// after the second on one letter: each can push text onto a wrapped line of
// its own or stack it out of sight. Printable text, including non-ASCII
// letters and one or two spaces in a row, is kept.
//
// A backslash is always written as `\\`, so an escape in the output comes
// only from the escaping: the string A, line break, B prints as `A\nB`, and
// the four characters A, backslash, n, B print as `A\\nB`.
//
// JSON output does not use it: encoding/json already escapes these characters,
// and a consumer needs the value as the pack states it.
func textSafe(s string) string {
	if textSafeClean(s) {
		return s
	}

	var b strings.Builder
	marks := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if unicode.In(r, unicode.Mn, unicode.Me) {
			marks++
		} else {
			marks = 0
		}
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\\':
			b.WriteString(`\\`)
		case r == ' ' && inSpaceRun(s, i):
			b.WriteString(`\x20`)
		case marks > maxCombiningMarks:
			fmt.Fprintf(&b, `\u%04x`, r)
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

// maxCombiningMarks is how many combining marks one letter keeps. Two cover
// ordinary text, such as Vietnamese letters with two diacritics.
const maxCombiningMarks = 2

// textSafeClean reports whether textSafe would return s as it is.
func textSafeClean(s string) bool {
	marks := 0
	for i, r := range s {
		if r == '\\' || r == utf8.RuneError || !textSafeRune(r) || (r == ' ' && inSpaceRun(s, i)) {
			return false
		}
		if unicode.In(r, unicode.Mn, unicode.Me) {
			if marks++; marks > maxCombiningMarks {
				return false
			}
		} else {
			marks = 0
		}
	}
	return true
}

// inSpaceRun reports whether the ASCII space at s[i] is part of a run of three
// or more.
func inSpaceRun(s string, i int) bool {
	start, end := i, i+1
	for start > 0 && s[start-1] == ' ' {
		start--
	}
	for end < len(s) && s[end] == ' ' {
		end++
	}
	return end-start >= 3
}

// blankRunes print as empty space although Unicode counts them as letters or
// symbols: the Hangul fillers and the blank Braille pattern.
var blankRunes = []rune{'\u115f', '\u1160', '\u3164', '\uffa0', '\u2800'}

// textSafeRune reports whether r prints as itself and shows: a graphic
// character that is not blank, or the ASCII space. unicode.IsPrint excludes
// control (Cc) and format (Cf) characters and the line and paragraph
// separators, which are the ones that move the cursor, reorder text or hide
// it. Every space separator but the ASCII space, and the blankRunes, print as
// nothing visible and are escaped.
func textSafeRune(r rune) bool {
	if r == utf8.RuneError {
		return false
	}
	if r == ' ' {
		return true
	}
	if unicode.Is(unicode.Zs, r) || slices.Contains(blankRunes, r) {
		return false
	}
	return unicode.IsPrint(r)
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
