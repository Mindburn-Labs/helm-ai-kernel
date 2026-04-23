package threatscan

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"golang.org/x/text/unicode/norm"
)

// ────────────────────────────────────────────────────────────────
// Unicode Normalization
// ────────────────────────────────────────────────────────────────

// Zero-width and invisible characters that should be flagged.
var zeroWidthChars = map[rune]string{
	'\u200B': "ZERO WIDTH SPACE",
	'\u200C': "ZERO WIDTH NON-JOINER",
	'\u200D': "ZERO WIDTH JOINER",
	'\u200E': "LEFT-TO-RIGHT MARK",
	'\u200F': "RIGHT-TO-LEFT MARK",
	'\u202A': "LEFT-TO-RIGHT EMBEDDING",
	'\u202B': "RIGHT-TO-LEFT EMBEDDING",
	'\u202C': "POP DIRECTIONAL FORMATTING",
	'\u202D': "LEFT-TO-RIGHT OVERRIDE",
	'\u202E': "RIGHT-TO-LEFT OVERRIDE",
	'\u2060': "WORD JOINER",
	'\u2061': "FUNCTION APPLICATION",
	'\u2062': "INVISIBLE TIMES",
	'\u2063': "INVISIBLE SEPARATOR",
	'\u2064': "INVISIBLE PLUS",
	'\uFEFF': "BYTE ORDER MARK",
	'\uFFF9': "INTERLINEAR ANNOTATION ANCHOR",
	'\uFFFA': "INTERLINEAR ANNOTATION SEPARATOR",
	'\uFFFB': "INTERLINEAR ANNOTATION TERMINATOR",
}

// Common homoglyph mappings (Latin look-alikes from Cyrillic, Greek, etc.)
var homoglyphs = map[rune]rune{
	'\u0410': 'A', // Cyrillic А → Latin A
	'\u0412': 'B', // Cyrillic В → Latin B
	'\u0421': 'C', // Cyrillic С → Latin C
	'\u0415': 'E', // Cyrillic Е → Latin E
	'\u041D': 'H', // Cyrillic Н → Latin H
	'\u041A': 'K', // Cyrillic К → Latin K
	'\u041C': 'M', // Cyrillic М → Latin M
	'\u041E': 'O', // Cyrillic О → Latin O
	'\u0420': 'P', // Cyrillic Р → Latin P
	'\u0422': 'T', // Cyrillic Т → Latin T
	'\u0425': 'X', // Cyrillic Х → Latin X
	'\u0430': 'a', // Cyrillic а → Latin a
	'\u0435': 'e', // Cyrillic е → Latin e
	'\u043E': 'o', // Cyrillic о → Latin o
	'\u0440': 'p', // Cyrillic р → Latin p
	'\u0441': 'c', // Cyrillic с → Latin c
	'\u0445': 'x', // Cyrillic х → Latin x
	'\u0443': 'y', // Cyrillic у → Latin y
	'\u0456': 'i', // Cyrillic і → Latin i
	'\u0391': 'A', // Greek Α → Latin A
	'\u0392': 'B', // Greek Β → Latin B
	'\u0395': 'E', // Greek Ε → Latin E
	'\u0397': 'H', // Greek Η → Latin H
	'\u0399': 'I', // Greek Ι → Latin I
	'\u039A': 'K', // Greek Κ → Latin K
	'\u039C': 'M', // Greek Μ → Latin M
	'\u039D': 'N', // Greek Ν → Latin N
	'\u039F': 'O', // Greek Ο → Latin O
	'\u03A1': 'P', // Greek Ρ → Latin P
	'\u03A4': 'T', // Greek Τ → Latin T
	'\u03A7': 'X', // Greek Χ → Latin X
	'\u03BF': 'o', // Greek ο → Latin o
}

// normalizeInput performs NFKC normalization, strips zero-width/invisible
// characters, and detects homoglyphs. Returns normalized text and evidence.
func normalizeInput(input string) (string, *contracts.NormalizationEvidence) {
	origLen := utf8.RuneCountInString(input)

	// Step 1: NFKC normalization
	nfkc := norm.NFKC.String(input)

	// Step 2: Strip zero-width characters and count them
	var cleaned strings.Builder
	cleaned.Grow(len(nfkc))
	zeroWidthCount := 0
	var suspiciousChars []string

	for _, r := range nfkc {
		if name, isZW := zeroWidthChars[r]; isZW {
			zeroWidthCount++
			suspiciousChars = append(suspiciousChars, name)
			continue
		}
		// Strip other control characters (except standard whitespace)
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			zeroWidthCount++
			continue
		}
		cleaned.WriteRune(r)
	}

	result := cleaned.String()

	// Step 3: Detect homoglyphs
	homoglyphCount := 0
	for _, r := range result {
		if _, isHomo := homoglyphs[r]; isHomo {
			homoglyphCount++
		}
	}

	normalizedLen := utf8.RuneCountInString(result)

	evidence := &contracts.NormalizationEvidence{
		OriginalLength:    origLen,
		NormalizedLength:  normalizedLen,
		LengthDelta:       origLen - normalizedLen,
		ZeroWidthsRemoved: zeroWidthCount,
		HomoglyphsFound:   homoglyphCount,
		NFKCApplied:       true,
		SuspiciousChars:   suspiciousChars,
	}

	return result, evidence
}
