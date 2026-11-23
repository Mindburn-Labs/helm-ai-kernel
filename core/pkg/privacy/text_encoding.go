package privacy

import (
	"html"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

func canonicalizePercentEscapes(value string) (string, bool) {
	canonical := value
	for depth := 0; depth < maxUnicodeEscapeDepth; depth++ {
		next, changed := decodePercentEscapes(canonical)
		if !changed {
			return canonical, false
		}
		canonical = next
	}
	_, unresolved := decodePercentEscapes(canonical)
	return canonical, unresolved
}

func decodePercentEscapes(value string) (string, bool) {
	if !strings.Contains(value, "%") {
		return value, false
	}
	var builder strings.Builder
	builder.Grow(len(value))
	changed := false
	for index := 0; index < len(value); index++ {
		if value[index] == '%' && index+2 < len(value) {
			high, highOK := hexValue(value[index+1])
			low, lowOK := hexValue(value[index+2])
			if highOK && lowOK {
				builder.WriteByte(high<<4 | low)
				index += 2
				changed = true
				continue
			}
		}
		builder.WriteByte(value[index])
	}
	return builder.String(), changed
}

func hexValue(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func percentEscapeVariants(value string) []string {
	return []string{
		percentEscape(value, "@+%", false),
		percentEscape(value, "@.+%", false),
		percentEscape(value, "@+%", true),
		percentEscape(value, "@.+%", true),
		percentEscape(value, "", false),
		percentEscape(value, "", true),
	}
}

func percentEscape(value, selected string, lowerHex bool) string {
	upper := "0123456789ABCDEF"
	hex := upper
	if lowerHex {
		hex = "0123456789abcdef"
	}
	encodeAll := selected == ""
	var builder strings.Builder
	builder.Grow(len(value) * 3)
	for index := 0; index < len(value); index++ {
		char := value[index]
		if !encodeAll && !strings.ContainsRune(selected, rune(char)) {
			builder.WriteByte(char)
			continue
		}
		builder.WriteByte('%')
		builder.WriteByte(hex[char>>4])
		builder.WriteByte(hex[char&0x0f])
	}
	return builder.String()
}
func canonicalizeQuotedEscapes(value string) (string, bool) {
	canonical := value
	replacer := strings.NewReplacer(`\"`, `"`, `\'`, `'`)
	for depth := 0; depth < maxUnicodeEscapeDepth; depth++ {
		next := replacer.Replace(canonical)
		if next == canonical {
			return canonical, false
		}
		canonical = next
	}
	return canonical, strings.Contains(canonical, `\"`) || strings.Contains(canonical, `\'`)
}

func canonicalizeTextEncodings(value string) (string, bool) {
	canonical := value
	for depth := 0; depth <= maxUnicodeEscapeDepth; depth++ {
		next, unresolved := canonicalizeUnicode(canonical)
		if unresolved {
			return "", true
		}
		next, unresolved = canonicalizePercentEscapes(next)
		if unresolved {
			return "", true
		}
		next, unresolved = canonicalizeQuotedEscapes(next)
		if unresolved {
			return "", true
		}
		next = html.UnescapeString(next)
		next = norm.NFKC.String(next)
		if next == canonical {
			return canonical, false
		}
		if depth == maxUnicodeEscapeDepth {
			return "", true
		}
		canonical = next
	}
	return "", true
}

func unicodeEscapeVariant(value string, slashCount int) string {
	if slashCount < 1 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(value) * (slashCount + len("u0000")))
	slashes := strings.Repeat("\\", slashCount)
	const hex = "0123456789abcdef"
	for _, char := range value {
		if char > 0x7f {
			return ""
		}
		builder.WriteString(slashes)
		builder.WriteByte('u')
		builder.WriteByte('0')
		builder.WriteByte('0')
		builder.WriteByte(hex[byte(char)>>4])
		builder.WriteByte(hex[byte(char)&0x0f])
	}
	return builder.String()
}
func canonicalizeUnicode(value string) (string, bool) {
	canonical := value
	for depth := 0; depth < maxUnicodeEscapeDepth; depth++ {
		if next, changed := collapseUnicodeLayer(canonical); changed {
			canonical = next
			continue
		}
		if next, changed := decodeUnicodeLayer(canonical); changed {
			canonical = next
			continue
		}
		return canonical, false
	}
	_, collapsed := collapseUnicodeLayer(canonical)
	_, decoded := decodeUnicodeLayer(canonical)
	return canonical, collapsed || decoded
}

func collapseUnicodeLayer(value string) (string, bool) {
	var builder strings.Builder
	changed := false
	for i := 0; i < len(value); {
		if value[i] != '\\' {
			builder.WriteByte(value[i])
			i++
			continue
		}
		start := i
		for i < len(value) && value[i] == '\\' {
			i++
		}
		run := i - start
		if i+4 < len(value) && value[i] == 'u' && isHex4(value[i+1:i+5]) && run >= 2 {
			builder.WriteString(strings.Repeat("\\", run-1))
			builder.WriteString(value[i : i+5])
			i += 5
			changed = true
			continue
		}
		builder.WriteString(value[start:i])
	}
	return builder.String(), changed
}

func decodeUnicodeLayer(value string) (string, bool) {
	var builder strings.Builder
	changed := false
	for i := 0; i < len(value); {
		if i+5 >= len(value) || value[i] != '\\' || value[i+1] != 'u' || !isHex4(value[i+2:i+6]) {
			_, size := utf8.DecodeRuneInString(value[i:])
			if size == 0 {
				size = 1
			}
			builder.WriteString(value[i : i+size])
			i += size
			continue
		}
		code, _ := strconv.ParseUint(value[i+2:i+6], 16, 16)
		runeValue := rune(code)
		consumed := 6
		if utf16.IsSurrogate(runeValue) && runeValue >= 0xD800 && runeValue <= 0xDBFF && i+11 < len(value) && value[i+6] == '\\' && value[i+7] == 'u' && isHex4(value[i+8:i+12]) {
			low, _ := strconv.ParseUint(value[i+8:i+12], 16, 16)
			if low >= 0xDC00 && low <= 0xDFFF {
				runeValue = utf16.DecodeRune(runeValue, rune(low))
				consumed = 12
			}
		}
		if !utf8.ValidRune(runeValue) || (runeValue >= 0xD800 && runeValue <= 0xDFFF) {
			builder.WriteString(value[i : i+consumed])
			i += consumed
			continue
		}
		builder.WriteRune(runeValue)
		i += consumed
		changed = true
	}
	return builder.String(), changed
}

func isHex4(value string) bool {
	if len(value) != 4 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
			return false
		}
	}
	return true
}
