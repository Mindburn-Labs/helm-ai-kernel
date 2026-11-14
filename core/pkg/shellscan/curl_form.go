package shellscan

import "strings"

// curlFormPaths extracts every local input from the supported -F grammar.
// Curl's tool_formparse.c interprets quotes inside argv, file lists after @,
// and headers files even on literal fields. Unsupported syntax is refused by
// curlEgress; a partial extraction must never authorize the command.
func curlFormPaths(value string) ([]string, bool) {
	_, rest, ok := strings.Cut(value, "=")
	if !ok || strings.HasPrefix(rest, "(") || rest == ")" {
		return nil, false
	}
	files := strings.HasPrefix(rest, "@")
	file := files || strings.HasPrefix(rest, "<")
	if file {
		rest = rest[1:]
	}
	var paths []string
	for {
		var word string
		word, rest, ok = curlFormWord(rest, files)
		if !ok {
			return paths, false
		}
		if file {
			paths = append(paths, word)
		}
		for strings.HasPrefix(rest, ";") {
			rest = strings.TrimLeft(rest[1:], curlFormSpace)
			name, value, found := strings.Cut(rest, "=")
			if !found {
				return paths, false
			}
			readFile := false
			switch strings.ToLower(name) {
			case "headers":
				// The file marker must immediately follow '='. Spaces after
				// the marker, unlike spaces before it, are ignored by curl.
				readFile = strings.HasPrefix(value, "@") || strings.HasPrefix(value, "<")
				if readFile {
					value = value[1:]
				}
			case "type":
				// Curl scans content types without quote decoding. Refuse
				// quotes rather than interpreting their delimiters differently.
				end := strings.IndexAny(value, ";,")
				if end < 0 {
					end = len(value)
				}
				if strings.Contains(value[:end], `"`) {
					return paths, false
				}
			case "filename", "encoder":
				// These set metadata, not local input paths.
			default:
				return paths, false
			}
			word, rest, ok = curlFormWord(value, files)
			if !ok {
				return paths, false
			}
			if readFile {
				paths = append(paths, word)
			}
		}
		if rest == "" {
			for _, path := range paths {
				// The shared path guard accepts both slash conventions. A
				// literal POSIX backslash could therefore resolve differently;
				// refuse it until that filesystem spelling is supported.
				if strings.Contains(path, `\`) {
					return paths, false
				}
			}
			return paths, true
		}
		if !files || rest[0] != ',' {
			return paths, false
		}
		rest = rest[1:]
	}
}

// Curl uses ASCII whitespace for unquoted fields; quoted whitespace belongs
// to the filename. Only backslash and double quote are escaped inside quotes.
const curlFormSpace = " \t\r\n\v\f"

func curlFormWord(value string, comma bool) (string, string, bool) {
	value = strings.TrimLeft(value, curlFormSpace)
	delimiter := func(b byte) bool { return b == ';' || (comma && b == ',') }
	if !strings.HasPrefix(value, `"`) {
		end := 0
		for end < len(value) && !delimiter(value[end]) {
			end++
		}
		return strings.TrimRight(value[:end], curlFormSpace), value[end:], true
	}
	var word strings.Builder
	for i := 1; i < len(value); i++ {
		switch value[i] {
		case '\\':
			if i+1 < len(value) && (value[i+1] == '\\' || value[i+1] == '"') {
				i++
			}
		case '"':
			rest := strings.TrimLeft(value[i+1:], curlFormSpace)
			// Curl tolerates trailing junk and unterminated quotes; we do
			// not authorize that ambiguous subset of its grammar.
			if rest != "" && !delimiter(rest[0]) {
				return "", "", false
			}
			return word.String(), rest, true
		}
		word.WriteByte(value[i])
	}
	return "", "", false
}
