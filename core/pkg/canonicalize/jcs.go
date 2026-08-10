// Package canonicalize provides RFC 8785 (JSON Canonicalization Scheme) compliant
// serialization for deterministic hashing of HELM artifacts.
// quantum_posture: canonical bytes bind hashes and signatures; this encoder does
// not itself choose a classical, hybrid, or post-quantum signing profile.
package canonicalize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxSafeInteger is 2^53-1, the largest integer an IEEE 754 double represents
// exactly. RFC 8785 Appendix B recommends confining true integers to
// ±MaxSafeInteger for maximum compliance with the ECMAScript JSON object.
const MaxSafeInteger = 9007199254740991

// JCS returns the RFC 8785 canonical JSON representation of v.
//
// Conformance and the one deviation, stated precisely (see
// protocols/specs/rfc/canonical-json-v1.md):
//
//  1. Object keys are sorted by UTF-16 code unit, per RFC 8785 Section 3.2.3.
//  2. Strings use the RFC 8785 Section 3.2.2.2 escape set: only U+0000..U+001F,
//     '"' and '\' are escaped. HTML escaping is DISABLED; U+2028/U+2029 and
//     U+007F are emitted as literal UTF-8.
//  3. DEVIATION from RFC 8785 Section 3.2.2.3: numbers are emitted as the JSON
//     literal produced by encoding/json for v (or, for a value decoded with
//     json.Number, the literal from the source document) rather than by the
//     ECMAScript Number-to-String algorithm. Over the interoperable subset
//     enforced by CheckInteroperableNumbers the two agree byte for byte;
//     outside it they do not. Signed HELM artifacts are confined to that
//     subset.
//
// JCS is lossy on invalid UTF-8: the encoding/json pre-marshal replaces
// ill-formed byte sequences with U+FFFD before this function sees them, so
// invalid input canonicalizes rather than failing. Callers that must reject
// ill-formed input have to validate before calling.
func JCS(v interface{}) ([]byte, error) {
	// Optimization: If v is a struct, standard json.Marshal might be needed to handle tags,
	// but it escapes HTML.
	// Strategy: Marshal to intermediate JSON (standard), then Decode to interface{}, then Recursive Marshal.
	// This ensures we respect json tags but override formatting/order.

	intermediate, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("jcs: pre-marshal failed: %w", err)
	}

	var generic interface{}
	decoder := json.NewDecoder(bytes.NewReader(intermediate))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		return nil, fmt.Errorf("jcs: intermediate decode failed: %w", err)
	}

	return marshalRecursive(generic)
}

// CanonicalHash returns the SHA-256 hex digest of the canonical JSON representation of v.
func CanonicalHash(v interface{}) (string, error) {
	b, err := JCS(v)
	if err != nil {
		return "", err
	}
	return HashBytes(b), nil
}

// HashBytes computes SHA-256 hash of raw bytes and returns hex string
func HashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// JCSString returns the JCS canonical form as a string
func JCSString(v interface{}) (string, error) {
	data, err := JCS(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func marshalRecursive(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // CRITICAL: RFC 8785 requires no HTML escaping

	switch t := v.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		if t {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case json.Number:
		return []byte(t.String()), nil
	case string:
		return marshalJCSString(t)
	case []interface{}:
		buf.Reset()
		buf.WriteByte('[')
		for i, elem := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			b, err := marshalRecursive(elem)
			if err != nil {
				return nil, err
			}
			buf.Write(b)
		}
		buf.WriteByte(']')
		return buf.Bytes(), nil
	case map[string]interface{}:
		buf.Reset()
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })

		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			// Encode Key (Strings must be quoted and escaped, but not HTML escaped)
			kb, err := marshalRecursive(k)
			if err != nil {
				return nil, err
			}
			buf.Write(kb)
			buf.WriteByte(':')

			// Encode Value
			vb, err := marshalRecursive(t[k])
			if err != nil {
				return nil, err
			}
			buf.Write(vb)
		}
		buf.WriteByte('}')
		return buf.Bytes(), nil
	default:
		// Fallback for unexpected types (like float64 if json.Number wasn't used)
		if err := enc.Encode(v); err != nil {
			return nil, err
		}
		return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
	}
}

// lessUTF16 reports whether a sorts before b when both are compared as arrays
// of UTF-16 code units treated as unsigned integers — the ordering RFC 8785
// Section 3.2.3 mandates for object property names.
//
// This differs from Go's native string comparison (UTF-8 byte order, which is
// code point order) for exactly one class of input: a supplementary-plane
// character (U+10000 and above, encoded as a UTF-16 surrogate pair beginning
// in U+D800..U+DBFF) sorts BEFORE any character in U+E000..U+FFFF, whereas in
// code point order it sorts after. Every other pair compares identically.
func lessUTF16(a, b string) bool {
	if a == b {
		return false
	}
	// Fast path: ASCII-only names — the overwhelming majority of HELM keys —
	// order identically under both rules, so skip the transcode.
	if isASCII(a) && isASCII(b) {
		return a < b
	}
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// ErrNonInteroperableNumber is returned by CheckInteroperableNumbers for a
// value whose JSON number literal is not guaranteed to be byte-identical
// between HELM canonical JSON and a strict RFC 8785 implementation.
var ErrNonInteroperableNumber = errors.New("canonicalize: number outside the interoperable subset")

// CheckInteroperableNumbers reports whether every number reachable from v is
// inside the subset on which HELM canonical JSON and RFC 8785 produce
// identical bytes: an integer in [-MaxSafeInteger, MaxSafeInteger] written
// without a sign on zero, without leading zeros, without a fraction and
// without an exponent.
//
// Numbers outside that subset are not rejected by JCS — JCS preserves the
// literal — so this is the gate every signed artifact and every published test
// vector MUST pass before its bytes are frozen. Without it, "1e2", "1.0",
// "-0" and 9007199254740993 canonicalize to literals a conformant RFC 8785
// implementation will not reproduce.
//
// The returned error names the JSON path of the first offending value.
func CheckInteroperableNumbers(v interface{}) error {
	intermediate, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("canonicalize: pre-marshal failed: %w", err)
	}
	var generic interface{}
	decoder := json.NewDecoder(bytes.NewReader(intermediate))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		return fmt.Errorf("canonicalize: intermediate decode failed: %w", err)
	}
	return checkNumbers(generic, "$")
}

// InteroperableJCS is JCS gated on CheckInteroperableNumbers. Use it to mint
// canonical bytes that a third-party RFC 8785 implementation reproduces.
func InteroperableJCS(v interface{}) ([]byte, error) {
	if err := CheckInteroperableNumbers(v); err != nil {
		return nil, err
	}
	return JCS(v)
}

func checkNumbers(v interface{}, path string) error {
	switch t := v.(type) {
	case json.Number:
		if !isInteroperableNumberLiteral(t.String()) {
			return fmt.Errorf("%w: %s is %q", ErrNonInteroperableNumber, path, t.String())
		}
		return nil
	case []interface{}:
		for i, elem := range t {
			if err := checkNumbers(elem, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		for _, k := range keys {
			if err := checkNumbers(t[k], path+"."+k); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

// isInteroperableNumberLiteral reports whether lit is a decimal integer in the
// IEEE 754 exactly-representable range, in the single spelling both HELM
// canonical JSON and the ECMAScript Number-to-String algorithm produce.
func isInteroperableNumberLiteral(lit string) bool {
	if lit == "" {
		return false
	}
	if strings.ContainsAny(lit, ".eE") {
		return false
	}
	body := lit
	if body[0] == '-' {
		body = body[1:]
		if body == "0" {
			return false // negative zero: RFC 8785 renders it "0"
		}
	}
	if body == "" {
		return false
	}
	if len(body) > 1 && body[0] == '0' {
		return false // leading zeros are not valid JSON anyway; reject defensively
	}
	for i := 0; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseInt(lit, 10, 64)
	if err != nil {
		return false // out of int64 range, so far outside the safe-integer range
	}
	return n >= -MaxSafeInteger && n <= MaxSafeInteger
}

// marshalJCSString implements the RFC 8785 string escape set directly. In
// particular, U+2028/U+2029 are emitted as UTF-8 literals. Post-processing
// encoding/json output would be unsafe because a literal `\\u2028` input can
// contain the same byte sequence as an encoder-generated escape.
func marshalJCSString(value string) ([]byte, error) {
	if !utf8.ValidString(value) {
		return nil, errors.New("jcs: strings must be valid UTF-8")
	}
	var buf bytes.Buffer
	buf.Grow(len(value) + 2)
	buf.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&buf, `\u%04x`, r)
				continue
			}
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
	return buf.Bytes(), nil
}
