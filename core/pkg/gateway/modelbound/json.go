package modelbound

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

// Field is one member of a JSON object, in order, with its value untouched.
type Field struct {
	Key string
	Raw json.RawMessage
}

// ParseObject reads body as exactly one JSON object and returns its members
// in order. A repeated key is refused, and so is anything after the object:
// encoding/json would resolve a duplicate silently while a provider's parser
// may resolve it the other way, and what a gateway inspects must be what the
// provider executes.
func ParseObject(body []byte) ([]Field, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("the request body is not one JSON object")
	}
	var fields []Field
	seen := map[string]struct{}{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errors.New("the request body is not valid JSON")
		}
		key, _ := tok.(string)
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("the request repeats the key %q", key)
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, errors.New("the request body is not valid JSON")
		}
		fields = append(fields, Field{Key: key, Raw: raw})
	}
	if _, err := dec.Token(); err != nil {
		return nil, errors.New("the request body is not valid JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the request body has data after its JSON object")
	}
	return fields, nil
}

// Lookup returns the value of the member named key.
func Lookup(fields []Field, key string) (json.RawMessage, bool) {
	for _, f := range fields {
		if f.Key == key {
			return f.Raw, true
		}
	}
	return nil, false
}

// IsNull reports a JSON null, which every API treats as an absent member.
func IsNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// absent reports a member that is missing or null.
func absent(raw json.RawMessage) bool { return len(raw) == 0 || IsNull(raw) }

// CheckNoDuplicateKeys refuses a repeated key at any depth of raw.
func CheckNoDuplicateKeys(raw json.RawMessage) error {
	return WalkKeys(json.NewDecoder(bytes.NewReader(raw)), nil)
}

// WalkKeys visits decoded object keys without collapsing duplicates. A
// provider may resolve an ambiguous object differently, so every depth is
// checked before the request can authorize a call or determine its quote.
func WalkKeys(dec *json.Decoder, visit func(string)) error {
	tok, err := dec.Token()
	if err != nil {
		return errors.New("not valid JSON")
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]struct{}{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return errors.New("not valid JSON")
			}
			key, _ := keyTok.(string)
			if _, dup := keys[key]; dup {
				return fmt.Errorf("repeats the key %q", key)
			}
			keys[key] = struct{}{}
			if visit != nil {
				visit(key)
			}
			if err := WalkKeys(dec, visit); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := WalkKeys(dec, visit); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return errors.New("not valid JSON")
	}
	return nil
}

// Object reads raw as a JSON object with exact keys, as a provider does: a
// struct decode would fold case and let {"TYPE": "function", "type": "mcp"}
// read as the harmless one while the provider reads the other.
func Object(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, false
	}
	return m, true
}

// String reads raw as a JSON string.
func String(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// IntOf reads a JSON integer, and refuses 1.5, 1e3 and the like. A value
// beyond int64 is reported as math.MaxInt64: it exceeds any clamp anyway.
func IntOf(raw json.RawMessage) (int64, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var n json.Number
	if dec.Decode(&n) != nil {
		return 0, false
	}
	text := n.String()
	if strings.ContainsAny(text, ".eE") {
		return 0, false
	}
	if v, err := n.Int64(); err == nil {
		return v, true
	}
	if strings.HasPrefix(text, "-") {
		return 0, false
	}
	return math.MaxInt64, true
}

// Rebuild writes fields as one JSON object with edit applied: a member named
// in edit takes the new value, and the members of edit not in fields are
// appended in the order of add. Every other member is copied as it came.
func Rebuild(fields []Field, edit map[string]json.RawMessage, add []string) []byte {
	var out bytes.Buffer
	out.WriteByte('{')
	first := true
	write := func(key string, raw json.RawMessage) {
		if !first {
			out.WriteByte(',')
		}
		first = false
		k, _ := json.Marshal(key)
		out.Write(k)
		out.WriteByte(':')
		out.Write(raw)
	}
	for _, f := range fields {
		if replacement, ok := edit[f.Key]; ok {
			write(f.Key, replacement)
		} else {
			write(f.Key, f.Raw)
		}
	}
	written := map[string]bool{}
	for _, key := range add {
		if _, exists := Lookup(fields, key); !exists && !written[key] {
			written[key] = true
			write(key, edit[key])
		}
	}
	out.WriteByte('}')
	return out.Bytes()
}
