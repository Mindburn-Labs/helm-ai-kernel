// Package canonicalize provides RFC 8785 (JSON Canonicalization Scheme) compliant
// serialization for deterministic hashing of HELM artifacts.
package canonicalize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// JCS returns the RFC 8785 canonical JSON representation of v.
//
// Key features:
// 1. Map keys are sorted lexicographically by UTF-8 bytes.
// 2. HTML escaping is DISABLED (unlike standard json.Marshal).
// 3. Numbers are preserved exactly if passed as json.Number or string, otherwise standard formatting.
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
		if err := enc.Encode(t); err != nil {
			return nil, err
		}
		// json.Encoder adds a newline, we must trim it
		return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
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
		sort.Strings(keys)

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
