package canonicalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestJCS_EmptyObject(t *testing.T) {
	b, err := JCS(map[string]any{})
	if err != nil || string(b) != "{}" {
		t.Fatalf("expected {}, got %s (err=%v)", b, err)
	}
}

func TestJCS_EmptyArray(t *testing.T) {
	b, err := JCS([]any{})
	if err != nil || string(b) != "[]" {
		t.Fatalf("expected [], got %s (err=%v)", b, err)
	}
}

func TestJCS_NullValue(t *testing.T) {
	b, err := JCS(map[string]any{"k": nil})
	if err != nil || string(b) != `{"k":null}` {
		t.Fatalf("expected null value, got %s", b)
	}
}

func TestJCS_BooleanTrue(t *testing.T) {
	b, _ := JCS(map[string]any{"v": true})
	if string(b) != `{"v":true}` {
		t.Fatalf("expected true, got %s", b)
	}
}

func TestJCS_BooleanFalse(t *testing.T) {
	b, _ := JCS(map[string]any{"v": false})
	if string(b) != `{"v":false}` {
		t.Fatalf("expected false, got %s", b)
	}
}

func TestJCS_Integer(t *testing.T) {
	b, _ := JCS(map[string]any{"n": 42})
	if string(b) != `{"n":42}` {
		t.Fatalf("expected 42, got %s", b)
	}
}

func TestJCS_NestedObjects(t *testing.T) {
	input := map[string]any{"b": map[string]any{"d": 1, "c": 2}, "a": 0}
	b, _ := JCS(input)
	if string(b) != `{"a":0,"b":{"c":2,"d":1}}` {
		t.Fatalf("nested sorting failed, got %s", b)
	}
}

func TestJCS_ArrayPreservesOrder(t *testing.T) {
	input := map[string]any{"arr": []any{3, 1, 2}}
	b, _ := JCS(input)
	if string(b) != `{"arr":[3,1,2]}` {
		t.Fatalf("array order should be preserved, got %s", b)
	}
}

func TestJCS_UnicodeString(t *testing.T) {
	input := map[string]any{"emoji": "\U0001F600", "jp": "\u3053\u3093\u306b\u3061\u306f"}
	b, err := JCS(input)
	if err != nil {
		t.Fatalf("unicode should not error: %v", err)
	}
	if !strings.Contains(string(b), "\U0001F600") {
		t.Fatal("emoji should be preserved in output")
	}
}

func TestJCS_HTMLCharsNotEscaped(t *testing.T) {
	input := map[string]any{"v": "<b>bold</b> & 'quote'"}
	b, _ := JCS(input)
	if strings.Contains(string(b), "\\u003c") {
		t.Fatal("HTML should not be escaped per RFC 8785")
	}
}

func TestJCS_Determinism_MapKeyOrder(t *testing.T) {
	a, _ := JCS(map[string]any{"z": 1, "a": 2, "m": 3})
	b, _ := JCS(map[string]any{"m": 3, "z": 1, "a": 2})
	if string(a) != string(b) {
		t.Fatal("different key insertion order should produce same output")
	}
}

func TestJCS_Determinism_MultipleCallsSameInput(t *testing.T) {
	input := map[string]any{"x": []any{1, "two", true, nil}}
	a, _ := JCS(input)
	b, _ := JCS(input)
	if string(a) != string(b) {
		t.Fatal("multiple calls with same input should be identical")
	}
}

func TestJCS_StructWithTags(t *testing.T) {
	type S struct {
		Beta  int `json:"beta"`
		Alpha int `json:"alpha"`
	}
	b, _ := JCS(S{Alpha: 1, Beta: 2})
	if string(b) != `{"alpha":1,"beta":2}` {
		t.Fatalf("struct json tags should be used, got %s", b)
	}
}

func TestCanonicalHash_NonEmpty(t *testing.T) {
	h, err := CanonicalHash(map[string]any{"a": 1})
	if err != nil || h == "" {
		t.Fatalf("hash should be non-empty, got %q (err=%v)", h, err)
	}
}

func TestCanonicalHash_Is64HexChars(t *testing.T) {
	h, _ := CanonicalHash(map[string]any{"test": true})
	if len(h) != 64 {
		t.Fatalf("SHA-256 hex should be 64 chars, got %d", len(h))
	}
}

func TestCanonicalHash_DeterministicAcrossRepresentations(t *testing.T) {
	h1, _ := CanonicalHash(map[string]any{"b": 2, "a": 1})
	h2, _ := CanonicalHash(map[string]any{"a": 1, "b": 2})
	if h1 != h2 {
		t.Fatalf("same data, different order should hash equal: %s vs %s", h1, h2)
	}
}

func TestCanonicalHash_DifferentDataDifferentHash(t *testing.T) {
	h1, _ := CanonicalHash(map[string]any{"a": 1})
	h2, _ := CanonicalHash(map[string]any{"a": 2})
	if h1 == h2 {
		t.Fatal("different data should produce different hashes")
	}
}

func TestHashBytes_KnownVector(t *testing.T) {
	// SHA-256 of empty string is well-known
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	got := HashBytes([]byte{})
	if got != expected {
		t.Fatalf("empty hash mismatch: got %s", got)
	}
}

func TestHashBytes_NonEmpty(t *testing.T) {
	h := sha256.Sum256([]byte("hello"))
	expected := hex.EncodeToString(h[:])
	got := HashBytes([]byte("hello"))
	if got != expected {
		t.Fatalf("hash mismatch: got %s, want %s", got, expected)
	}
}

func TestHashBytes_Deterministic(t *testing.T) {
	a := HashBytes([]byte("test"))
	b := HashBytes([]byte("test"))
	if a != b {
		t.Fatal("HashBytes should be deterministic")
	}
}

func TestJCS_JsonNumberPreserved(t *testing.T) {
	input := map[string]any{"n": json.Number("99.99")}
	b, _ := JCS(input)
	if string(b) != `{"n":99.99}` {
		t.Fatalf("json.Number should be preserved, got %s", b)
	}
}

func TestJCS_DeeplyNested(t *testing.T) {
	input := map[string]any{"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": 1}}}}
	b, err := JCS(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"a":{"b":{"c":{"d":1}}}}` {
		t.Fatalf("deeply nested failed, got %s", b)
	}
}

func TestJCSString_MatchesJCS(t *testing.T) {
	input := map[string]any{"x": 1}
	bytes, _ := JCS(input)
	str, _ := JCSString(input)
	if str != string(bytes) {
		t.Fatal("JCSString should match string(JCS())")
	}
}
