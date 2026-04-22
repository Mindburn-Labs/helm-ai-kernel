package canonicalize

import (
	"encoding/json"
	"testing"
)

func TestJCS_Sorting(t *testing.T) {
	// Map with unsorted keys
	input := map[string]interface{}{
		"c": 3,
		"a": 1,
		"b": 2,
	}

	// Expected: {"a":1,"b":2,"c":3}
	expected := `{"a":1,"b":2,"c":3}`

	b, err := JCS(input)
	if err != nil {
		t.Fatalf("JCS failed: %v", err)
	}

	if string(b) != expected {
		t.Errorf("Expected %s, got %s", expected, string(b))
	}
}

func TestJCS_RecursiveSorting(t *testing.T) {
	// Nested map
	input := map[string]interface{}{
		"z": map[string]interface{}{
			"y": "foo",
			"x": "bar",
		},
		"a": 1,
	}

	// Expected keys sorted at valid levels: {"a":1,"z":{"x":"bar","y":"foo"}}
	expected := `{"a":1,"z":{"x":"bar","y":"foo"}}`

	b, err := JCS(input)
	if err != nil {
		t.Fatalf("JCS failed: %v", err)
	}

	if string(b) != expected {
		t.Errorf("Expected %s, got %s", expected, string(b))
	}
}

func TestJCS_NoHTMLEscaping(t *testing.T) {
	// String with HTML characters
	input := map[string]string{
		"html": "<script>alert('xss')</script> &",
	}

	// Standard encoding/json produces: {"html":"\u003cscript\u003ealert('xss')\u003c/script\u003e \u0026"}
	// RFC 8785 requires: {"html":"<script>alert('xss')</script> &"}
	expected := `{"html":"<script>alert('xss')</script> &"}`

	b, err := JCS(input)
	if err != nil {
		t.Fatalf("JCS failed: %v", err)
	}

	if string(b) != expected {
		t.Errorf("Expected %s, got %s", expected, string(b))
	}
}

func TestCanonicalHash_Stability(t *testing.T) {
	// Two inputs that are semantically identical but constructed differently
	// 1. Map literal
	v1 := map[string]interface{}{"a": 1, "b": 2}

	// 2. Struct converted to map via JSON intermediate
	type S struct {
		B int `json:"b"`
		A int `json:"a"`
	}
	v2 := S{A: 1, B: 2}

	h1, err := CanonicalHash(v1)
	if err != nil {
		t.Fatal(err)
	}

	h2, err := CanonicalHash(v2)
	if err != nil {
		t.Fatal(err)
	}

	if h1 != h2 {
		t.Errorf("Hash mismatch for semantically identical inputs: %s != %s", h1, h2)
	}
}

func TestJCS_NumberTypes(t *testing.T) {
	// Ensure json.Number is respected
	input := map[string]interface{}{
		"num": json.Number("123.456"),
	}
	expected := `{"num":123.456}`

	b, err := JCS(input)
	if err != nil {
		t.Fatal(err)
	}

	if string(b) != expected {
		t.Errorf("Expected %s, got %s", expected, string(b))
	}
}

func TestJCSString_IsReachable(t *testing.T) {
	s, err := JCSString(map[string]int{"b": 2, "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	if s == "" {
		t.Fatal("expected non-empty string")
	}
}
