package csnf

import (
	"testing"
)

func TestCanonicalize_String_NFC(t *testing.T) {
	result, err := Canonicalize("hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "hello" {
		t.Errorf("expected 'hello', got %v", result)
	}
}

func TestCanonicalize_Int(t *testing.T) {
	result, err := Canonicalize(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != int64(42) {
		t.Errorf("expected int64(42), got %v (%T)", result, result)
	}
}

func TestCanonicalize_Bool(t *testing.T) {
	result, err := Canonicalize(true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != true {
		t.Errorf("expected true, got %v", result)
	}
}

func TestCanonicalize_Map_StripsNils(t *testing.T) {
	input := map[string]interface{}{
		"keep":   "value",
		"remove": nil,
	}
	result, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", result)
	}
	if _, exists := m["remove"]; exists {
		t.Error("expected nil values to be stripped")
	}
	if m["keep"] != "value" {
		t.Errorf("expected 'value', got %v", m["keep"])
	}
}

func TestCanonicalize_Slice(t *testing.T) {
	input := []interface{}{"a", "b", "c"}
	result, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	arr, ok := result.([]interface{})
	if !ok {
		t.Fatalf("expected slice, got %T", result)
	}
	if len(arr) != 3 {
		t.Errorf("expected 3 elements, got %d", len(arr))
	}
}

func TestCanonicalize_Float_Integer(t *testing.T) {
	result, err := Canonicalize(42.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != int64(42) {
		t.Errorf("expected int64(42), got %v (%T)", result, result)
	}
}

func TestCanonicalize_Float_Fractional_Rejected(t *testing.T) {
	_, err := Canonicalize(3.14)
	if err == nil {
		t.Error("expected error for fractional float")
	}
}

func TestCanonicalize_Nil(t *testing.T) {
	result, err := Canonicalize(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestHash_SimpleMap(t *testing.T) {
	input := map[string]interface{}{
		"name": "helm",
		"ver":  1,
	}
	hash, err := Hash(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars", len(hash))
	}
}

func TestHash_Deterministic(t *testing.T) {
	input := map[string]interface{}{
		"a": "1",
		"b": "2",
	}
	h1, _ := Hash(input)
	h2, _ := Hash(input)
	if h1 != h2 {
		t.Error("hash should be deterministic")
	}
}

func TestHash_Nil_Error(t *testing.T) {
	_, err := Hash(nil)
	if err == nil {
		t.Error("expected error for nil input")
	}
}

func TestHash_DifferentInputsDifferentHashes(t *testing.T) {
	h1, _ := Hash(map[string]interface{}{"k": "v1"})
	h2, _ := Hash(map[string]interface{}{"k": "v2"})
	if h1 == h2 {
		t.Error("different inputs should produce different hashes")
	}
}
