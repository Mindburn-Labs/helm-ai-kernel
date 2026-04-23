package manifest

import (
	"testing"
)

func TestValidateAndCanonicalizeToolArgs_StableHash(t *testing.T) {
	args1 := map[string]interface{}{"b": "world", "a": "hello"}
	args2 := map[string]interface{}{"a": "hello", "b": "world"}

	r1, err := ValidateAndCanonicalizeToolArgs(nil, args1)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := ValidateAndCanonicalizeToolArgs(nil, args2)
	if err != nil {
		t.Fatal(err)
	}

	if r1.ArgsHash != r2.ArgsHash {
		t.Errorf("hashes differ for equivalent args: %s vs %s", r1.ArgsHash, r2.ArgsHash)
	}

	// Canonical JSON must be sorted
	expected := `{"a":"hello","b":"world"}`
	if string(r1.CanonicalJSON) != expected {
		t.Errorf("canonical JSON = %s, want %s", r1.CanonicalJSON, expected)
	}
}

func TestValidateAndCanonicalizeToolArgs_MissingRequired(t *testing.T) {
	schema := &ToolArgSchema{
		Fields: map[string]FieldSpec{
			"tool_name": {Type: "string", Required: true},
			"params":    {Type: "object", Required: false},
		},
	}

	_, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{
		"params": map[string]interface{}{},
	})
	if err == nil {
		t.Fatal("expected error for missing required field")
	}
	tErr, ok := err.(*ToolArgError)
	if !ok {
		t.Fatalf("expected ToolArgError, got %T", err)
	}
	if tErr.Code != ErrToolArgsMissingRequired {
		t.Errorf("code = %s, want %s", tErr.Code, ErrToolArgsMissingRequired)
	}
}

func TestValidateAndCanonicalizeToolArgs_UnknownField(t *testing.T) {
	schema := &ToolArgSchema{
		Fields: map[string]FieldSpec{
			"name": {Type: "string", Required: true},
		},
	}

	_, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{
		"name":    "test",
		"unknown": "value",
	})
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
	tErr := err.(*ToolArgError)
	if tErr.Code != ErrToolArgsUnknownField {
		t.Errorf("code = %s, want %s", tErr.Code, ErrToolArgsUnknownField)
	}
}

func TestValidateAndCanonicalizeToolArgs_TypeMismatch(t *testing.T) {
	schema := &ToolArgSchema{
		Fields: map[string]FieldSpec{
			"count": {Type: "number", Required: true},
		},
	}

	_, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{
		"count": "not-a-number",
	})
	if err == nil {
		t.Fatal("expected error for type mismatch")
	}
	tErr := err.(*ToolArgError)
	if tErr.Code != ErrToolArgsTypeMismatch {
		t.Errorf("code = %s, want %s", tErr.Code, ErrToolArgsTypeMismatch)
	}
}

func TestValidateAndCanonicalizeToolArgs_AllowExtra(t *testing.T) {
	schema := &ToolArgSchema{
		Fields: map[string]FieldSpec{
			"name": {Type: "string", Required: true},
		},
		AllowExtra: true,
	}

	result, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{
		"name":  "test",
		"extra": "allowed",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ArgsHash == "" {
		t.Error("expected non-empty hash")
	}
}

func TestValidateAndCanonicalizeToolArgs_NoSchema(t *testing.T) {
	result, err := ValidateAndCanonicalizeToolArgs(nil, map[string]interface{}{
		"foo": "bar",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ArgsHash == "" {
		t.Error("expected non-empty hash")
	}
}
