package kernel

import (
	"testing"
)

func TestValidateDecimalString(t *testing.T) {
	valid := []string{"0", "123", "-456", "0.5", "-0.5", "123.456"}
	for _, s := range valid {
		if err := ValidateDecimalString(s); err != nil {
			t.Errorf("ValidateDecimalString(%q) should pass: %v", s, err)
		}
	}

	invalid := []string{"", "abc", "00", "01", ".5", "5.", "1.2.3"}
	for _, s := range invalid {
		if err := ValidateDecimalString(s); err == nil {
			t.Errorf("ValidateDecimalString(%q) should fail", s)
		}
	}
}

func TestValidateTimestamp(t *testing.T) {
	valid := []string{
		"2024-01-15T10:30:00Z",
		"2024-01-15T10:30:00+00:00",
		"2024-01-15T10:30:00.123Z",
		"2024-01-15T10:30:00.123456789Z",
	}
	for _, s := range valid {
		if err := ValidateTimestamp(s); err != nil {
			t.Errorf("ValidateTimestamp(%q) should pass: %v", s, err)
		}
	}

	invalid := []string{
		"not-a-timestamp",
		"2024-01-15",
		"10:30:00",
		"2024/01/15T10:30:00Z",
	}
	for _, s := range invalid {
		if err := ValidateTimestamp(s); err == nil {
			t.Errorf("ValidateTimestamp(%q) should fail", s)
		}
	}
}

func TestNormalizeTimestamp(t *testing.T) {
	t.Run("Valid timestamps", func(t *testing.T) {
		inputs := []string{
			"2024-01-15T10:30:00Z",
			"2024-01-15T10:30:00+00:00",
			"2024-01-15T12:30:00+02:00",
		}
		for _, input := range inputs {
			result, err := NormalizeTimestamp(input)
			if err != nil {
				t.Errorf("NormalizeTimestamp(%q) failed: %v", input, err)
			}
			t.Logf("NormalizeTimestamp(%q) = %q", input, result)
		}
	})

	t.Run("Invalid timestamp", func(t *testing.T) {
		_, err := NormalizeTimestamp("invalid")
		if err == nil {
			t.Error("Expected error for invalid timestamp")
		}
	})

	t.Run("RFC3339 vs RFC3339Nano", func(t *testing.T) {
		// Standard format
		result1, _ := NormalizeTimestamp("2024-01-15T10:30:00Z")
		// Nano format
		result2, _ := NormalizeTimestamp("2024-01-15T10:30:00.123456789Z")

		t.Logf("Standard: %s, Nano: %s", result1, result2)
	})
}

func TestStripNulls(t *testing.T) {
	t.Run("Simple null stripping", func(t *testing.T) {
		obj := map[string]any{
			"name":  "Alice",
			"empty": nil,
			"age":   int64(30),
		}

		result := StripNulls(obj)
		if _, exists := result["empty"]; exists {
			t.Error("Null field should be stripped")
		}
		if result["name"] != "Alice" {
			t.Error("Non-null field should be preserved")
		}
	})

	t.Run("Nested null stripping", func(t *testing.T) {
		obj := map[string]any{
			"user": map[string]any{
				"name":  "Bob",
				"email": nil,
			},
		}

		result := StripNulls(obj)
		user := result["user"].(map[string]any)
		if _, exists := user["email"]; exists {
			t.Error("Nested null should be stripped")
		}
		if user["name"] != "Bob" {
			t.Error("Nested non-null should be preserved")
		}
	})

	t.Run("Array with nulls", func(t *testing.T) {
		obj := map[string]any{
			"items": []any{"a", nil, "b"},
		}

		result := StripNulls(obj)
		items := result["items"].([]any)
		// Arrays preserve nulls
		if len(items) != 3 {
			t.Errorf("Array length = %d, want 3", len(items))
		}
	})
}

func TestStripNullsWithSchema(t *testing.T) {
	t.Run("With nil schema", func(t *testing.T) {
		obj := map[string]any{
			"name":  "Alice",
			"empty": nil,
		}

		result := StripNullsWithSchema(obj, nil)
		if _, exists := result["empty"]; exists {
			t.Error("Null should be stripped without schema")
		}
	})

	t.Run("With nullable field in schema", func(t *testing.T) {
		obj := map[string]any{
			"name":     "Alice",
			"optional": nil,
		}

		schema := &CSNFSchema{
			Fields: map[string]CSNFSchemaField{
				"optional": {Nullable: true},
			},
		}

		result := StripNullsWithSchema(obj, schema)
		if _, exists := result["optional"]; !exists {
			t.Error("Nullable null should be preserved")
		}
	})

	t.Run("With non-nullable field in schema", func(t *testing.T) {
		obj := map[string]any{
			"name":     "Alice",
			"required": nil,
		}

		schema := &CSNFSchema{
			Fields: map[string]CSNFSchemaField{
				"required": {Nullable: false},
			},
		}

		result := StripNullsWithSchema(obj, schema)
		if _, exists := result["required"]; exists {
			t.Error("Non-nullable null should be stripped")
		}
	})

	t.Run("Nested objects", func(t *testing.T) {
		obj := map[string]any{
			"user": map[string]any{
				"name":  "Bob",
				"email": nil,
			},
		}

		schema := &CSNFSchema{Fields: map[string]CSNFSchemaField{}}

		result := StripNullsWithSchema(obj, schema)
		user := result["user"].(map[string]any)
		if _, exists := user["email"]; exists {
			t.Error("Nested null should be stripped")
		}
	})

	t.Run("Arrays", func(t *testing.T) {
		obj := map[string]any{
			"items": []any{"a", nil, "b"},
		}

		schema := &CSNFSchema{Fields: map[string]CSNFSchemaField{}}

		result := StripNullsWithSchema(obj, schema)
		items := result["items"].([]any)
		if len(items) != 3 {
			t.Errorf("Array length = %d, want 3", len(items))
		}
	})
}

func TestStripNullsFromArray(t *testing.T) {
	t.Run("Simple array", func(t *testing.T) {
		arr := []any{"a", nil, "b"}
		result := stripNullsFromArray(arr)
		if len(result) != 3 {
			t.Errorf("Length = %d, want 3", len(result))
		}
	})

	t.Run("Nested objects in array", func(t *testing.T) {
		arr := []any{
			map[string]any{"name": "Alice", "age": nil},
			map[string]any{"name": "Bob"},
		}
		result := stripNullsFromArray(arr)
		first := result[0].(map[string]any)
		if _, exists := first["age"]; exists {
			t.Error("Nested null should be stripped")
		}
	})

	t.Run("Nested arrays", func(t *testing.T) {
		arr := []any{
			[]any{1, nil, 2},
		}
		result := stripNullsFromArray(arr)
		nested := result[0].([]any)
		if len(nested) != 3 {
			t.Errorf("Nested array length = %d, want 3", len(nested))
		}
	})
}

func TestValidateCSNFStrict(t *testing.T) {
	t.Run("Valid integer", func(t *testing.T) {
		result := ValidateCSNFStrict(int64(42), nil)
		if !result.Valid {
			t.Error("Integer should be valid")
		}
	})

	t.Run("Float that is integer", func(t *testing.T) {
		result := ValidateCSNFStrict(float64(42), nil)
		// Should produce warning but still valid
		t.Logf("Float as int: Valid=%v, Issues=%d", result.Valid, len(result.Issues))
	})

	t.Run("Fractional float", func(t *testing.T) {
		result := ValidateCSNFStrict(float64(3.14), nil)
		if result.Valid {
			t.Error("Fractional float should be invalid")
		}
	})

	t.Run("Non-NFC string", func(t *testing.T) {
		// e + combining acute accent (not precomposed)
		nonNFC := "e\u0301"
		result := ValidateCSNFStrict(nonNFC, nil)
		if result.Valid {
			t.Error("Non-NFC string should be invalid")
		}
	})

	t.Run("NFC string", func(t *testing.T) {
		nfc := "café"
		result := ValidateCSNFStrict(nfc, nil)
		if !result.Valid {
			t.Error("NFC string should be valid")
		}
	})

	t.Run("Nested object with invalid float", func(t *testing.T) {
		obj := map[string]any{
			"user": map[string]any{
				"score": float64(3.14),
			},
		}
		result := ValidateCSNFStrict(obj, nil)
		if result.Valid {
			t.Error("Nested float should be invalid")
		}
	})

	t.Run("Array with invalid float", func(t *testing.T) {
		arr := []any{int64(1), float64(2.5), int64(3)}
		result := ValidateCSNFStrict(arr, nil)
		if result.Valid {
			t.Error("Array with float should be invalid")
		}
	})
}

func TestIsNFCNormalized(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"hello", true},
		{"café", true},     // Precomposed
		{"e\u0301", false}, // Decomposed (e + combining accent)
		{"", true},
	}

	for _, tc := range tests {
		result := IsNFCNormalized(tc.input)
		if result != tc.expected {
			t.Errorf("IsNFCNormalized(%q) = %v, want %v", tc.input, result, tc.expected)
		}
	}
}
