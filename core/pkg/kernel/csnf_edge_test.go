package kernel

import (
	"testing"
)

// Test extractSortKey edge cases
//
//nolint:gocognit // test complexity is acceptable
func TestExtractSortKey(t *testing.T) {
	transformer := NewCSNFTransformer()

	t.Run("Primitive element without sort key", func(t *testing.T) {
		val, err := transformer.extractSortKey("hello", "")
		if err != nil {
			t.Fatalf("extractSortKey failed: %v", err)
		}
		if val != "hello" {
			t.Errorf("Expected 'hello', got %v", val)
		}
	})

	t.Run("Integer element without sort key", func(t *testing.T) {
		val, err := transformer.extractSortKey(int64(42), "")
		if err != nil {
			t.Fatalf("extractSortKey failed: %v", err)
		}
		if val != int64(42) {
			t.Errorf("Expected 42, got %v", val)
		}
	})

	t.Run("Float element without sort key", func(t *testing.T) {
		val, err := transformer.extractSortKey(float64(3.14), "")
		if err != nil {
			t.Fatalf("extractSortKey failed: %v", err)
		}
		if val != float64(3.14) {
			t.Errorf("Expected 3.14, got %v", val)
		}
	})

	t.Run("Object element without sort key - fails", func(t *testing.T) {
		obj := map[string]any{"name": "test"}
		_, err := transformer.extractSortKey(obj, "")
		if err == nil {
			t.Error("Expected error for object without sort key")
		}
	})

	t.Run("Extract sort key from object", func(t *testing.T) {
		obj := map[string]any{"name": "Alice", "priority": int64(5)}
		val, err := transformer.extractSortKey(obj, "/priority")
		if err != nil {
			t.Fatalf("extractSortKey failed: %v", err)
		}
		if val != int64(5) {
			t.Errorf("Expected 5, got %v", val)
		}
	})

	t.Run("Extract nested sort key", func(t *testing.T) {
		obj := map[string]any{
			"meta": map[string]any{
				"id": "abc",
			},
		}
		val, err := transformer.extractSortKey(obj, "/meta/id")
		if err != nil {
			t.Fatalf("extractSortKey failed: %v", err)
		}
		if val != "abc" {
			t.Errorf("Expected 'abc', got %v", val)
		}
	})

	t.Run("Missing sort key field", func(t *testing.T) {
		obj := map[string]any{"name": "Alice"}
		_, err := transformer.extractSortKey(obj, "/nonexistent")
		if err == nil {
			t.Error("Expected error for missing sort key")
		}
	})

	t.Run("Sort key path traversal fails", func(t *testing.T) {
		obj := map[string]any{"name": "Alice"} // name is string, not object
		_, err := transformer.extractSortKey(obj, "/name/sub")
		if err == nil {
			t.Error("Expected error for path through non-object")
		}
	})

	t.Run("Float sort key converted to int", func(t *testing.T) {
		obj := map[string]any{"score": float64(100)}
		val, err := transformer.extractSortKey(obj, "/score")
		if err != nil {
			t.Fatalf("extractSortKey failed: %v", err)
		}
		if val != int64(100) {
			t.Errorf("Expected int64(100), got %v (%T)", val, val)
		}
	})

	t.Run("Fractional float sort key rejects", func(t *testing.T) {
		obj := map[string]any{"score": float64(3.14)}
		_, err := transformer.extractSortKey(obj, "/score")
		if err == nil {
			t.Error("Expected error for fractional float sort key")
		}
	})

	t.Run("Non-primitive sort key rejects", func(t *testing.T) {
		obj := map[string]any{"nested": map[string]any{"a": "b"}}
		_, err := transformer.extractSortKey(obj, "/nested")
		if err == nil {
			t.Error("Expected error for non-primitive sort key")
		}
	})
}

// Test toInt64 with all types
func TestToInt64(t *testing.T) {
	tests := []struct {
		input    any
		expected int64
	}{
		{int64(42), 42},
		{int(100), 100},
		{float64(3.9), 3}, // truncates
		{float64(0), 0},
		{"string", 0}, // unsupported type
		{nil, 0},
	}

	for _, tc := range tests {
		result := toInt64(tc.input)
		if result != tc.expected {
			t.Errorf("toInt64(%v) = %d, want %d", tc.input, result, tc.expected)
		}
	}
}

// Test compareSortKeys
func TestCompareSortKeys(t *testing.T) {
	tests := []struct {
		a, b     any
		expected int // -1, 0, or 1
	}{
		{"a", "b", -1},
		{"b", "a", 1},
		{"x", "x", 0},
		{int64(1), int64(2), -1},
		{int64(5), int64(3), 1},
		{int64(7), int64(7), 0},
		{int(10), int64(10), 0},
		{float64(1.5), float64(2.5), -1}, // converted to int64
	}

	for _, tc := range tests {
		result := compareSortKeys(tc.a, tc.b)
		if result != tc.expected {
			t.Errorf("compareSortKeys(%v, %v) = %d, want %d", tc.a, tc.b, result, tc.expected)
		}
	}
}

// Test CSNFNormalizeJSON
func TestCSNFNormalizeJSONEdgeCases(t *testing.T) {
	t.Run("Valid JSON with integer", func(t *testing.T) {
		input := []byte(`{"value":42}`)
		output, err := CSNFNormalizeJSON(input)
		if err != nil {
			t.Fatalf("CSNFNormalizeJSON failed: %v", err)
		}
		t.Logf("CSNFNormalizeJSON: %s", output)
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		input := []byte(`{invalid}`)
		_, err := CSNFNormalizeJSON(input)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Float that's integer", func(t *testing.T) {
		input := []byte(`{"value":42.0}`)
		output, err := CSNFNormalizeJSON(input)
		if err != nil {
			t.Fatalf("CSNFNormalizeJSON failed: %v", err)
		}
		t.Logf("CSNFNormalizeJSON float->int: %s", output)
	})

	t.Run("Nested objects", func(t *testing.T) {
		input := []byte(`{"user":{"name":"Alice","age":30}}`)
		output, err := CSNFNormalizeJSON(input)
		if err != nil {
			t.Fatalf("CSNFNormalizeJSON failed: %v", err)
		}
		t.Logf("CSNFNormalizeJSON nested: %s", output)
	})

	t.Run("Array", func(t *testing.T) {
		input := []byte(`{"items":["a","b","c"]}`)
		output, err := CSNFNormalizeJSON(input)
		if err != nil {
			t.Fatalf("CSNFNormalizeJSON failed: %v", err)
		}
		t.Logf("CSNFNormalizeJSON array: %s", output)
	})
}

// Test CSNFNormalize
func TestCSNFNormalizeEdgeCases(t *testing.T) {
	t.Run("String value", func(t *testing.T) {
		result, err := CSNFNormalize("hello")
		if err != nil {
			t.Fatalf("CSNFNormalize failed: %v", err)
		}
		if result != "hello" {
			t.Errorf("Expected 'hello', got %v", result)
		}
	})

	t.Run("Integer value", func(t *testing.T) {
		result, err := CSNFNormalize(int64(42))
		if err != nil {
			t.Fatalf("CSNFNormalize failed: %v", err)
		}
		if result != int64(42) {
			t.Errorf("Expected 42, got %v", result)
		}
	})

	t.Run("Float that's integer", func(t *testing.T) {
		result, err := CSNFNormalize(float64(10.0))
		if err != nil {
			t.Fatalf("CSNFNormalize failed: %v", err)
		}
		if result != int64(10) {
			t.Errorf("Expected int64(10), got %v (%T)", result, result)
		}
	})

	t.Run("Boolean", func(t *testing.T) {
		result, err := CSNFNormalize(true)
		if err != nil {
			t.Fatalf("CSNFNormalize failed: %v", err)
		}
		if result != true {
			t.Errorf("Expected true, got %v", result)
		}
	})

	t.Run("Null", func(t *testing.T) {
		result, err := CSNFNormalize(nil)
		if err != nil {
			t.Fatalf("CSNFNormalize failed: %v", err)
		}
		if result != nil {
			t.Errorf("Expected nil, got %v", result)
		}
	})
}

// Test hashElement
func TestHashElement(t *testing.T) {
	transformer := NewCSNFTransformer()

	t.Run("Same input same hash", func(t *testing.T) {
		elem := map[string]any{"name": "Alice"}
		hash1, _ := transformer.hashElement(elem)
		hash2, _ := transformer.hashElement(elem)
		if hash1 != hash2 {
			t.Error("Same element should have same hash")
		}
	})

	t.Run("Different input different hash", func(t *testing.T) {
		hash1, _ := transformer.hashElement("a")
		hash2, _ := transformer.hashElement("b")
		if hash1 == hash2 {
			t.Error("Different elements should have different hashes")
		}
	})
}

// Test deduplicateArray
func TestDeduplicateArray(t *testing.T) {
	transformer := NewCSNFTransformer()

	t.Run("Remove duplicates", func(t *testing.T) {
		arr := []any{"a", "b", "a", "c", "b"}
		result := transformer.deduplicateArray(arr)
		if len(result) != 3 {
			t.Errorf("Expected 3 unique elements, got %d", len(result))
		}
	})

	t.Run("Object duplicates", func(t *testing.T) {
		arr := []any{
			map[string]any{"id": int64(1)},
			map[string]any{"id": int64(2)},
			map[string]any{"id": int64(1)},
		}
		result := transformer.deduplicateArray(arr)
		if len(result) != 2 {
			t.Errorf("Expected 2 unique objects, got %d", len(result))
		}
	})

	t.Run("No duplicates", func(t *testing.T) {
		arr := []any{"a", "b", "c"}
		result := transformer.deduplicateArray(arr)
		if len(result) != 3 {
			t.Errorf("Expected 3 elements, got %d", len(result))
		}
	})
}
