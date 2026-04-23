package kernel

import (
	"encoding/json"
	"testing"
)

//nolint:gocognit // test complexity is acceptable
func TestCSNFTransformer(t *testing.T) {
	t.Run("Transform string NFC normalization", func(t *testing.T) {
		transformer := NewCSNFTransformer()

		// Test NFC normalization (é as e + combining acute vs precomposed)
		input := "caf\u0065\u0301" // e + combining acute
		result, err := transformer.Transform(input)
		if err != nil {
			t.Fatalf("Transform failed: %v", err)
		}

		// Should be NFC normalized
		expected := "café" // precomposed
		if result != expected {
			t.Errorf("Expected NFC normalized %q, got %q", expected, result)
		}
	})

	t.Run("Transform integer", func(t *testing.T) {
		transformer := NewCSNFTransformer()

		result, err := transformer.Transform(float64(42))
		if err != nil {
			t.Fatalf("Transform failed: %v", err)
		}

		// Should be integer
		if _, ok := result.(int64); !ok {
			t.Errorf("Expected int64, got %T", result)
		}
	})

	t.Run("Transform rejects floats", func(t *testing.T) {
		transformer := NewCSNFTransformer()

		_, err := transformer.Transform(3.14159)
		if err == nil {
			t.Error("Expected error for float value")
		}
	})

	t.Run("Transform nested object", func(t *testing.T) {
		transformer := NewCSNFTransformer()

		input := map[string]any{
			"name":  "test",
			"count": float64(100),
			"nested": map[string]any{
				"value": float64(42),
			},
		}

		result, err := transformer.Transform(input)
		if err != nil {
			t.Fatalf("Transform failed: %v", err)
		}

		obj, ok := result.(map[string]any)
		if !ok {
			t.Fatalf("Expected map, got %T", result)
		}

		nested, ok := obj["nested"].(map[string]any)
		if !ok {
			t.Fatalf("Expected nested map, got %T", obj["nested"])
		}

		if _, ok := nested["value"].(int64); !ok {
			t.Errorf("Expected int64 in nested, got %T", nested["value"])
		}
	})

	t.Run("Transform array ORDERED", func(t *testing.T) {
		transformer := NewCSNFTransformer().
			WithArrayMeta("/items", CSNFArrayMeta{Kind: CSNFArrayKindOrdered})

		input := map[string]any{
			"items": []any{float64(3), float64(1), float64(2)},
		}

		result, err := transformer.Transform(input)
		if err != nil {
			t.Fatalf("Transform failed: %v", err)
		}

		obj := result.(map[string]any)
		items := obj["items"].([]any)

		// ORDERED should preserve order
		if items[0].(int64) != 3 || items[1].(int64) != 1 || items[2].(int64) != 2 {
			t.Error("ORDERED array should preserve element order")
		}
	})

	t.Run("Transform array SET", func(t *testing.T) {
		transformer := NewCSNFTransformer().
			WithArrayMeta("/items", CSNFArrayMeta{Kind: CSNFArrayKindSet})

		input := map[string]any{
			"items": []any{float64(3), float64(1), float64(2)},
		}

		result, err := transformer.Transform(input)
		if err != nil {
			t.Fatalf("Transform failed: %v", err)
		}

		obj := result.(map[string]any)
		items := obj["items"].([]any)

		// SET should sort elements
		if items[0].(int64) != 1 || items[1].(int64) != 2 || items[2].(int64) != 3 {
			t.Errorf("SET array should be sorted, got %v", items)
		}
	})

	t.Run("Transform array SET with sort key", func(t *testing.T) {
		transformer := NewCSNFTransformer().
			WithArrayMeta("/users", CSNFArrayMeta{
				Kind:    CSNFArrayKindSet,
				SortKey: "id",
			})

		input := map[string]any{
			"users": []any{
				map[string]any{"id": float64(3), "name": "charlie"},
				map[string]any{"id": float64(1), "name": "alice"},
				map[string]any{"id": float64(2), "name": "bob"},
			},
		}

		result, err := transformer.Transform(input)
		if err != nil {
			t.Fatalf("Transform failed: %v", err)
		}

		obj := result.(map[string]any)
		users := obj["users"].([]any)

		// Should be sorted by id
		first := users[0].(map[string]any)
		if first["name"] != "alice" {
			t.Errorf("First user should be alice, got %v", first["name"])
		}
	})

	t.Run("Transform array SET unique", func(t *testing.T) {
		transformer := NewCSNFTransformer().
			WithArrayMeta("/tags", CSNFArrayMeta{
				Kind:   CSNFArrayKindSet,
				Unique: true,
			})

		input := map[string]any{
			"tags": []any{"a", "b", "a", "c", "b"},
		}

		result, err := transformer.Transform(input)
		if err != nil {
			t.Fatalf("Transform failed: %v", err)
		}

		obj := result.(map[string]any)
		tags := obj["tags"].([]any)

		if len(tags) != 3 {
			t.Errorf("Expected 3 unique tags, got %d: %v", len(tags), tags)
		}
	})
}

func TestCSNFNormalize(t *testing.T) {
	input := map[string]any{
		"name": "test",
		"val":  float64(42),
	}

	result, err := CSNFNormalize(input)
	if err != nil {
		t.Fatalf("CSNFNormalize failed: %v", err)
	}

	obj := result.(map[string]any)
	if _, ok := obj["val"].(int64); !ok {
		t.Errorf("Expected int64, got %T", obj["val"])
	}
}

func TestCSNFNormalizeJSON(t *testing.T) {
	input := []byte(`{"name":"test","count":42,"nested":{"value":100}}`)

	result, err := CSNFNormalizeJSON(input)
	if err != nil {
		t.Fatalf("CSNFNormalizeJSON failed: %v", err)
	}

	// Should produce valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("Result is not valid JSON: %v", err)
	}
}

func TestValidateCSNFCompliance(t *testing.T) {
	t.Run("Valid simple object", func(t *testing.T) {
		input := map[string]any{
			"name": "test",
			"val":  int64(42),
		}

		issues := ValidateCSNFCompliance(input)
		if len(issues) != 0 {
			t.Errorf("Expected no issues, got: %v", issues)
		}
	})

	t.Run("Float violation", func(t *testing.T) {
		input := map[string]any{
			"price": 3.14,
		}

		issues := ValidateCSNFCompliance(input)
		if len(issues) == 0 {
			t.Error("Expected float violation to be reported")
		}
	})
}
