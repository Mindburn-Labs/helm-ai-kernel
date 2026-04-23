package kernel

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCSNFStringNormalization verifies NFC Unicode normalization.
func TestCSNFStringNormalization(t *testing.T) {
	transformer := NewCSNFTransformer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already NFC",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "NFD to NFC (composed)",
			input:    "cafe\u0301", // café with combining acute
			expected: "café",       // composed form
		},
		{
			name:     "mixed combining marks",
			input:    "n\u0303", // ñ with combining tilde
			expected: "ñ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := transformer.Transform(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.expected, result)
		})
	}
}

// TestCSNFIntegerOnlyNumbers verifies fractional number rejection.
func TestCSNFIntegerOnlyNumbers(t *testing.T) {
	transformer := NewCSNFTransformer()

	t.Run("integer allowed", func(t *testing.T) {
		result, err := transformer.Transform(float64(42))
		require.NoError(t, err)
		require.Equal(t, int64(42), result)
	})

	t.Run("zero allowed", func(t *testing.T) {
		result, err := transformer.Transform(float64(0))
		require.NoError(t, err)
		require.Equal(t, int64(0), result)
	})

	t.Run("negative integer allowed", func(t *testing.T) {
		result, err := transformer.Transform(float64(-100))
		require.NoError(t, err)
		require.Equal(t, int64(-100), result)
	})

	t.Run("fractional rejected", func(t *testing.T) {
		_, err := transformer.Transform(float64(3.14))
		require.Error(t, err)
		require.Contains(t, err.Error(), "fractional numbers not allowed")
	})

	t.Run("small fractional rejected", func(t *testing.T) {
		_, err := transformer.Transform(float64(0.001))
		require.Error(t, err)
		require.Contains(t, err.Error(), "fractional numbers not allowed")
	})
}

// TestCSNFArraySorting verifies SET array deterministic sorting.
func TestCSNFArraySorting(t *testing.T) {
	t.Run("SET array sorted by sort key", func(t *testing.T) {
		transformer := NewCSNFTransformer().
			WithArrayMeta("/items", CSNFArrayMeta{
				Kind:    CSNFArrayKindSet,
				SortKey: "/id",
			})

		input := map[string]any{
			"items": []any{
				map[string]any{"id": "c", "value": 3},
				map[string]any{"id": "a", "value": 1},
				map[string]any{"id": "b", "value": 2},
			},
		}

		result, err := transformer.Transform(input)
		require.NoError(t, err)

		items := result.(map[string]any)["items"].([]any)
		require.Len(t, items, 3)
		require.Equal(t, "a", items[0].(map[string]any)["id"])
		require.Equal(t, "b", items[1].(map[string]any)["id"])
		require.Equal(t, "c", items[2].(map[string]any)["id"])
	})

	t.Run("SET array with integer sort key", func(t *testing.T) {
		transformer := NewCSNFTransformer().
			WithArrayMeta("/items", CSNFArrayMeta{
				Kind:    CSNFArrayKindSet,
				SortKey: "/priority",
			})

		input := map[string]any{
			"items": []any{
				map[string]any{"priority": float64(10), "name": "low"},
				map[string]any{"priority": float64(1), "name": "high"},
				map[string]any{"priority": float64(5), "name": "medium"},
			},
		}

		result, err := transformer.Transform(input)
		require.NoError(t, err)

		items := result.(map[string]any)["items"].([]any)
		require.Len(t, items, 3)
		require.Equal(t, int64(1), items[0].(map[string]any)["priority"])
		require.Equal(t, int64(5), items[1].(map[string]any)["priority"])
		require.Equal(t, int64(10), items[2].(map[string]any)["priority"])
	})

	t.Run("ORDERED array preserves order", func(t *testing.T) {
		transformer := NewCSNFTransformer().
			WithArrayMeta("/items", CSNFArrayMeta{
				Kind: CSNFArrayKindOrdered,
			})

		input := map[string]any{
			"items": []any{"c", "a", "b"},
		}

		result, err := transformer.Transform(input)
		require.NoError(t, err)

		items := result.(map[string]any)["items"].([]any)
		require.Equal(t, []any{"c", "a", "b"}, items)
	})

	t.Run("SET array with uniqueness", func(t *testing.T) {
		transformer := NewCSNFTransformer().
			WithArrayMeta("/tags", CSNFArrayMeta{
				Kind:   CSNFArrayKindSet,
				Unique: true,
			})

		input := map[string]any{
			"tags": []any{"b", "a", "b", "c", "a"},
		}

		result, err := transformer.Transform(input)
		require.NoError(t, err)

		tags := result.(map[string]any)["tags"].([]any)
		require.Len(t, tags, 3)
		require.Equal(t, "a", tags[0])
		require.Equal(t, "b", tags[1])
		require.Equal(t, "c", tags[2])
	})
}

// TestCSNFObjectNormalization verifies object recursion.
func TestCSNFObjectNormalization(t *testing.T) {
	transformer := NewCSNFTransformer()

	input := map[string]any{
		"name":  "cafe\u0301", // NFD form
		"count": float64(42),
		"nested": map[string]any{
			"value": float64(100),
		},
	}

	result, err := transformer.Transform(input)
	require.NoError(t, err)

	obj := result.(map[string]any)
	require.Equal(t, "café", obj["name"])
	require.Equal(t, int64(42), obj["count"])

	nested := obj["nested"].(map[string]any)
	require.Equal(t, int64(100), nested["value"])
}

// TestCSNFNullPreservation verifies null vs absent semantics.
func TestCSNFNullPreservation(t *testing.T) {
	transformer := NewCSNFTransformer()

	input := map[string]any{
		"present":     "value",
		"null_field":  nil,
		"zero_string": "",
	}

	result, err := transformer.Transform(input)
	require.NoError(t, err)

	obj := result.(map[string]any)
	require.Contains(t, obj, "null_field")
	require.Nil(t, obj["null_field"])
	require.Equal(t, "", obj["zero_string"])
}

// TestCSNFValidateCompliance verifies compliance checking.
func TestCSNFValidateCompliance(t *testing.T) {
	t.Run("compliant value", func(t *testing.T) {
		v := map[string]any{
			"name":  "test",
			"count": int64(42),
		}
		issues := ValidateCSNFCompliance(v)
		require.Empty(t, issues)
	})

	t.Run("non-compliant fractional", func(t *testing.T) {
		v := map[string]any{
			"value": 3.14,
		}
		issues := ValidateCSNFCompliance(v)
		require.Len(t, issues, 1)
		require.Contains(t, issues[0], "fractional")
	})
}

// TestCSNFDeterminism verifies identical outputs for equivalent inputs.
func TestCSNFDeterminism(t *testing.T) {
	transformer := NewCSNFTransformer().
		WithArrayMeta("/items", CSNFArrayMeta{
			Kind:    CSNFArrayKindSet,
			SortKey: "/id",
		})

	// Two inputs that should normalize to identical output
	input1 := map[string]any{
		"name": "cafe\u0301",
		"items": []any{
			map[string]any{"id": "b"},
			map[string]any{"id": "a"},
		},
	}

	input2 := map[string]any{
		"name": "café", // Already composed
		"items": []any{
			map[string]any{"id": "a"},
			map[string]any{"id": "b"},
		},
	}

	result1, err := transformer.Transform(input1)
	require.NoError(t, err)

	result2, err := transformer.Transform(input2)
	require.NoError(t, err)

	// Serialize and compare
	json1, _ := json.Marshal(result1)
	json2, _ := json.Marshal(result2)

	require.JSONEq(t, string(json1), string(json2))
}
