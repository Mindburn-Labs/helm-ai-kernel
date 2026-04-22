package kernel

import (
	"encoding/json"
	"testing"
)

// FuzzCSNFTransform tests the CSNF transformer with random inputs.
// Run: go test -fuzz=FuzzCSNFTransform -fuzztime=30s ./core/pkg/kernel/
func FuzzCSNFTransform(f *testing.F) {
	// Seed corpus with known edge cases
	f.Add(`{"name": "test", "value": 42}`)
	f.Add(`{"arr": [3, 1, 2], "nested": {"a": "b"}}`)
	f.Add(`{"unicode": "café ☕ 日本語"}`)
	f.Add(`{"empty": {}, "null": null, "bool": true}`)
	f.Add(`{"deep": {"level1": {"level2": {"level3": "value"}}}}`)
	f.Add(`[]`)
	f.Add(`null`)
	f.Add(`"string"`)
	f.Add(`12345`)
	f.Add(`{"special": "line\nbreak\ttab"}`)
	f.Add(`{"large_num": 9999999999999999}`)

	f.Fuzz(func(t *testing.T, input string) {
		// Parse JSON
		var v any
		if err := json.Unmarshal([]byte(input), &v); err != nil {
			// Invalid JSON is fine, skip
			return
		}

		transformer := NewCSNFTransformer()

		// Should not panic
		result, err := transformer.Transform(v)
		if err != nil {
			// Errors are expected for some inputs
			return
		}

		// If transformation succeeds, result should be re-transformable (idempotent)
		result2, err := transformer.Transform(result)
		if err != nil {
			t.Errorf("re-transform failed: %v", err)
			return
		}

		// Re-serialization should produce same output (idempotency check)
		json1, _ := json.Marshal(result)
		json2, _ := json.Marshal(result2)
		if string(json1) != string(json2) {
			t.Errorf("CSNF not idempotent: %s != %s", json1, json2)
		}
	})
}

// FuzzCSNFNormalizeJSON tests JSON normalization with random bytes.
func FuzzCSNFNormalizeJSON(f *testing.F) {
	// Seed with valid JSON
	f.Add([]byte(`{"a":1,"b":2}`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`"hello"`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"nested":{"deep":"value"}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		result, err := CSNFNormalizeJSON(data)
		if err != nil {
			// Errors are expected for invalid JSON
			return
		}

		// Result should be valid JSON
		var v any
		if err := json.Unmarshal(result, &v); err != nil {
			t.Errorf("result is not valid JSON: %v", err)
		}

		// Re-normalization should produce same result (idempotency)
		result2, err := CSNFNormalizeJSON(result)
		if err != nil {
			t.Errorf("re-normalization failed: %v", err)
			return
		}
		if string(result) != string(result2) {
			t.Errorf("CSNFNormalizeJSON not idempotent")
		}
	})
}

// FuzzValidateCSNFCompliance tests compliance validation with random inputs.
func FuzzValidateCSNFCompliance(f *testing.F) {
	f.Add(`{"valid": "test"}`)
	f.Add(`{"num": 123}`)
	f.Add(`null`)

	f.Fuzz(func(t *testing.T, input string) {
		var v any
		if err := json.Unmarshal([]byte(input), &v); err != nil {
			return
		}

		// Should not panic
		_ = ValidateCSNFCompliance(v)
	})
}
