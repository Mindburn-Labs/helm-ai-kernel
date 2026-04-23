package canonicalize

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name     string
		schemaID string
		input    interface{}
		expect   string // Expected SHA-256 digest
	}{
		{
			name:     "Simple String",
			schemaID: "text/plain",
			input:    "hello world",
			expect:   hashHelper("hello world"),
		},
		{
			name:     "JSON Object (Unordered Keys)",
			schemaID: "json/object",
			input: map[string]interface{}{
				"b": 2,
				"a": 1,
			},
			// Expect JCS canonicalization: {"a":1,"b":2}
			expect: hashHelper(`{"a":1,"b":2}`),
		},
		{
			name:     "JSON Nested Object",
			schemaID: "json/nested",
			input: map[string]interface{}{
				"x": map[string]interface{}{
					"z": 10,
					"y": 5,
				},
			},
			// Expect JCS: {"x":{"y":5,"z":10}}
			expect: hashHelper(`{"x":{"y":5,"z":10}}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifact, err := Canonicalize(tt.schemaID, tt.input)
			if err != nil {
				t.Fatalf("Canonicalize failed: %v", err)
			}

			if artifact.Digest != tt.expect {
				t.Errorf("Digest mismatch:\nGot:  %s\nWant: %s", artifact.Digest, tt.expect)
			}

			if artifact.SchemaID != tt.schemaID {
				t.Errorf("SchemaID mismatch: got %s, want %s", artifact.SchemaID, tt.schemaID)
			}
		})
	}
}

func hashHelper(s string) string {
	hash := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(hash[:])
}
