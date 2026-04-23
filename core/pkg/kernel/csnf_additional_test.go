package kernel

import (
	"testing"
)

func TestValidateCSNFComplianceFractionalNumber(t *testing.T) {
	// Test fractional number detection
	issues := ValidateCSNFCompliance(3.14)
	if len(issues) == 0 {
		t.Error("Should report fractional number")
	}

	// Integer float is OK
	issues = ValidateCSNFCompliance(3.0)
	if len(issues) != 0 {
		t.Errorf("Integer float should be valid: %v", issues)
	}
}

func TestValidateCSNFComplianceNonNFCString(t *testing.T) {
	// NFC string is OK
	issues := ValidateCSNFCompliance("hello")
	if len(issues) != 0 {
		t.Errorf("NFC string should be valid: %v", issues)
	}

	// Test with composed Unicode that needs NFC
	// é as "e" + combining acute accent (non-NFC)
	nonNFC := "e\u0301" // This is e + combining acute, not NFC é
	issues = ValidateCSNFCompliance(nonNFC)
	if len(issues) == 0 {
		t.Error("Should report non-NFC string")
	}
}

func TestValidateCSNFComplianceNestedArray(t *testing.T) {
	data := []any{
		1.0,
		2.5,             // fractional
		[]any{3.0, 4.5}, // nested with fractional
	}
	issues := ValidateCSNFCompliance(data)
	if len(issues) < 2 {
		t.Errorf("Should report multiple fractional numbers, got %d issues", len(issues))
	}
}

func TestValidateCSNFComplianceNestedMap(t *testing.T) {
	data := map[string]any{
		"a": 1.0,
		"b": 2.5, // fractional
		"c": map[string]any{
			"d": 3.5, // nested fractional
		},
	}
	issues := ValidateCSNFCompliance(data)
	if len(issues) < 2 {
		t.Errorf("Should report multiple fractional numbers, got %d issues", len(issues))
	}
}

func TestCSNFTransformUnsupportedType(t *testing.T) {
	transformer := NewCSNFTransformer()

	// Complex types are unsupported
	type customType struct{}
	_, err := transformer.Transform(customType{})
	if err == nil {
		t.Error("Should error on unsupported type")
	}
}

func TestCSNFTransformReflectIntTypes(t *testing.T) {
	transformer := NewCSNFTransformer()

	// Test various int types
	var int8Val int8 = 42
	result, err := transformer.Transform(int8Val)
	if err != nil {
		t.Fatalf("Transform int8 error: %v", err)
	}
	if result != int64(42) {
		t.Errorf("Got %v, want 42", result)
	}

	// Uint
	var uint32Val uint32 = 100
	result, err = transformer.Transform(uint32Val)
	if err != nil {
		t.Fatalf("Transform uint32 error: %v", err)
	}
	if result != int64(100) {
		t.Errorf("Got %v, want 100", result)
	}
}

func TestCSNFTransformFloat32(t *testing.T) {
	transformer := NewCSNFTransformer()

	// Fractional float32 should error
	var floatVal float32 = 3.5
	_, err := transformer.Transform(floatVal)
	if err == nil {
		t.Error("Fractional float32 should error")
	}

	// Integer float32 should succeed
	var intFloat float32 = 3.0
	result, err := transformer.Transform(intFloat)
	if err != nil {
		t.Fatalf("Transform integer float32 error: %v", err)
	}
	if result != int64(3) {
		t.Errorf("Got %v, want 3", result)
	}
}

func TestCSNFTransformNestedEmpty(t *testing.T) {
	transformer := NewCSNFTransformer()

	// Empty array
	result, err := transformer.Transform([]any{})
	if err != nil {
		t.Fatalf("Transform empty array error: %v", err)
	}
	arr, ok := result.([]any)
	if !ok || len(arr) != 0 {
		t.Error("Empty array should remain empty")
	}

	// Empty map
	result, err = transformer.Transform(map[string]any{})
	if err != nil {
		t.Fatalf("Transform empty map error: %v", err)
	}
	m, ok := result.(map[string]any)
	if !ok || len(m) != 0 {
		t.Error("Empty map should remain empty")
	}
}
