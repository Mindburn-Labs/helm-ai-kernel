package manifest

import (
	"testing"
)

func TestValidateToolOutput_StableHash(t *testing.T) {
	out1 := map[string]interface{}{"status": "ok", "code": float64(200)}
	out2 := map[string]interface{}{"code": float64(200), "status": "ok"}

	r1, err := ValidateAndCanonicalizeToolOutput(nil, out1)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := ValidateAndCanonicalizeToolOutput(nil, out2)
	if err != nil {
		t.Fatal(err)
	}

	if r1.OutputHash != r2.OutputHash {
		t.Errorf("hashes differ: %s vs %s", r1.OutputHash, r2.OutputHash)
	}
}

func TestValidateToolOutput_DriftDetected_UnexpectedField(t *testing.T) {
	schema := &ToolOutputSchema{
		Fields: map[string]FieldSpec{
			"result": {Type: "string", Required: true},
		},
	}

	_, err := ValidateAndCanonicalizeToolOutput(schema, map[string]interface{}{
		"result":    "ok",
		"new_field": "surprise",
	})
	if err == nil {
		t.Fatal("expected drift error for unexpected field")
	}
	oErr := err.(*ToolOutputError)
	if oErr.Code != ErrConnectorContractDrift {
		t.Errorf("code = %s, want %s", oErr.Code, ErrConnectorContractDrift)
	}
}

func TestValidateToolOutput_DriftDetected_MissingField(t *testing.T) {
	schema := &ToolOutputSchema{
		Fields: map[string]FieldSpec{
			"result":  {Type: "string", Required: true},
			"version": {Type: "string", Required: true},
		},
	}

	_, err := ValidateAndCanonicalizeToolOutput(schema, map[string]interface{}{
		"result": "ok",
	})
	if err == nil {
		t.Fatal("expected drift error for missing required field")
	}
	oErr := err.(*ToolOutputError)
	if oErr.Code != ErrConnectorOutputMissing {
		t.Errorf("code = %s, want %s", oErr.Code, ErrConnectorOutputMissing)
	}
}

func TestValidateToolOutput_DriftDetected_TypeMismatch(t *testing.T) {
	schema := &ToolOutputSchema{
		Fields: map[string]FieldSpec{
			"count": {Type: "number", Required: true},
		},
	}

	_, err := ValidateAndCanonicalizeToolOutput(schema, map[string]interface{}{
		"count": "not-a-number",
	})
	if err == nil {
		t.Fatal("expected type mismatch error")
	}
	oErr := err.(*ToolOutputError)
	if oErr.Code != ErrConnectorOutputType {
		t.Errorf("code = %s, want %s", oErr.Code, ErrConnectorOutputType)
	}
}

func TestValidateToolOutput_NoSchema(t *testing.T) {
	result, err := ValidateAndCanonicalizeToolOutput(nil, map[string]interface{}{
		"anything": "goes",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OutputHash == "" {
		t.Error("expected non-empty hash")
	}
}
