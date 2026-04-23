package manifest

import (
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// Deterministic error codes for connector output drift.
const (
	ErrConnectorContractDrift = "ERR_CONNECTOR_CONTRACT_DRIFT"
	ErrConnectorOutputCanon   = "ERR_CONNECTOR_OUTPUT_CANONICALIZATION_FAILED"
	ErrConnectorOutputMissing = "ERR_CONNECTOR_OUTPUT_MISSING_FIELD"
	ErrConnectorOutputType    = "ERR_CONNECTOR_OUTPUT_TYPE_MISMATCH"
)

// ToolOutputSchema defines the expected shape of a connector's output.
type ToolOutputSchema struct {
	Fields     map[string]FieldSpec `json:"fields"`
	AllowExtra bool                 `json:"allow_extra,omitempty"`
}

// ToolOutputValidationResult is the successful result of output validation.
type ToolOutputValidationResult struct {
	CanonicalJSON []byte `json:"-"`
	OutputHash    string `json:"output_hash"` // SHA-256 hex of canonical JSON
}

// ToolOutputError is a typed connector drift error.
type ToolOutputError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

func (e *ToolOutputError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s (field: %s)", e.Code, e.Message, e.Field)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ValidateAndCanonicalizeToolOutput validates connector output against a schema,
// then returns the JCS-canonicalized bytes and SHA-256 hash.
// If schema is nil, validation is skipped but canonicalization still occurs.
// Returns fail-closed on any drift.
func ValidateAndCanonicalizeToolOutput(schema *ToolOutputSchema, output any) (*ToolOutputValidationResult, error) {
	// 1. Normalize output to map
	outputMap, err := outputToMap(output)
	if err != nil {
		return nil, &ToolOutputError{
			Code:    ErrConnectorOutputCanon,
			Message: fmt.Sprintf("output must be a JSON object: %v", err),
		}
	}

	// 2. Schema validation if provided
	if schema != nil {
		if err := validateOutputSchema(schema, outputMap); err != nil {
			return nil, err
		}
	}

	// 3. JCS canonicalization
	canonical, err := canonicalize.JCS(outputMap)
	if err != nil {
		return nil, &ToolOutputError{
			Code:    ErrConnectorOutputCanon,
			Message: fmt.Sprintf("JCS canonicalization failed: %v", err),
		}
	}

	// 4. SHA-256 hash
	hash := canonicalize.HashBytes(canonical)

	return &ToolOutputValidationResult{
		CanonicalJSON: canonical,
		OutputHash:    hash,
	}, nil
}

func validateOutputSchema(schema *ToolOutputSchema, output map[string]interface{}) error {
	for name, spec := range schema.Fields {
		val, exists := output[name]
		if spec.Required && !exists {
			return &ToolOutputError{
				Code:    ErrConnectorOutputMissing,
				Message: fmt.Sprintf("required output field %q is missing — connector contract drift detected", name),
				Field:   name,
			}
		}
		if exists && spec.Type != "any" {
			if err := checkOutputType(name, val, spec.Type); err != nil {
				return err
			}
		}
	}

	if !schema.AllowExtra {
		for name := range output {
			if _, ok := schema.Fields[name]; !ok {
				return &ToolOutputError{
					Code:    ErrConnectorContractDrift,
					Message: fmt.Sprintf("unexpected output field %q — connector contract drift detected", name),
					Field:   name,
				}
			}
		}
	}

	return nil
}

func checkOutputType(field string, val interface{}, expected string) *ToolOutputError {
	var ok bool
	switch expected {
	case "string":
		_, ok = val.(string)
	case "number":
		switch val.(type) {
		case float64, json.Number, int, int64:
			ok = true
		}
	case "boolean":
		_, ok = val.(bool)
	case "object":
		_, ok = val.(map[string]interface{})
	case "array":
		_, ok = val.([]interface{})
	case "any":
		ok = true
	default:
		ok = true
	}

	if !ok {
		return &ToolOutputError{
			Code:    ErrConnectorOutputType,
			Message: fmt.Sprintf("output field %q expected type %s, got %T — connector contract drift", field, expected, val),
			Field:   field,
		}
	}
	return nil
}

func outputToMap(v any) (map[string]interface{}, error) {
	switch t := v.(type) {
	case map[string]interface{}:
		return t, nil
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		var m map[string]interface{}
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		return m, nil
	}
}
