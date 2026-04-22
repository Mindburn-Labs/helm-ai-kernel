// Package manifest provides tool argument and output validation
// for the PEP (Policy Enforcement Point) boundary.
package manifest

import (
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// Deterministic error codes for PEP boundary violations.
const (
	ErrToolArgsUnknownField    = "ERR_TOOL_ARGS_UNKNOWN_FIELD"
	ErrToolArgsMissingRequired = "ERR_TOOL_ARGS_MISSING_REQUIRED"
	ErrToolArgsTypeMismatch    = "ERR_TOOL_ARGS_TYPE_MISMATCH"
	ErrToolArgsCanonFailed     = "ERR_TOOL_ARGS_CANONICALIZATION_FAILED"
)

// ToolArgSchema defines the expected schema for a tool's arguments.
// This is a lightweight schema that supports required fields and type checking
// without the full weight of JSON Schema.
type ToolArgSchema struct {
	// Fields maps field name → expected type string ("string", "number", "boolean", "object", "array", "any").
	Fields map[string]FieldSpec `json:"fields"`
	// AllowExtra permits fields not declared in the schema.
	AllowExtra bool `json:"allow_extra,omitempty"`
}

// FieldSpec describes a single argument field.
type FieldSpec struct {
	Type     string `json:"type"` // "string", "number", "boolean", "object", "array", "any"
	Required bool   `json:"required,omitempty"`
}

// ToolArgValidationResult is the successful result of validation.
type ToolArgValidationResult struct {
	CanonicalJSON []byte `json:"-"`
	ArgsHash      string `json:"args_hash"` // SHA-256 hex of canonical JSON
}

// ToolArgError is a typed PEP boundary error.
type ToolArgError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

func (e *ToolArgError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s (field: %s)", e.Code, e.Message, e.Field)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ValidateAndCanonicalizeToolArgs validates tool arguments against a schema,
// then returns the JCS-canonicalized bytes and SHA-256 hash.
// If schema is nil, validation is skipped but canonicalization still occurs.
func ValidateAndCanonicalizeToolArgs(schema *ToolArgSchema, args any) (*ToolArgValidationResult, error) {
	// 1. Normalize args to map[string]interface{}
	argsMap, err := toMap(args)
	if err != nil {
		return nil, &ToolArgError{
			Code:    ErrToolArgsCanonFailed,
			Message: fmt.Sprintf("args must be a JSON object: %v", err),
		}
	}

	// 2. Schema validation (if schema provided)
	if schema != nil {
		if err := validateSchema(schema, argsMap); err != nil {
			return nil, err
		}
	}

	// 3. JCS canonicalization
	canonical, err := canonicalize.JCS(argsMap)
	if err != nil {
		return nil, &ToolArgError{
			Code:    ErrToolArgsCanonFailed,
			Message: fmt.Sprintf("JCS canonicalization failed: %v", err),
		}
	}

	// 4. SHA-256 hash
	hash := canonicalize.HashBytes(canonical)

	return &ToolArgValidationResult{
		CanonicalJSON: canonical,
		ArgsHash:      hash,
	}, nil
}

func validateSchema(schema *ToolArgSchema, args map[string]interface{}) error {
	// Check required fields
	for name, spec := range schema.Fields {
		val, exists := args[name]
		if spec.Required && !exists {
			return &ToolArgError{
				Code:    ErrToolArgsMissingRequired,
				Message: fmt.Sprintf("required field %q is missing", name),
				Field:   name,
			}
		}
		if exists && spec.Type != "any" {
			if err := checkType(name, val, spec.Type); err != nil {
				return err
			}
		}
	}

	// Check for unknown fields
	if !schema.AllowExtra {
		for name := range args {
			if _, ok := schema.Fields[name]; !ok {
				return &ToolArgError{
					Code:    ErrToolArgsUnknownField,
					Message: fmt.Sprintf("unknown field %q not in schema", name),
					Field:   name,
				}
			}
		}
	}

	return nil
}

func checkType(field string, val interface{}, expected string) *ToolArgError {
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
		ok = true // Unknown type spec → permissive
	}

	if !ok {
		return &ToolArgError{
			Code:    ErrToolArgsTypeMismatch,
			Message: fmt.Sprintf("field %q expected type %s, got %T", field, expected, val),
			Field:   field,
		}
	}
	return nil
}

func toMap(v any) (map[string]interface{}, error) {
	switch t := v.(type) {
	case map[string]interface{}:
		return t, nil
	default:
		// Try JSON round-trip for structs
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
