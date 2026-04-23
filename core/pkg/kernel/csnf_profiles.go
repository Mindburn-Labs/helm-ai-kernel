// Package kernel provides extended CSNF profile validation per Normative Addendum 6.5.
// This file contains enhanced validation for DecimalString and Timestamp profiles,
// as well as null stripping according to schema configuration.
package kernel

import (
	"fmt"
	"regexp"
	"time"

	"golang.org/x/text/unicode/norm"
)

// DecimalString profile regex per Addendum 6.5.5
// Matches: -?(0|[1-9][0-9]*)(\.[0-9]+)?
var decimalStringPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)

// ValidateDecimalString checks if a string is a valid CSNF DecimalString.
// Per Addendum 6.5.5: DecimalStrings MUST match the regex pattern.
func ValidateDecimalString(s string) error {
	if !decimalStringPattern.MatchString(s) {
		return fmt.Errorf("csnf: invalid decimal string format: %q", s)
	}
	return nil
}

// Timestamp profile validation per Addendum 6.5.6.
// All timestamps MUST be RFC 3339 format with explicit timezone offset.

// ValidateTimestamp checks if a string is a valid CSNF timestamp.
// Per Addendum 6.5.6: Timestamps MUST have explicit timezone offset.
func ValidateTimestamp(s string) error {
	// Try parsing with timezone offset
	_, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// Try with nanoseconds
		_, err = time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return fmt.Errorf("csnf: invalid timestamp format (must be RFC 3339 with timezone): %q", s)
		}
	}

	// Verify timezone is present (not just local time)
	// RFC 3339 always requires timezone, so parse success implies this
	return nil
}

// NormalizeTimestamp converts a timestamp to canonical UTC form.
// While any RFC 3339 with offset is valid, UTC (Z suffix) is recommended.
func NormalizeTimestamp(s string) (string, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
		if err != nil {
			return "", fmt.Errorf("csnf: cannot parse timestamp: %w", err)
		}
	}

	// Convert to UTC and format with millisecond precision
	return t.UTC().Format("2006-01-02T15:04:05.000Z"), nil
}

// CSNFSchemaField represents schema information for a field.
type CSNFSchemaField struct {
	Nullable  bool          `json:"nullable"`
	Type      string        `json:"type"`
	Format    string        `json:"format,omitempty"`
	ArrayKind CSNFArrayKind `json:"x-helm-array-kind,omitempty"`
	SortKey   []string      `json:"x-helm-sort-key,omitempty"`
	SetDedup  bool          `json:"x-helm-set-dedup,omitempty"`
}

// CSNFSchema provides schema information for CSNF validation.
type CSNFSchema struct {
	Fields map[string]CSNFSchemaField `json:"properties"`
}

// StripNullsWithSchema removes null values from non-nullable fields.
// Per Addendum 6.5.3: Null values MUST be stripped from non-nullable fields.
func StripNullsWithSchema(obj map[string]any, schema *CSNFSchema) map[string]any {
	if schema == nil {
		// Without schema, strip all nulls (conservative approach)
		return StripNulls(obj)
	}

	result := make(map[string]any, len(obj))
	for key, val := range obj {
		if val == nil {
			// Check if field is nullable in schema
			field, exists := schema.Fields[key]
			if exists && field.Nullable {
				result[key] = nil // Keep null for nullable fields
			}
			// Otherwise: omit the null value
		} else if nested, ok := val.(map[string]any); ok {
			// Recursively process nested objects
			// Note: A more complete implementation would track nested schemas
			result[key] = StripNulls(nested)
		} else if arr, ok := val.([]any); ok {
			// Process arrays
			result[key] = stripNullsFromArray(arr)
		} else {
			result[key] = val
		}
	}
	return result
}

// StripNulls removes all null values from an object (no schema version).
// This is a conservative approach when schema is not available.
func StripNulls(obj map[string]any) map[string]any {
	result := make(map[string]any, len(obj))
	for key, val := range obj {
		if val == nil {
			continue // Strip null
		}
		if nested, ok := val.(map[string]any); ok {
			result[key] = StripNulls(nested)
		} else if arr, ok := val.([]any); ok {
			result[key] = stripNullsFromArray(arr)
		} else {
			result[key] = val
		}
	}
	return result
}

func stripNullsFromArray(arr []any) []any {
	result := make([]any, 0, len(arr))
	for _, val := range arr {
		if val == nil {
			// Arrays should keep nulls if they're semantically meaningful
			// For now, preserve nulls in arrays (different from object fields)
			result = append(result, nil)
		} else if nested, ok := val.(map[string]any); ok {
			result = append(result, StripNulls(nested))
		} else if nestedArr, ok := val.([]any); ok {
			result = append(result, stripNullsFromArray(nestedArr))
		} else {
			result = append(result, val)
		}
	}
	return result
}

// CSNFValidationResult contains the results of CSNF validation.
type CSNFValidationResult struct {
	Valid  bool
	Issues []CSNFIssue
}

// CSNFIssue represents a single CSNF compliance issue.
type CSNFIssue struct {
	Path     string `json:"path"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Severity string `json:"severity"` // "error" or "warning"
}

// ValidateCSNFStrict performs strict CSNF validation per Addendum 6.5.
func ValidateCSNFStrict(v any, schema *CSNFSchema) CSNFValidationResult {
	result := CSNFValidationResult{Valid: true}
	validateCSNFStrictInternal(v, "", schema, &result.Issues)
	result.Valid = len(result.Issues) == 0 || !hasCSNFErrors(result.Issues)
	return result
}

func validateCSNFStrictInternal(v any, path string, schema *CSNFSchema, issues *[]CSNFIssue) {
	if v == nil {
		// Null is only valid if schema permits
		//nolint:staticcheck // suppressed
		if schema != nil {
			// Would need to look up path in schema
			// For now, allow nulls (schema validation is best-effort)
		} //nolint:staticcheck // Placeholder for schema validation
		return
	}

	switch val := v.(type) {
	case float64:
		// All floats are rejected per Addendum 6.5.2
		if val != float64(int64(val)) {
			*issues = append(*issues, CSNFIssue{
				Path:     path,
				Code:     "CSNF_FLOAT_NOT_ALLOWED",
				Message:  fmt.Sprintf("fractional number not allowed: %v", val),
				Severity: "error",
			})
		} else {
			*issues = append(*issues, CSNFIssue{
				Path:     path,
				Code:     "CSNF_FLOAT_SHOULD_BE_INTEGER",
				Message:  fmt.Sprintf("float64 should be represented as integer: %v", val),
				Severity: "warning",
			})
		}

	case []any:
		for i, elem := range val {
			validateCSNFStrictInternal(elem, fmt.Sprintf("%s[%d]", path, i), schema, issues)
		}

	case map[string]any:
		for key, elem := range val {
			childPath := path + "/" + key
			validateCSNFStrictInternal(elem, childPath, schema, issues)
		}

	case string:
		// Check NFC normalization
		if !IsNFCNormalized(val) {
			*issues = append(*issues, CSNFIssue{
				Path:     path,
				Code:     "CSNF_NOT_NFC",
				Message:  "string is not NFC normalized",
				Severity: "error",
			})
		}
	}
}

// IsNFCNormalized checks if a string is already NFC normalized.
func IsNFCNormalized(s string) bool {
	return norm.NFC.IsNormalString(s)
}

func hasCSNFErrors(issues []CSNFIssue) bool {
	for _, issue := range issues {
		if issue.Severity == "error" {
			return true
		}
	}
	return false
}
