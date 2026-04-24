package manifest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFinal_ModuleJSONRoundTrip(t *testing.T) {
	m := Module{Name: "mod1", Version: "1.0.0", Description: "test module"}
	data, _ := json.Marshal(m)
	var got Module
	json.Unmarshal(data, &got)
	if got.Name != "mod1" || got.Version != "1.0.0" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_CapabilityConfigJSONRoundTrip(t *testing.T) {
	c := CapabilityConfig{Name: "read", Description: "Read data", ArgsSchema: "{}"}
	data, _ := json.Marshal(c)
	var got CapabilityConfig
	json.Unmarshal(data, &got)
	if got.Name != "read" {
		t.Fatal("round-trip")
	}
}

func TestFinal_PolicyConfigJSONRoundTrip(t *testing.T) {
	p := PolicyConfig{Name: "p1", EnforcedOn: "BeforeExecution", RegoContent: "allow { true }"}
	data, _ := json.Marshal(p)
	var got PolicyConfig
	json.Unmarshal(data, &got)
	if got.EnforcedOn != "BeforeExecution" {
		t.Fatal("policy config round-trip")
	}
}

func TestFinal_BundleJSONRoundTrip(t *testing.T) {
	b := Bundle{Manifest: Module{Name: "m1", Version: "1.0.0"}, Signature: "sig", PowerDelta: 5}
	data, _ := json.Marshal(b)
	var got Bundle
	json.Unmarshal(data, &got)
	if got.PowerDelta != 5 || got.Manifest.Name != "m1" {
		t.Fatal("bundle round-trip")
	}
}

func TestFinal_ErrorCodeConstants(t *testing.T) {
	codes := []string{ErrToolArgsUnknownField, ErrToolArgsMissingRequired, ErrToolArgsTypeMismatch, ErrToolArgsCanonFailed}
	for _, c := range codes {
		if c == "" {
			t.Fatal("empty error code")
		}
	}
}

func TestFinal_OutputErrorCodeConstants(t *testing.T) {
	codes := []string{ErrConnectorContractDrift, ErrConnectorOutputCanon, ErrConnectorOutputMissing, ErrConnectorOutputType}
	for _, c := range codes {
		if c == "" {
			t.Fatal("empty error code")
		}
	}
}

func TestFinal_ToolArgErrorString(t *testing.T) {
	e := &ToolArgError{Code: "TEST", Message: "msg", Field: "f"}
	s := e.Error()
	if !strings.Contains(s, "TEST") || !strings.Contains(s, "f") {
		t.Fatal("error string")
	}
}

func TestFinal_ToolArgErrorNoField(t *testing.T) {
	e := &ToolArgError{Code: "TEST", Message: "msg"}
	s := e.Error()
	if strings.Contains(s, "field") {
		t.Fatal("should not mention field")
	}
}

func TestFinal_ToolOutputErrorString(t *testing.T) {
	e := &ToolOutputError{Code: "TEST", Message: "msg", Field: "f"}
	s := e.Error()
	if !strings.Contains(s, "TEST") {
		t.Fatal("error string")
	}
}

func TestFinal_ToolOutputErrorNoField(t *testing.T) {
	e := &ToolOutputError{Code: "TEST", Message: "msg"}
	s := e.Error()
	if strings.Contains(s, "field") {
		t.Fatal("should not mention field")
	}
}

func TestFinal_ValidateAndCanonicalizeNoSchema(t *testing.T) {
	result, err := ValidateAndCanonicalizeToolArgs(nil, map[string]interface{}{"key": "val"})
	if err != nil || result == nil {
		t.Fatal("should succeed without schema")
	}
	if result.ArgsHash == "" {
		t.Fatal("hash should be set")
	}
}

func TestFinal_ValidateAndCanonicalizeRequired(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"name": {Type: "string", Required: true}}}
	_, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{})
	if err == nil {
		t.Fatal("should error on missing required")
	}
}

func TestFinal_ValidateAndCanonicalizeUnknownField(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"name": {Type: "string"}}}
	_, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{"name": "x", "extra": "y"})
	if err == nil {
		t.Fatal("should error on unknown field")
	}
}

func TestFinal_ValidateAndCanonicalizeAllowExtra(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"name": {Type: "string"}}, AllowExtra: true}
	_, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{"name": "x", "extra": "y"})
	if err != nil {
		t.Fatal("should allow extra")
	}
}

func TestFinal_ValidateAndCanonicalizeTypeMismatch(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"count": {Type: "number"}}}
	_, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{"count": "not a number"})
	if err == nil {
		t.Fatal("should error on type mismatch")
	}
}

func TestFinal_ValidateAndCanonicalizeTypeString(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"name": {Type: "string"}}}
	_, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{"name": "hello"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_ValidateAndCanonicalizeTypeBoolean(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"flag": {Type: "boolean"}}}
	_, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{"flag": true})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_ValidateAndCanonicalizeTypeAny(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"data": {Type: "any"}}}
	_, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{"data": 42.0})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_CanonicalHashDeterministic(t *testing.T) {
	args := map[string]interface{}{"z": "last", "a": "first"}
	r1, _ := ValidateAndCanonicalizeToolArgs(nil, args)
	r2, _ := ValidateAndCanonicalizeToolArgs(nil, args)
	if r1.ArgsHash != r2.ArgsHash {
		t.Fatal("not deterministic")
	}
}

func TestFinal_ValidateOutputNoSchema(t *testing.T) {
	result, err := ValidateAndCanonicalizeToolOutput(nil, map[string]interface{}{"result": "ok"})
	if err != nil || result == nil {
		t.Fatal("should succeed without schema")
	}
}

func TestFinal_ValidateOutputMissingRequired(t *testing.T) {
	schema := &ToolOutputSchema{Fields: map[string]FieldSpec{"status": {Type: "string", Required: true}}}
	_, err := ValidateAndCanonicalizeToolOutput(schema, map[string]interface{}{})
	if err == nil {
		t.Fatal("should error on missing")
	}
}

func TestFinal_ValidateOutputUnknownField(t *testing.T) {
	schema := &ToolOutputSchema{Fields: map[string]FieldSpec{"status": {Type: "string"}}}
	_, err := ValidateAndCanonicalizeToolOutput(schema, map[string]interface{}{"status": "ok", "extra": "bad"})
	if err == nil {
		t.Fatal("should error on drift")
	}
}

func TestFinal_ValidateOutputAllowExtra(t *testing.T) {
	schema := &ToolOutputSchema{Fields: map[string]FieldSpec{"status": {Type: "string"}}, AllowExtra: true}
	_, err := ValidateAndCanonicalizeToolOutput(schema, map[string]interface{}{"status": "ok", "extra": "ok"})
	if err != nil {
		t.Fatal("should allow extra")
	}
}

func TestFinal_ValidateOutputTypeMismatch(t *testing.T) {
	schema := &ToolOutputSchema{Fields: map[string]FieldSpec{"count": {Type: "number"}}}
	_, err := ValidateAndCanonicalizeToolOutput(schema, map[string]interface{}{"count": "str"})
	if err == nil {
		t.Fatal("should error")
	}
}

func TestFinal_OutputHashDeterministic(t *testing.T) {
	out := map[string]interface{}{"z": 1.0, "a": 2.0}
	r1, _ := ValidateAndCanonicalizeToolOutput(nil, out)
	r2, _ := ValidateAndCanonicalizeToolOutput(nil, out)
	if r1.OutputHash != r2.OutputHash {
		t.Fatal("not deterministic")
	}
}

func TestFinal_ToolArgSchemaJSONRoundTrip(t *testing.T) {
	s := ToolArgSchema{Fields: map[string]FieldSpec{"name": {Type: "string", Required: true}}, AllowExtra: false}
	data, _ := json.Marshal(s)
	var got ToolArgSchema
	json.Unmarshal(data, &got)
	if got.Fields["name"].Type != "string" {
		t.Fatal("schema round-trip")
	}
}

func TestFinal_ToolOutputSchemaJSONRoundTrip(t *testing.T) {
	s := ToolOutputSchema{Fields: map[string]FieldSpec{"result": {Type: "object"}}}
	data, _ := json.Marshal(s)
	var got ToolOutputSchema
	json.Unmarshal(data, &got)
	if got.Fields["result"].Type != "object" {
		t.Fatal("output schema round-trip")
	}
}

func TestFinal_ToolArgValidationResultJSONRoundTrip(t *testing.T) {
	r := ToolArgValidationResult{ArgsHash: "abc123"}
	data, _ := json.Marshal(r)
	var got ToolArgValidationResult
	json.Unmarshal(data, &got)
	if got.ArgsHash != "abc123" {
		t.Fatal("result round-trip")
	}
}

func TestFinal_ToolOutputValidationResultJSONRoundTrip(t *testing.T) {
	r := ToolOutputValidationResult{OutputHash: "def456"}
	data, _ := json.Marshal(r)
	var got ToolOutputValidationResult
	json.Unmarshal(data, &got)
	if got.OutputHash != "def456" {
		t.Fatal("result round-trip")
	}
}

func TestFinal_ValidateStruct(t *testing.T) {
	type Args struct {
		Name string `json:"name"`
	}
	_, err := ValidateAndCanonicalizeToolArgs(nil, Args{Name: "test"})
	if err != nil {
		t.Fatal("struct args should work")
	}
}

func TestFinal_FieldSpecJSONRoundTrip(t *testing.T) {
	fs := FieldSpec{Type: "array", Required: true}
	data, _ := json.Marshal(fs)
	var got FieldSpec
	json.Unmarshal(data, &got)
	if got.Type != "array" || !got.Required {
		t.Fatal("field spec round-trip")
	}
}
