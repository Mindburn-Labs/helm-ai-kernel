package manifest

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModuleRoundTrip(t *testing.T) {
	m := Module{Name: "m", Version: "1.0.0", Description: "d"}
	data, _ := json.Marshal(m)
	var out Module
	require.NoError(t, json.Unmarshal(data, &out))
	assert.Equal(t, m, out)
}

func TestBundleDefaults(t *testing.T) {
	b := Bundle{Manifest: Module{Name: "b"}, PowerDelta: 5}
	assert.Equal(t, 5, b.PowerDelta)
	assert.Empty(t, b.Signature)
}

func TestToolArgSchemaAllowExtraTrue(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"a": {Type: "string"}}, AllowExtra: true}
	r, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{"a": "v", "b": 1.0})
	require.NoError(t, err)
	assert.NotEmpty(t, r.ArgsHash)
}

func TestToolArgSchemaRequiredPresent(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"x": {Type: "string", Required: true}}}
	r, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{"x": "ok"})
	require.NoError(t, err)
	assert.NotEmpty(t, r.ArgsHash)
}

func TestToolArgSchemaBooleanType(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"flag": {Type: "boolean", Required: true}}}
	_, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{"flag": "yes"})
	require.Error(t, err)
	assert.Equal(t, ErrToolArgsTypeMismatch, err.(*ToolArgError).Code)
}

func TestToolArgSchemaArrayType(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"items": {Type: "array", Required: true}}}
	r, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{"items": []interface{}{"a"}})
	require.NoError(t, err)
	assert.NotEmpty(t, r.ArgsHash)
}

func TestToolArgSchemaObjectType(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"obj": {Type: "object", Required: true}}}
	_, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{"obj": "bad"})
	require.Error(t, err)
	assert.Equal(t, ErrToolArgsTypeMismatch, err.(*ToolArgError).Code)
}

func TestToolArgSchemaAnyType(t *testing.T) {
	schema := &ToolArgSchema{Fields: map[string]FieldSpec{"val": {Type: "any", Required: true}}}
	r, err := ValidateAndCanonicalizeToolArgs(schema, map[string]interface{}{"val": 42.0})
	require.NoError(t, err)
	assert.NotEmpty(t, r.ArgsHash)
}

func TestToolArgErrorFormat(t *testing.T) {
	e := &ToolArgError{Code: ErrToolArgsUnknownField, Message: "bad", Field: "f"}
	assert.Contains(t, e.Error(), "f")
}

func TestToolArgErrorFormatNoField(t *testing.T) {
	e := &ToolArgError{Code: ErrToolArgsCanonFailed, Message: "fail"}
	assert.NotContains(t, e.Error(), "field")
}

func TestToolOutputAllowExtra(t *testing.T) {
	schema := &ToolOutputSchema{Fields: map[string]FieldSpec{"a": {Type: "string"}}, AllowExtra: true}
	r, err := ValidateAndCanonicalizeToolOutput(schema, map[string]interface{}{"a": "v", "extra": true})
	require.NoError(t, err)
	assert.NotEmpty(t, r.OutputHash)
}

func TestToolOutputTypeMismatchBoolean(t *testing.T) {
	schema := &ToolOutputSchema{Fields: map[string]FieldSpec{"ok": {Type: "boolean", Required: true}}}
	_, err := ValidateAndCanonicalizeToolOutput(schema, map[string]interface{}{"ok": "true"})
	require.Error(t, err)
	assert.Equal(t, ErrConnectorOutputType, err.(*ToolOutputError).Code)
}

func TestToolOutputErrorFormat(t *testing.T) {
	e := &ToolOutputError{Code: ErrConnectorContractDrift, Message: "drift", Field: "x"}
	assert.Contains(t, e.Error(), "x")
}

func TestToolOutputErrorFormatNoField(t *testing.T) {
	e := &ToolOutputError{Code: ErrConnectorOutputCanon, Message: "fail"}
	assert.NotContains(t, e.Error(), "field")
}
