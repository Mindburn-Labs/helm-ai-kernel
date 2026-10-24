package adapters

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// ArgumentSchema is an immutable, composition-owned input contract. It adds
// structural validation to the built-in target and argument checks; it does
// not replace them or grant authority.
type ArgumentSchema struct {
	schema   *jsonschema.Schema
	maxBytes int
}

// CompileArgumentSchema compiles a declared closed draft-2020-12 object
// without network or filesystem resolution. Empty declarations retain the
// existing built-in or dedicated-route argument contract. Exact published
// built-in schemas retain their dedicated validators: some use ECMA regex
// syntax the generic Go schema compiler does not support.
func CompileArgumentSchema(d Declaration) (*ArgumentSchema, error) {
	if len(d.ArgumentSchema) == 0 {
		return nil, nil
	}
	if native, ok := effectargs.ArgumentSchema(d.EffectType); ok && bytes.Equal(native, d.ArgumentSchema) {
		return nil, nil
	}
	root, err := argumentObject(d.ArgumentSchema, effectargs.MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid argument schema: %w", err)
	}
	if root["type"] != "object" || root["additionalProperties"] != false {
		return nil, errors.New("an argument schema must be a closed JSON object")
	}
	if draft, exists := root["$schema"]; exists && draft != "https://json-schema.org/draft/2020-12/schema" {
		return nil, errors.New("an argument schema must use draft 2020-12")
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	compiler.LoadURL = func(string) (io.ReadCloser, error) {
		return nil, errors.New("argument schemas may not resolve external resources")
	}
	const location = "https://helm.invalid/gateway/argument-schema.json"
	if err := compiler.AddResource(location, bytes.NewReader(d.ArgumentSchema)); err != nil {
		return nil, fmt.Errorf("invalid argument schema: %w", err)
	}
	compiled, err := compiler.Compile(location)
	if err != nil {
		return nil, fmt.Errorf("invalid argument schema: %w", err)
	}
	maxBytes := effectargs.MaxBytes
	if effectargs.IsAuthorityPlan(d.EffectType) {
		maxBytes = effectargs.MaxPlanBytes
	}
	return &ArgumentSchema{schema: compiled, maxBytes: maxBytes}, nil
}

// Validate checks the complete original argument object, even when a built-in
// semantic validator returns only the subset exposed to mandate conditions.
func (s *ArgumentSchema) Validate(raw []byte) error {
	if s == nil {
		return errors.New("the effect has no declared argument schema")
	}
	value, err := argumentObject(raw, s.maxBytes)
	if err != nil {
		return err
	}
	if err := s.schema.Validate(value); err != nil {
		return errors.New("the arguments do not satisfy the effect's declared schema")
	}
	return nil
}

func argumentObject(raw []byte, maxBytes int) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > maxBytes || !utf8.Valid(raw) {
		return nil, errors.New("expected a bounded UTF-8 JSON object")
	}
	if err := effectargs.CheckNoDuplicateKeys(raw); err != nil {
		return nil, err
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// Validate decimal numbers as sent, without rounding an integer through
	// float64 and accidentally accepting a value outside a declared bound.
	decoder.UseNumber()
	if decoder.Decode(&value) != nil || value == nil {
		return nil, errors.New("expected a JSON object")
	}
	return value, nil
}
