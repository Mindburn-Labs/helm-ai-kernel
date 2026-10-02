package adapters

// quantum_posture: SHA-256 binds result bytes; this transport neither signs
// them nor upgrades the source's declared trust class.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/interfaces"
)

// MaxResultBytes bounds an effect's complete canonical JSON result. An
// adapter must explicitly refuse a snapshot that cannot fit, never truncate
// it or claim that an incomplete snapshot is the complete result.
const MaxResultBytes = 1 << 20

var resultSchemaID = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,240}\.v[1-9][0-9]*$`)

// ResultSchema is the compiled, immutable result contract of one declared
// effect type. It comes from composition, never from a tool-call argument or
// an adapter's observation.
type ResultSchema struct {
	id     string
	schema *jsonschema.Schema
}

// CompileResultSchema compiles a declared output schema without network or
// filesystem resolution. A declaration without either result field keeps
// the existing fixed-result or no-result contract.
func CompileResultSchema(d Declaration) (*ResultSchema, error) {
	if d.ResultSchemaID == "" && len(d.ResultSchema) == 0 {
		return nil, nil
	}
	if !resultSchemaID.MatchString(d.ResultSchemaID) || len(d.ResultSchema) == 0 || len(d.ResultSchema) > MaxResultBytes {
		return nil, errors.New("a result declaration requires a bounded versioned schema")
	}
	var root map[string]any
	if !utf8.Valid(d.ResultSchema) || json.Unmarshal(d.ResultSchema, &root) != nil ||
		root["type"] != "object" || root["additionalProperties"] != false {
		return nil, errors.New("a result schema must be a closed JSON object")
	}
	if id, exists := root["$id"]; exists && id != d.ResultSchemaID {
		return nil, errors.New("the declared result schema id differs from its document id")
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	compiler.LoadURL = func(string) (io.ReadCloser, error) {
		return nil, errors.New("result schemas may not resolve external resources")
	}
	const location = "https://helm.invalid/gateway/result-schema.json"
	if err := compiler.AddResource(location, bytes.NewReader(d.ResultSchema)); err != nil {
		return nil, fmt.Errorf("invalid result schema: %w", err)
	}
	compiled, err := compiler.Compile(location)
	if err != nil {
		return nil, fmt.Errorf("invalid result schema: %w", err)
	}
	return &ResultSchema{id: d.ResultSchemaID, schema: compiled}, nil
}

// NewJSONResult wraps already canonical result bytes in HELM's canonical
// Artifact model. It does not canonicalize a different result on behalf of
// its producer: the retained provider snapshot and the returned digest must
// identify the same bytes.
func NewJSONResult(schemaID string, canonical []byte) (*interfaces.Artifact, error) {
	sum := sha256.Sum256(canonical)
	a := &interfaces.Artifact{SchemaID: schemaID, ContentType: "application/json",
		CanonicalBytes: bytes.Clone(canonical), Digest: "sha256:" + hex.EncodeToString(sum[:])}
	if _, err := resultValue(a); err != nil {
		return nil, err
	}
	return a, nil
}

// Validate binds an observation to the exact result contract registered for
// its effect type, including content address and interoperable JSON bytes.
func (s *ResultSchema) Validate(a *interfaces.Artifact) error {
	if s == nil || a == nil || a.SchemaID != s.id {
		return errors.New("the result does not name the effect's declared schema")
	}
	value, err := resultValue(a)
	if err != nil {
		return err
	}
	if err := s.schema.Validate(value); err != nil {
		return errors.New("the result does not satisfy the effect's declared schema")
	}
	return nil
}

// ValidateResultArtifact checks stored content integrity without consulting
// today's adapter registry. A historical observation remains readable after
// its adapter is removed or superseded; its recorded schema id stays intact.
func ValidateResultArtifact(a *interfaces.Artifact) error {
	// Validate the original envelope before reconstructing the canonical
	// content address. Never normalize away metadata or a retained bad digest.
	if a == nil || a.ContentType != "application/json" || a.Preview != "" || len(a.Metadata) != 0 {
		return errors.New("the result is not a bounded JSON artifact")
	}
	checked, err := NewJSONResult(a.SchemaID, a.CanonicalBytes)
	if err != nil {
		return err
	}
	if a.Digest != checked.Digest {
		return errors.New("the result digest does not bind its canonical bytes")
	}
	return nil
}

func resultValue(a *interfaces.Artifact) (any, error) {
	if a == nil || !resultSchemaID.MatchString(a.SchemaID) || a.ContentType != "application/json" ||
		a.Preview != "" || len(a.Metadata) != 0 || len(a.CanonicalBytes) == 0 || len(a.CanonicalBytes) > MaxResultBytes ||
		!utf8.Valid(a.CanonicalBytes) {
		return nil, errors.New("the result is not a bounded JSON artifact")
	}
	sum := sha256.Sum256(a.CanonicalBytes)
	if a.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		return nil, errors.New("the result digest does not bind its canonical bytes")
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(a.CanonicalBytes))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil || value == nil {
		return nil, errors.New("the result is not a JSON object")
	}
	canonical, err := canonicalize.InteroperableJCS(value)
	if err != nil || !bytes.Equal(canonical, a.CanonicalBytes) {
		return nil, errors.New("the result is not interoperable canonical JSON")
	}
	return value, nil
}
