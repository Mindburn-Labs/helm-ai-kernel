package adapters

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/interfaces"
)

const resultID = "helm.work.delegate.result.v1"

func delegateResultDeclaration() Declaration {
	return Declaration{EffectType: "helm.work.delegate", ResultSchemaID: resultID,
		ResultSchema: []byte(`{"$id":"helm.work.delegate.result.v1","type":"object","additionalProperties":false,"required":["child_id"],"properties":{"child_id":{"type":"string","minLength":1}}}`)}
}

func rawArtifact(raw string) *interfaces.Artifact {
	body := []byte(raw)
	sum := sha256.Sum256(body)
	return &interfaces.Artifact{SchemaID: resultID, ContentType: "application/json", CanonicalBytes: body,
		Digest: "sha256:" + hex.EncodeToString(sum[:])}
}

func TestDeclaredResultSchemaBindsTheCanonicalArtifact(t *testing.T) {
	d := delegateResultDeclaration()
	schema, err := CompileResultSchema(d)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"child_id":"child-7"}`)
	result, err := NewJSONResult(resultID, raw)
	if err != nil || schema.Validate(result) != nil {
		t.Fatalf("valid retained result: %+v, %v", result, err)
	}
	// Composition and the producer cannot mutate an already compiled schema
	// or the result bytes by retaining their original input slices.
	d.ResultSchema[0], raw[0] = '[', '['
	if schema.Validate(result) != nil || !bytes.Equal(result.CanonicalBytes, []byte(`{"child_id":"child-7"}`)) {
		t.Fatal("external mutation changed the result contract or bytes")
	}
	wrongSchema := *result
	wrongSchema.SchemaID = "helm.work.review.result.v1"
	wrongDigest := *result
	wrongDigest.Digest = "sha256:" + strings.Repeat("0", 64)
	for name, candidate := range map[string]*interfaces.Artifact{
		"wrong schema": &wrongSchema, "wrong digest": &wrongDigest,
		"extra field":   rawArtifact(`{"child_id":"child-7","granted":true}`),
		"wrong type":    rawArtifact(`{"child_id":7}`),
		"missing child": rawArtifact(`{}`), "nil": nil,
	} {
		if schema.Validate(candidate) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestResultArtifactsRejectAmbiguousUnboundedOrAlteredBytes(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate key":        `{"child_id":"first","child_id":"second"}`,
		"trailing object":      `{"child_id":"a"}{}`,
		"noncanonical spacing": `{ "child_id": "a" }`,
		"out of order":         `{"z":1,"a":2}`,
		"unsafe integer":       `{"n":9007199254740993}`,
		"fraction":             `{"n":1.0}`,
		"exponent":             `{"n":1e2}`,
		"negative zero":        `{"n":-0}`,
		"array":                `[]`, "null": `null`,
		"invalid utf8": "{\"child_id\":\"\xff\"}",
		"too large":    `{"child_id":"` + strings.Repeat("a", MaxResultBytes) + `"}`,
	} {
		if _, err := NewJSONResult(resultID, []byte(raw)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for name, modify := range map[string]func(*interfaces.Artifact){
		"unvalidated metadata": func(a *interfaces.Artifact) { a.Metadata = map[string]string{"grant": "all"} },
		"preview":              func(a *interfaces.Artifact) { a.Preview = "not the retained result" },
		"wrong media":          func(a *interfaces.Artifact) { a.ContentType = "text/plain" },
		"unversioned schema":   func(a *interfaces.Artifact) { a.SchemaID = "work" },
	} {
		a := rawArtifact(`{"child_id":"a"}`)
		modify(a)
		if ValidateResultArtifact(a) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestResultSchemasFailClosedWithoutExternalResolution(t *testing.T) {
	for name, body := range map[string]string{
		"not closed":   `{"type":"object"}`,
		"wrong root":   `{"type":"array","additionalProperties":false}`,
		"wrong id":     `{"$id":"other.v1","type":"object","additionalProperties":false}`,
		"external ref": `{"type":"object","additionalProperties":false,"properties":{"x":{"$ref":"https://example.invalid/secret"}}}`,
		"file ref":     `{"type":"object","additionalProperties":false,"properties":{"x":{"$ref":"file:///etc/passwd"}}}`,
		"invalid JSON": `{`,
	} {
		d := delegateResultDeclaration()
		d.ResultSchema = []byte(body)
		if _, err := CompileResultSchema(d); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if schema, err := CompileResultSchema(Declaration{EffectType: "old.effect"}); err != nil || schema != nil {
		t.Fatalf("existing declaration changed: %v, %v", schema, err)
	}
	if _, err := CompileResultSchema(Declaration{EffectType: "work", ResultSchemaID: resultID}); err == nil {
		t.Fatal("schema id alone was accepted")
	}
}
