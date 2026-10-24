package adapters

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

const testArgumentSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://helm.invalid/schemas/ops.note.v1.json",
  "type":"object","additionalProperties":false,
  "required":["text","metadata"],
  "properties":{
    "text":{"type":"string","minLength":1},
    "metadata":{"$ref":"#/$defs/metadata"}
  },
  "$defs":{"metadata":{
    "type":"object","additionalProperties":false,"required":["priority"],
    "properties":{"priority":{"type":"integer","minimum":1,"maximum":3}}
  }}
}`

func TestArgumentSchemaEnforcesTheDeclaredClosedObject(t *testing.T) {
	d := Declaration{EffectType: "ops.note", ArgumentSchema: []byte(testArgumentSchema)}
	schema, err := CompileArgumentSchema(d)
	if err != nil {
		t.Fatal(err)
	}
	valid := []byte(`{"text":"hello","metadata":{"priority":2}}`)
	if err := schema.Validate(valid); err != nil {
		t.Fatal(err)
	}
	// Composition cannot mutate a registered contract through its original slice.
	d.ArgumentSchema[0] = '['
	if err := schema.Validate(valid); err != nil {
		t.Fatal("mutating the declaration changed the compiled contract:", err)
	}
	for name, raw := range map[string]string{
		"extra field":         `{"text":"hello","metadata":{"priority":2},"grant":"all"}`,
		"missing field":       `{"text":"hello"}`,
		"wrong type":          `{"text":7,"metadata":{"priority":2}}`,
		"nested extra field":  `{"text":"hello","metadata":{"priority":2,"grant":"all"}}`,
		"nested missing":      `{"text":"hello","metadata":{}}`,
		"nested wrong type":   `{"text":"hello","metadata":{"priority":"2"}}`,
		"nested out of range": `{"text":"hello","metadata":{"priority":4}}`,
		"root duplicate":      `{"text":7,"text":"hello","metadata":{"priority":2}}`,
		"escaped duplicate":   `{"text":7,"te\u0078t":"hello","metadata":{"priority":2}}`,
		"nested duplicate":    `{"text":"hello","metadata":{"priority":4,"priority":2}}`,
		"trailing object":     `{"text":"hello","metadata":{"priority":2}}{}`,
		"null":                `null`,
		"array":               `[]`,
		"invalid UTF-8":       "{\"text\":\"\xff\",\"metadata\":{\"priority\":2}}",
		"oversized":           `{"text":"` + strings.Repeat("a", effectargs.MaxBytes) + `","metadata":{"priority":2}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := schema.Validate([]byte(raw)); err == nil {
				t.Fatal("invalid arguments were accepted")
			}
		})
	}
}

func TestArgumentSchemaRejectsMalformedOrUnsupportedDeclarations(t *testing.T) {
	for name, raw := range map[string]string{
		"open object":        `{"type":"object"}`,
		"array root":         `{"type":"array","additionalProperties":false}`,
		"boolean schema":     `true`,
		"invalid JSON":       `{`,
		"trailing object":    `{"type":"object","additionalProperties":false}{}`,
		"duplicate closure":  `{"type":"object","additionalProperties":true,"additionalProperties":false}`,
		"duplicate nested":   `{"type":"object","additionalProperties":false,"properties":{"x":{"type":"number","type":"string"}}}`,
		"wrong dialect":      `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","additionalProperties":false}`,
		"invalid constraint": `{"type":"object","additionalProperties":false,"properties":{"x":{"type":"string","minLength":-1}}}`,
		"missing local ref":  `{"type":"object","additionalProperties":false,"properties":{"x":{"$ref":"#/$defs/missing"}}}`,
		"network ref":        `{"type":"object","additionalProperties":false,"properties":{"x":{"$ref":"https://example.invalid/input.json"}}}`,
		"file ref":           `{"type":"object","additionalProperties":false,"properties":{"x":{"$ref":"file:///etc/passwd"}}}`,
		"invalid UTF-8":      "{\"type\":\"object\",\"additionalProperties\":false,\"title\":\"\xff\"}",
		"oversized":          `{"type":"object","additionalProperties":false,"title":"` + strings.Repeat("a", effectargs.MaxBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileArgumentSchema(Declaration{ArgumentSchema: []byte(raw)}); err == nil {
				t.Fatal("invalid declaration was registered")
			}
		})
	}
	if schema, err := CompileArgumentSchema(Declaration{EffectType: "legacy.effect"}); schema != nil || err != nil {
		t.Fatalf("empty declaration changed: %v, %v", schema, err)
	}
}

func TestArgumentSchemaChecksNumbersWithoutFloatRounding(t *testing.T) {
	schema, err := CompileArgumentSchema(Declaration{ArgumentSchema: []byte(`{"type":"object","additionalProperties":false,"properties":{"n":{"type":"integer","maximum":9007199254740992}}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate([]byte(`{"n":9007199254740992}`)); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate([]byte(`{"n":9007199254740993}`)); err == nil {
		t.Fatal("an integer above the declared bound was rounded down and accepted")
	}
}

func TestPublishedBuiltinArgumentSchemasKeepNativeValidation(t *testing.T) {
	for _, effectType := range []string{
		effectargs.GitHubBranchCreateFromChanges, effectargs.GitHubGitPush,
		effectargs.GitHubPullRequestCreateDraft, effectargs.GitHubPullRequestCreate,
		effectargs.GitHubPullRequestMerge, effectargs.GitHubRepositoryGet,
		effectargs.AuthorityProvision, effectargs.AuthorityNarrow,
		effectargs.AuthorityWorkReassignmentGrant, effectargs.AuthorityWorkReassignmentRevoke,
	} {
		t.Run(effectType, func(t *testing.T) {
			raw, ok := effectargs.ArgumentSchema(effectType)
			if !ok {
				t.Fatal("published schema missing")
			}
			if schema, err := CompileArgumentSchema(Declaration{EffectType: effectType, ArgumentSchema: raw}); err != nil || schema != nil {
				t.Fatalf("native contract did not retain its validator: %v, %v", schema, err)
			}
		})
	}
}

func TestBuiltinNameCannotBypassCustomSchemaCompilation(t *testing.T) {
	for name, declaration := range map[string]Declaration{
		"changed builtin": {EffectType: effectargs.GitHubRepositoryGet, ArgumentSchema: []byte(`{"type":"object"}`)},
		"borrowed schema": {EffectType: "custom.branch", ArgumentSchema: func() []byte {
			body, _ := effectargs.ArgumentSchema(effectargs.GitHubBranchCreateFromChanges)
			return body
		}()},
	} {
		if _, err := CompileArgumentSchema(declaration); err == nil {
			t.Fatalf("%s inherited the native exemption", name)
		}
	}
	schema, err := CompileArgumentSchema(Declaration{EffectType: effectargs.GitHubRepositoryGet, ArgumentSchema: []byte(testArgumentSchema)})
	if err != nil || schema == nil {
		t.Fatalf("custom schema under a builtin name did not compile: %v, %v", schema, err)
	}
	if err := schema.Validate([]byte(`{"schema":"helm.github.repository.get.v1"}`)); err == nil {
		t.Fatal("custom schema under a builtin name was bypassed")
	}
}
