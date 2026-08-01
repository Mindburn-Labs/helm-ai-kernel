package api

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

// TestOpenAPISpec_Integrity verifies the canonical OpenAPI spec loads and has required endpoints.
func TestOpenAPISpec_Integrity(t *testing.T) {
	// Find the canonical OpenAPI spec relative to repo root.
	paths := []string{
		"../../api/openapi/helm.openapi.yaml",
		"../../../api/openapi/helm.openapi.yaml",
	}

	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Skip("canonical OpenAPI spec not found (run from repo root)")
		return
	}

	var spec map[string]interface{}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("canonical OpenAPI parse error: %v", err)
	}

	// Verify required paths exist
	pathsMap, ok := spec["paths"].(map[string]interface{})
	if !ok {
		t.Fatal("canonical OpenAPI spec missing paths section")
	}

	required := []string{
		"/healthz",
		"/version",
		"/mcp",
		"/.well-known/oauth-protected-resource/mcp",
		"/api/v1/kernel/approve",
		"/api/v1/console/bootstrap",
		"/api/v1/evaluate",
		"/api/v1/receipts",
		"/api/v1/trust/keys/add",
		"/api/v1/trust/keys/revoke",
		"/v1/chat/completions",
		"/mcp/v1/capabilities",
		"/mcp/v1/execute",
	}

	for _, path := range required {
		if _, exists := pathsMap[path]; !exists {
			t.Errorf("canonical OpenAPI spec missing required path: %s", path)
		}
	}
}

// TestEvaluateRequestOpenAPISessionRequirement validates the generator-compatible
// JSON Schema expression directly, rather than only checking the server's
// runtime validation. A nonblank session is mandatory at either accepted
// location; a valid context value remains a fallback when the top-level value
// is blank.
func TestEvaluateRequestOpenAPISessionRequirement(t *testing.T) {
	paths := []string{
		"../../api/openapi/helm.openapi.yaml",
		"../../../api/openapi/helm.openapi.yaml",
	}

	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Skip("canonical OpenAPI spec not found (run from repo root)")
	}

	var spec map[string]any
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("canonical OpenAPI parse error: %v", err)
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal OpenAPI spec as JSON Schema resource: %v", err)
	}

	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	const resourceURL = "https://helm.mindburn.org/openapi/helm.openapi.json"
	if err := compiler.AddResource(resourceURL, strings.NewReader(string(encoded))); err != nil {
		t.Fatalf("add OpenAPI schema resource: %v", err)
	}
	schema, err := compiler.Compile(resourceURL + "#/components/schemas/EvaluateRequest")
	if err != nil {
		t.Fatalf("compile EvaluateRequest schema: %v", err)
	}

	for name, value := range map[string]any{
		"top-level session": map[string]any{
			"tool": "read_file", "session_id": "session-top",
		},
		"context session": map[string]any{
			"tool": "read_file", "context": map[string]any{"session_id": "session-context"},
		},
		"context fallback after blank top-level": map[string]any{
			"tool": "read_file", "session_id": " \t ", "context": map[string]any{"session_id": "session-context"},
		},
	} {
		if err := schema.Validate(value); err != nil {
			t.Errorf("EvaluateRequest rejected valid %s: %v", name, err)
		}
	}

	for name, value := range map[string]any{
		"missing":              map[string]any{"tool": "read_file"},
		"whitespace top-level": map[string]any{"tool": "read_file", "session_id": " \t\n "},
		"whitespace context": map[string]any{
			"tool": "read_file", "context": map[string]any{"session_id": " \t\n "},
		},
		"both whitespace": map[string]any{
			"tool": "read_file", "session_id": " ", "context": map[string]any{"session_id": "\t"},
		},
	} {
		if err := schema.Validate(value); err == nil {
			t.Errorf("EvaluateRequest accepted invalid %s session: %#v", name, value)
		}
	}
}
