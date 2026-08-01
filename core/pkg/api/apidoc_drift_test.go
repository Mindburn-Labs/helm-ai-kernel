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

// TestEvaluateRequestOpenAPISessionRequirement validates the v0.8 public
// compatibility envelope directly, rather than only checking runtime
// validation. Canonical V5 clients use top-level tool/effect_level/session_id;
// legacy direct-daemon callers retain action/resource with context.session_id.
// The operation-level schema must not make the V5 fields globally required,
// because that would reject the established public legacy request shape.
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
		"canonical V5 request": map[string]any{
			"tool": "read_file", "effect_level": "read", "session_id": "session-top",
		},
		"legacy public request": map[string]any{
			"principal": "legacy-client", "action": "read_file", "resource": "read",
			"context": map[string]any{"session_id": "session-context"},
		},
		"legacy request with V5 additions": map[string]any{
			"action": "read_file", "resource": "read", "tool": "read_file",
			"effect_level": "read", "context": map[string]any{"session_id": "session-context"},
		},
	} {
		if err := schema.Validate(value); err != nil {
			t.Errorf("EvaluateRequest rejected valid %s: %v", name, err)
		}
	}

	// The operation schema intentionally has no global required fields: v0.8
	// accepts both public request envelopes and the runtime performs the
	// shape/non-blank validation before it issues a receipt.
	if err := schema.Validate(map[string]any{"tool": "read_file"}); err != nil {
		t.Errorf("EvaluateRequest must retain additive compatibility at the OpenAPI boundary: %v", err)
	}

	components, ok := spec["components"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI components missing")
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI component schemas missing")
	}
	for schemaName, fields := range map[string][]string{
		"EvaluateRequest":  {"principal", "action", "resource", "tool", "effect_level", "session_id"},
		"EvaluateResponse": {"id", "action", "resource", "reason", "policy_version", "policy_decision_hash", "signature"},
	} {
		schemaMap, ok := schemas[schemaName].(map[string]any)
		if !ok {
			t.Errorf("OpenAPI schema %s missing", schemaName)
			continue
		}
		properties, ok := schemaMap["properties"].(map[string]any)
		if !ok {
			t.Errorf("OpenAPI schema %s properties missing", schemaName)
			continue
		}
		for _, field := range fields {
			if _, ok := properties[field]; !ok {
				t.Errorf("OpenAPI schema %s is missing compatibility field %q", schemaName, field)
			}
		}
	}
}
