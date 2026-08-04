package api

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

// kernelOpenAPITitle identifies the kernel's own API document.
//
// Renaming it makes the tests below skip rather than fail, so treat this
// constant as part of the spec's identity and change both together.
const kernelOpenAPITitle = "HELM Kernel API"

// loadKernelOpenAPISpec returns the kernel's canonical OpenAPI document, or
// skips.
//
// It skips in two cases. The spec may be absent, when tests run from somewhere
// other than the repo. Or the document sitting at this path may belong to
// someone else: helm-ai-enterprise mirrors this package but publishes its own,
// larger API document at the same relative path. Asserting the kernel's
// contract against the commercial one tests nothing and fails for the wrong
// reason, so the document is identified before it is trusted.
func loadKernelOpenAPISpec(t *testing.T) (map[string]interface{}, []byte) {
	t.Helper()

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
		return nil, nil
	}

	var spec map[string]interface{}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("canonical OpenAPI parse error: %v", err)
	}

	info, _ := spec["info"].(map[string]interface{})
	title, _ := info["title"].(string)
	if title != kernelOpenAPITitle {
		t.Skipf("OpenAPI document at this path is %q, not the kernel's %q", title, kernelOpenAPITitle)
		return nil, nil
	}

	return spec, data
}

// TestOpenAPISpec_Integrity verifies the canonical OpenAPI spec loads and has required endpoints.
func TestOpenAPISpec_Integrity(t *testing.T) {
	spec, _ := loadKernelOpenAPISpec(t)

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
	spec, _ := loadKernelOpenAPISpec(t)

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
	for name, sessionID := range map[string]string{
		"whitespace-only": " \t\n ",
		"slash":           "bad/session",
		"backslash":       `bad\session`,
	} {
		if err := schema.Validate(map[string]any{
			"tool": "read_file", "effect_level": "read", "session_id": sessionID,
		}); err == nil {
			t.Errorf("EvaluateRequest accepted an invalid %s top-level session_id", name)
		}
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

// TestOpenAPIApprovalAndProofGraphCompatibility ensures the schema remains
// source-compatible with v0.7.5 clients while the runtime continues to own
// the fail-closed checks. Old approval transition bodies are accepted by the
// schema only; the route returns 428 and changes no state without the reviewed
// ceremony hash.
func TestOpenAPIApprovalAndProofGraphCompatibility(t *testing.T) {
	spec, _ := loadKernelOpenAPISpec(t)
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI paths missing")
	}

	approvalPath, ok := paths["/api/v1/approvals/{approval_id}/{action}"].(map[string]any)
	if !ok {
		t.Fatal("approval transition path missing")
	}
	post, ok := approvalPath["post"].(map[string]any)
	if !ok {
		t.Fatal("approval transition operation missing")
	}
	requestBody, ok := post["requestBody"].(map[string]any)
	if !ok {
		t.Fatal("approval transition request body missing")
	}
	content, ok := requestBody["content"].(map[string]any)
	if !ok {
		t.Fatal("approval transition request content missing")
	}
	jsonContent, ok := content["application/json"].(map[string]any)
	if !ok {
		t.Fatal("approval transition JSON schema missing")
	}
	transitionSchema, ok := jsonContent["schema"].(map[string]any)
	if !ok {
		t.Fatal("approval transition schema missing")
	}
	if required, ok := transitionSchema["required"].([]any); ok {
		for _, field := range required {
			if field == "expected_ceremony_hash" {
				t.Fatal("approval transition schema must accept the v0.7.5 body without expected_ceremony_hash")
			}
		}
	}
	responses, ok := post["responses"].(map[string]any)
	if !ok {
		t.Fatal("approval transition responses missing")
	}
	if _, ok := responses["428"]; !ok {
		t.Fatal("approval transition must document the no-transition 428 compatibility response")
	}

	proofgraphPath, ok := paths["/api/v1/proofgraph/sessions/{session_id}/receipts"].(map[string]any)
	if !ok {
		t.Fatal("proofgraph session route missing")
	}
	get, ok := proofgraphPath["get"].(map[string]any)
	if !ok {
		t.Fatal("proofgraph session operation missing")
	}
	parameters, ok := get["parameters"].([]any)
	if !ok {
		t.Fatal("proofgraph session parameters missing")
	}
	for _, rawParameter := range parameters {
		parameter, ok := rawParameter.(map[string]any)
		if !ok || parameter["name"] != "session_id" || parameter["in"] != "path" {
			continue
		}
		schema, ok := parameter["schema"].(map[string]any)
		if !ok || schema["type"] != "string" {
			t.Fatalf("proofgraph session compatibility schema = %#v, want unconstrained string", parameter["schema"])
		}
		for _, constrained := range []string{"$ref", "minLength", "pattern"} {
			if _, ok := schema[constrained]; ok {
				t.Fatalf("proofgraph session schema unexpectedly exposes %q: %#v", constrained, schema)
			}
		}
		return
	}
	t.Fatal("proofgraph session_id path parameter missing")
}
