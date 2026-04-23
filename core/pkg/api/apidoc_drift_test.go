package api

import (
	"os"
	"testing"

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
		"/api/v1/trust/keys/add",
		"/api/v1/trust/keys/revoke",
		"/api/v1/oss-local/summary",
		"/api/v1/oss-local/decision-timeline",
		"/api/v1/oss-local/replay-report",
		"/api/v1/oss-local/capabilities",
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
