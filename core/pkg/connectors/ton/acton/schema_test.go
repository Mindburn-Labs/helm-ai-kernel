package acton

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestSchemasCompileAndValidateCoreArtifacts(t *testing.T) {
	commandSchema := compileSchema(t, "acton_command.schema.json")
	receiptSchema := compileSchema(t, "acton_receipt.schema.json")
	contractSchema := compileSchema(t, "acton_contract_bundle.schema.json")
	manifestSchema := compileSchema(t, "acton_script_manifest.schema.json")

	env, err := NewEnvelope(map[string]any{
		"acton_version":         "fixture-acton-1.0.0",
		"tolk_compiler_version": "fixture-tolk-1.0.0",
		"sandbox_grant_hash":    sealedGrant(t, false, true).GrantHash,
	}, ActionBuild, "sha256:intent", 0)
	if err != nil {
		t.Fatal(err)
	}
	validateJSON(t, commandSchema, env)

	receipt := executeReceipt(t, NewConnector(Config{
		Runner:       Runner{Executor: &fakeExecutor{stdout: []byte(`{"build":"ok"}`)}, SandboxID: "s1"},
		SandboxGrant: sealedGrant(t, false, true),
	}), ActionBuild, map[string]any{
		"acton_version":              "fixture-acton-1.0.0",
		"tolk_compiler_version":      "fixture-tolk-1.0.0",
		"expected_output_shape_hash": outputShapeHash([]byte(`{"build":"ok"}`)),
	})
	validateJSON(t, receiptSchema, receipt)
	validateJSON(t, contractSchema, ContractBundle())
	validateJSON(t, manifestSchema, scriptManifest("contracts/scripts/deploy.tolk", "sha256:script", NetworkTestnet))
}

func compileSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "..", "protocols", "json-schemas", "connectors", "ton", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource(name, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(name)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func validateJSON(t *testing.T, schema *jsonschema.Schema, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(generic); err != nil {
		t.Fatalf("schema validation failed: %v\njson=%s", err, data)
	}
}
