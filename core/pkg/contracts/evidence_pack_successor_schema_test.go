package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestEvidencePackSuccessorSchemasAcceptCanonicalContractsAndRejectExtensions(t *testing.T) {
	root := evidencePackSuccessorRepoRoot(t)
	successorSchema := compileEvidencePackSuccessorSchema(t, filepath.Join(root, "schemas", "evidence_pack_successor.json"))
	evidencePackSchema := compileEvidencePackSuccessorSchema(t, filepath.Join(root, "protocols", "json-schemas", "core", "evidence_pack.schema.json"))

	successor, err := testEvidencePackSuccessor(
		EvidencePackSuccessorMeasurementFinal,
		"successor:progress",
		testEvidencePackSHA("progress-successor"),
		testEvidencePackLineage(),
	).Seal()
	if err != nil {
		t.Fatal(err)
	}
	validateEvidencePackSuccessorSchemaValue(t, successorSchema, successor)

	lineage := testEvidencePackLineage()
	pack := map[string]any{
		"pack_id": "pack-1", "format_version": "v1", "created_at": "2026-09-04T12:00:00Z",
		"identity":  map[string]any{"actor_id": "actor-1", "actor_type": "control_loop"},
		"policy":    map[string]any{"decision_id": "decision-1", "policy_version": "v1", "rules_fired": []any{}, "evaluation_graph_hash": testEvidencePackSHA("policy")},
		"effect":    map[string]any{"effect_id": "effect-1", "effect_type": "CRM_UPDATE", "effect_payload_hash": testEvidencePackSHA("effect")},
		"context":   map[string]any{},
		"execution": map[string]any{"execution_id": "execution-1", "status": "success", "retry_count": 0, "started_at": "2026-09-04T12:00:00Z"},
		"receipts":  map[string]any{}, "reconciliation": map[string]any{},
		"attestation": map[string]any{"pack_hash": testEvidencePackSHA("pack")},
		"lineage":     lineage,
	}
	validateEvidencePackSuccessorSchemaValue(t, evidencePackSchema, pack)

	successorObject := evidencePackSchemaObject(t, successor)
	successorObject["unknown_authority"] = true
	if err := successorSchema.Validate(successorObject); err == nil {
		t.Fatal("successor schema accepted an unknown top-level field")
	}
	lineageObject := evidencePackSchemaObject(t, lineage)
	lineageObject["unbound_contract_hash"] = testEvidencePackSHA("smuggled")
	pack["lineage"] = lineageObject
	if err := evidencePackSchema.Validate(pack); err == nil {
		t.Fatal("EvidencePack schema accepted an unknown lineage field")
	}
}

func compileEvidencePackSuccessorSchema(t *testing.T, filename string) *jsonschema.Schema {
	t.Helper()
	payload, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	url := "file:///" + strings.ReplaceAll(filename, string(filepath.Separator), "/")
	if err := compiler.AddResource(url, strings.NewReader(string(payload))); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(url)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func validateEvidencePackSuccessorSchemaValue(t *testing.T, schema *jsonschema.Schema, value any) {
	t.Helper()
	if err := schema.Validate(evidencePackSchemaObject(t, value)); err != nil {
		t.Fatalf("schema validation: %v", err)
	}
}

func evidencePackSchemaObject(t *testing.T, value any) map[string]any {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func evidencePackSuccessorRepoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
}
