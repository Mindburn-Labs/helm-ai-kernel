package approvalceremony

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

type effectDispositionVectorIndex struct {
	Comment         string                      `json:"$comment"`
	SchemaVersion   string                      `json:"schema_version"`
	ContractVersion string                      `json:"contract_version"`
	QuantumPosture  string                      `json:"quantum_posture"`
	Command         effectCloseSignedVector     `json:"command"`
	Receipt         effectCloseSignedVector     `json:"receipt"`
	NegativeVectors []effectCloseNegativeVector `json:"negative_vectors"`
}

func TestEffectDispositionSchemas(t *testing.T) {
	root := effectCloseRepoRoot(t)
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	for _, name := range []string{
		"effect_disposition_command.json",
		"effect_disposition_command_envelope.json",
		"effect_disposition_receipt.json",
	} {
		filename := filepath.Join(root, "schemas", name)
		payload, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource(effectCloseFileURL(filename), strings.NewReader(string(payload))); err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource("https://helm.mindburn.org/schemas/"+name, strings.NewReader(string(payload))); err != nil {
			t.Fatal(err)
		}
	}
	commandSchema, err := compiler.Compile(effectCloseFileURL(filepath.Join(root, "schemas", "effect_disposition_command.json")))
	if err != nil {
		t.Fatal(err)
	}
	envelopeSchema, err := compiler.Compile(effectCloseFileURL(filepath.Join(root, "schemas", "effect_disposition_command_envelope.json")))
	if err != nil {
		t.Fatal(err)
	}
	receiptSchema, err := compiler.Compile(effectCloseFileURL(filepath.Join(root, "schemas", "effect_disposition_receipt.json")))
	if err != nil {
		t.Fatal(err)
	}
	packRoot := filepath.Join(root, "reference_packs", "effect-disposition-v1")
	for schema, filename := range map[*jsonschema.Schema]string{
		commandSchema: "command.c14n.json", envelopeSchema: "command_envelope.c14n.json", receiptSchema: "receipt.c14n.json",
	} {
		payload, err := os.ReadFile(filepath.Join(packRoot, filename))
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(payload, &value); err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(value); err != nil {
			t.Fatalf("%s schema validation: %v", filename, err)
		}
	}
}
