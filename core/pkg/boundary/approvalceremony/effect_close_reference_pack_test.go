package approvalceremony

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

type effectCloseVectorFile struct {
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

type effectCloseSignedVector struct {
	Artifact       effectCloseVectorFile `json:"artifact"`
	Envelope       effectCloseVectorFile `json:"envelope,omitempty"`
	SigningPayload effectCloseVectorFile `json:"signing_payload"`
	PublicKey      string                `json:"public_key"`
	Signature      string                `json:"signature"`
	KeyNotBefore   string                `json:"key_not_before"`
	KeyNotAfter    string                `json:"key_not_after"`
}

type effectCloseNegativeVector struct {
	ID            string `json:"id"`
	Mutation      string `json:"mutation"`
	ExpectedError string `json:"expected_error"`
}

type effectCloseVectorIndex struct {
	Comment         string                      `json:"$comment"`
	SchemaVersion   string                      `json:"schema_version"`
	ContractVersion string                      `json:"contract_version"`
	QuantumPosture  string                      `json:"quantum_posture"`
	Acknowledgement effectCloseSignedVector     `json:"acknowledgement"`
	Receipt         effectCloseSignedVector     `json:"receipt"`
	NegativeVectors []effectCloseNegativeVector `json:"negative_vectors"`
}

func TestEffectCloseSchemas(t *testing.T) {
	root := effectCloseRepoRoot(t)
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	for _, name := range []string{
		"connector_effect_acknowledgement.json",
		"connector_effect_acknowledgement_envelope.json",
		"effect_close_receipt.json",
		"connector_effect_acknowledgement_v2.json",
		"connector_effect_acknowledgement_envelope_v2.json",
		"effect_close_receipt_v2.json",
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
	ackSchema, err := compiler.Compile(effectCloseFileURL(filepath.Join(root, "schemas", "connector_effect_acknowledgement.json")))
	if err != nil {
		t.Fatal(err)
	}
	envelopeSchema, err := compiler.Compile(effectCloseFileURL(filepath.Join(root, "schemas", "connector_effect_acknowledgement_envelope.json")))
	if err != nil {
		t.Fatal(err)
	}
	receiptSchema, err := compiler.Compile(effectCloseFileURL(filepath.Join(root, "schemas", "effect_close_receipt.json")))
	if err != nil {
		t.Fatal(err)
	}
	ackSchemaV2, err := compiler.Compile(effectCloseFileURL(filepath.Join(root, "schemas", "connector_effect_acknowledgement_v2.json")))
	if err != nil {
		t.Fatal(err)
	}
	envelopeSchemaV2, err := compiler.Compile(effectCloseFileURL(filepath.Join(root, "schemas", "connector_effect_acknowledgement_envelope_v2.json")))
	if err != nil {
		t.Fatal(err)
	}
	receiptSchemaV2, err := compiler.Compile(effectCloseFileURL(filepath.Join(root, "schemas", "effect_close_receipt_v2.json")))
	if err != nil {
		t.Fatal(err)
	}
	packRoot := filepath.Join(root, "reference_packs", "effect-close-v1")
	for schema, filename := range map[*jsonschema.Schema]string{
		ackSchema: "acknowledgement.c14n.json", envelopeSchema: "acknowledgement_envelope.c14n.json",
		receiptSchema: "receipt.c14n.json",
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
	packRootV2 := filepath.Join(root, "reference_packs", "effect-close-v2")
	for schema, filename := range map[*jsonschema.Schema]string{
		ackSchemaV2: "acknowledgement.c14n.json", envelopeSchemaV2: "acknowledgement_envelope.c14n.json",
		receiptSchemaV2: "receipt.c14n.json",
	} {
		payload, err := os.ReadFile(filepath.Join(packRootV2, filename))
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(payload, &value); err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(value); err != nil {
			t.Fatalf("v2 %s schema validation: %v", filename, err)
		}
	}
}

func effectCloseCanonical(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := canonicalize.JCS(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func effectCloseVectorHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func effectCloseVectorSHA(value string) string {
	return effectCloseVectorHash([]byte(value))
}

func effectCloseRepoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "..", ".."))
}

func effectCloseFileURL(filename string) string {
	return "file:///" + strings.ReplaceAll(filename, string(filepath.Separator), "/")
}
