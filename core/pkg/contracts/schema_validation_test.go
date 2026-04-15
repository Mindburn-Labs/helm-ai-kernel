package contracts_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// repoRoot returns the root of the helm-oss repository by walking up
// from this test file's location (core/pkg/contracts/).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
}

// compileSchema loads and compiles a JSON schema from the protocols directory.
func compileSchema(t *testing.T, relPath string) *jsonschema.Schema {
	t.Helper()
	root := repoRoot(t)
	schemaPath := filepath.Join(root, "protocols", "json-schemas", relPath)

	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("cannot read schema %s: %v", relPath, err)
	}

	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft2020
	url := "file:///" + strings.ReplaceAll(schemaPath, string(filepath.Separator), "/")
	if err := c.AddResource(url, strings.NewReader(string(data))); err != nil {
		t.Fatalf("cannot add schema resource %s: %v", relPath, err)
	}

	schema, err := c.Compile(url)
	if err != nil {
		t.Fatalf("cannot compile schema %s: %v", relPath, err)
	}
	return schema
}

// validateAgainstSchema marshals a Go struct to JSON and validates it against
// the given compiled schema. Returns nil on success.
func validateAgainstSchema(t *testing.T, schema *jsonschema.Schema, v interface{}) error {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal into interface{} failed: %v", err)
	}

	return schema.Validate(raw)
}

// TestSchemaAlignment enforces that Go structs match their JSON Schema definitions.
// It creates representative instances, marshals them to JSON, and validates
// against the canonical JSON schemas in protocols/json-schemas/.
func TestSchemaAlignment(t *testing.T) {
	root := repoRoot(t)

	// Guard: verify the schemas directory is reachable.
	schemasDir := filepath.Join(root, "protocols", "json-schemas")
	if _, err := os.Stat(schemasDir); err != nil {
		t.Skipf("JSON schemas directory not found at %s: %v", schemasDir, err)
	}

	t.Run("Receipt_v2", func(t *testing.T) {
		schema := compileSchema(t, "receipt/v2.json")

		receipt := contracts.Receipt{
			ReceiptID:           "rcpt_001",
			DecisionID:          "dec_001",
			EffectID:            "eff_001",
			ExternalReferenceID: "ext_001",
			Status:              "SUCCESS",
			BlobHash:            "abc123",
			OutputHash:          "def456",
			Timestamp:           time.Now().UTC(),
			ExecutorID:          "exec_001",
			Metadata:            map[string]any{"key": "value"},
			MerkleRoot:          "merkle_root_hash",
			WitnessSignatures: []contracts.WitnessSignature{
				{WitnessID: "w1", Signature: "sig1"},
			},
		}

		if err := validateAgainstSchema(t, schema, receipt); err != nil {
			t.Errorf("Receipt does not match receipt/v2.json schema: %v", err)
		}
	})

	t.Run("Receipt_v2_required_fields_only", func(t *testing.T) {
		schema := compileSchema(t, "receipt/v2.json")

		// Minimal receipt with only required fields.
		receipt := struct {
			ReceiptID  string `json:"receipt_id"`
			DecisionID string `json:"decision_id"`
			EffectID   string `json:"effect_id"`
			Status     string `json:"status"`
			Timestamp  string `json:"timestamp"`
		}{
			ReceiptID:  "rcpt_min",
			DecisionID: "dec_min",
			EffectID:   "eff_min",
			Status:     "SUCCESS",
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
		}

		if err := validateAgainstSchema(t, schema, receipt); err != nil {
			t.Errorf("Minimal receipt does not match receipt/v2.json schema: %v", err)
		}
	})

	t.Run("Receipt_v2_rejects_invalid_status", func(t *testing.T) {
		schema := compileSchema(t, "receipt/v2.json")

		// The schema constrains status to an enum.
		invalid := struct {
			ReceiptID  string `json:"receipt_id"`
			DecisionID string `json:"decision_id"`
			EffectID   string `json:"effect_id"`
			Status     string `json:"status"`
			Timestamp  string `json:"timestamp"`
		}{
			ReceiptID:  "rcpt_bad",
			DecisionID: "dec_bad",
			EffectID:   "eff_bad",
			Status:     "INVALID_STATUS",
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
		}

		if err := validateAgainstSchema(t, schema, invalid); err == nil {
			t.Error("Expected schema validation to reject invalid status enum, but it passed")
		}
	})

	t.Run("IntentTicket_v1", func(t *testing.T) {
		schemaPath := filepath.Join(root, "protocols", "json-schemas", "intent", "intent_ticket.v1.schema.json")
		if _, err := os.Stat(schemaPath); err != nil {
			t.Skip("intent_ticket.v1.schema.json not found")
		}

		schema := compileSchema(t, "intent/intent_ticket.v1.schema.json")

		// The IntentTicket schema requires ticket_id, intent, created_at, principal.
		ticket := map[string]interface{}{
			"ticket_id":  "550e8400-e29b-41d4-a716-446655440000",
			"intent":     "Launch an e-commerce store selling organic tea",
			"created_at": time.Now().UTC().Format(time.RFC3339),
			"principal": map[string]interface{}{
				"principal_id":   "user_123",
				"principal_type": "individual",
			},
		}

		if err := schema.Validate(ticket); err != nil {
			t.Errorf("IntentTicket does not match schema: %v", err)
		}
	})

	t.Run("EffectTypeCatalog_schema_parseable", func(t *testing.T) {
		schemaPath := filepath.Join(root, "protocols", "json-schemas", "effects", "effect_type_catalog.schema.json")
		if _, err := os.Stat(schemaPath); err != nil {
			t.Skip("effect_type_catalog.schema.json not found")
		}
		// Just verifying the schema itself is valid JSON and compiles.
		compileSchema(t, "effects/effect_type_catalog.schema.json")
	})

	t.Run("AccessRequest_field_names", func(t *testing.T) {
		// Verify that AccessRequest marshals with expected JSON field names.
		req := contracts.AccessRequest{
			PrincipalID: "principal_1",
			Action:      "read",
			ResourceID:  "resource_1",
			Context:     map[string]interface{}{"env": "prod"},
		}

		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}

		var fields map[string]interface{}
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}

		expectedFields := []string{"principal_id", "action", "resource_id", "context"}
		for _, f := range expectedFields {
			if _, ok := fields[f]; !ok {
				t.Errorf("AccessRequest JSON missing expected field %q", f)
			}
		}
	})

	t.Run("DecisionRecord_field_names", func(t *testing.T) {
		// Verify that DecisionRecord marshals with expected JSON field names
		// that align with decision.proto.
		dr := contracts.DecisionRecord{
			ID:            "dec_1",
			ProposalID:    "prop_1",
			StepID:        "step_1",
			SubjectID:     "subj_1",
			Action:        "write",
			Resource:      "file.txt",
			Verdict:       "ALLOW",
			Reason:        "Policy allows",
			Signature:     "sig_abc",
			SignatureType: "ed25519",
			Timestamp:     time.Now().UTC(),
		}

		data, err := json.Marshal(dr)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}

		var fields map[string]interface{}
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}

		required := []string{
			"id", "proposal_id", "step_id", "subject_id",
			"action", "resource", "verdict", "reason",
			"signature", "signature_type", "timestamp",
		}
		for _, f := range required {
			if _, ok := fields[f]; !ok {
				t.Errorf("DecisionRecord JSON missing expected field %q", f)
			}
		}

		// Verify verdict is one of the canonical values.
		verdict, _ := fields["verdict"].(string)
		validVerdicts := map[string]bool{"ALLOW": true, "DENY": true, "ESCALATE": true}
		if !validVerdicts[verdict] {
			t.Errorf("DecisionRecord verdict %q not in canonical set {ALLOW, DENY, ESCALATE}", verdict)
		}
	})

	t.Run("Receipt_roundtrip_determinism", func(t *testing.T) {
		// Verify that Receipt JSON roundtrip is deterministic (important for hashing).
		receipt := contracts.Receipt{
			ReceiptID:  "rcpt_det",
			DecisionID: "dec_det",
			EffectID:   "eff_det",
			Status:     "SUCCESS",
			Timestamp:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Metadata:   map[string]any{"a": "1", "b": "2", "c": "3"},
		}

		data1, _ := json.Marshal(receipt)
		data2, _ := json.Marshal(receipt)

		if string(data1) != string(data2) {
			t.Error("Receipt JSON marshaling is not deterministic")
		}
	})
}
