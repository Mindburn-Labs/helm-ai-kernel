package contracts_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// repoRoot returns the root of the helm-ai-kernel repository by walking up
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

	t.Run("ExecutePayment_requires_payee_positive_amount_and_ap2_binding", func(t *testing.T) {
		schema := compileSchema(t, "effects/execute_payment_effect.v1.json")
		valid := map[string]interface{}{
			"effect_id":            "EXECUTE_PAYMENT",
			"amount":               12.34,
			"currency":             "USD",
			"payee":                "wallet:treasury:vendor-001",
			"payment_request_hash": "sha256:" + strings.Repeat("a", 64),
			"ap2_receipt_id":       "ap2-rcpt-001",
			"budget_receipt_id":    "budget-rcpt-001",
		}
		clone := func(input map[string]interface{}) map[string]interface{} {
			t.Helper()
			data, err := json.Marshal(input)
			if err != nil {
				t.Fatalf("marshal clone: %v", err)
			}
			var out map[string]interface{}
			if err := json.Unmarshal(data, &out); err != nil {
				t.Fatalf("unmarshal clone: %v", err)
			}
			return out
		}
		if err := schema.Validate(valid); err != nil {
			t.Fatalf("valid execute-payment effect should validate: %v", err)
		}
		for name, mutate := range map[string]func(map[string]interface{}){
			"missing_payee": func(v map[string]interface{}) { delete(v, "payee") },
			"zero_amount":   func(v map[string]interface{}) { v["amount"] = 0 },
			"bad_currency":  func(v map[string]interface{}) { v["currency"] = "usd" },
			"bad_hash":      func(v map[string]interface{}) { v["payment_request_hash"] = "sha256:bad" },
			"missing_ap2":   func(v map[string]interface{}) { delete(v, "ap2_receipt_id") },
		} {
			t.Run(name, func(t *testing.T) {
				candidate := clone(valid)
				mutate(candidate)
				if err := schema.Validate(candidate); err == nil {
					t.Fatalf("expected %s to fail schema validation", name)
				}
			})
		}
	})

	t.Run("AuthorityEvaluation_top_level_binds_request_or_decision", func(t *testing.T) {
		schema := compileSchema(t, "authority/authority_evaluation.v1.schema.json")
		now := time.Now().UTC().Format(time.RFC3339)
		request := map[string]interface{}{
			"request_id":     "auth-req-001",
			"principal_id":   "principal-1",
			"principal_type": "user",
			"effect_types":   []interface{}{"EXECUTE_PAYMENT"},
			"policy_epoch":   "epoch-1",
			"timestamp":      now,
		}
		decision := map[string]interface{}{
			"decision_id":  "auth-dec-001",
			"request_id":   "auth-req-001",
			"result":       "DENY",
			"policy_epoch": "epoch-1",
			"issued_at":    now,
			"content_hash": "sha256:" + strings.Repeat("b", 64),
		}
		if err := schema.Validate(request); err != nil {
			t.Fatalf("authority request should validate: %v", err)
		}
		if err := schema.Validate(decision); err != nil {
			t.Fatalf("authority decision should validate: %v", err)
		}
		inert := map[string]interface{}{"unexpected": "accepted-before"}
		if err := schema.Validate(inert); err == nil {
			t.Fatal("expected inert authority object to fail top-level schema validation")
		}
		smuggled := map[string]interface{}{
			"request_id":     "auth-req-001",
			"principal_id":   "principal-1",
			"principal_type": "user",
			"effect_types":   []interface{}{"EXECUTE_PAYMENT"},
			"policy_epoch":   "epoch-1",
			"timestamp":      now,
			"admin_override": true,
		}
		if err := schema.Validate(smuggled); err == nil {
			t.Fatal("expected authority request with extra top-level claim to fail")
		}
	})

	t.Run("ModuleAttestation_requires_valid_commit_hash", func(t *testing.T) {
		schema := compileSchema(t, "certification/module_attestation.schema.json")
		valid := map[string]interface{}{
			"attestation_id": "550e8400-e29b-41d4-a716-446655440000",
			"module": map[string]interface{}{
				"module_id":     "module-1",
				"artifact_hash": "sha256:" + strings.Repeat("a", 64),
				"manifest_hash": "sha256:" + strings.Repeat("b", 64),
				"commit_hash":   strings.Repeat("c", 40),
			},
			"provenance": map[string]interface{}{
				"builder_id":        "builder-1",
				"build_timestamp":   time.Now().UTC().Format(time.RFC3339),
				"build_config_hash": "sha256:" + strings.Repeat("d", 64),
			},
			"certification": map[string]interface{}{
				"schema_conformance":   map[string]interface{}{"passed": true},
				"determinism_tests":    map[string]interface{}{"passed": true},
				"permissions_declared": map[string]interface{}{"effect_types": []interface{}{"EXECUTE_PAYMENT"}},
			},
			"signatures": []interface{}{
				map[string]interface{}{
					"signer_id": "certifier-1",
					"signature": "base64-signature",
					"signed_at": time.Now().UTC().Format(time.RFC3339),
				},
			},
		}
		clone := func(input map[string]interface{}) map[string]interface{} {
			t.Helper()
			data, err := json.Marshal(input)
			if err != nil {
				t.Fatalf("marshal clone: %v", err)
			}
			var out map[string]interface{}
			if err := json.Unmarshal(data, &out); err != nil {
				t.Fatalf("unmarshal clone: %v", err)
			}
			return out
		}
		if err := schema.Validate(valid); err != nil {
			t.Fatalf("valid module attestation should validate: %v", err)
		}
		missing := clone(valid)
		delete(missing["module"].(map[string]interface{}), "commit_hash")
		if err := schema.Validate(missing); err == nil {
			t.Fatal("expected missing commit_hash to fail")
		}
		bad := clone(valid)
		bad["module"].(map[string]interface{})["commit_hash"] = "not-a-git-sha"
		if err := schema.Validate(bad); err == nil {
			t.Fatal("expected malformed commit_hash to fail")
		}
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

	t.Run("PrivilegedAccessReceipt_requires_signed_closed_grant", func(t *testing.T) {
		schema := compileSchema(t, "access/PrivilegedAccessReceipt.v1.json")
		now := time.Now().UTC()
		valid := map[string]interface{}{
			"version":    "1.0.0",
			"receipt_id": "prec-prod-root",
			"request_id": "preq-001",
			"grant": map[string]interface{}{
				"granted_tier": "breakglass",
				"granted_at":   now.Format(time.RFC3339),
				"expires_at":   now.Add(time.Hour).Format(time.RFC3339),
				"granted_by":   []interface{}{"did:helm:approver#key-1"},
				"granted_scope": map[string]interface{}{
					"actions": []interface{}{"deploy"},
				},
			},
			"grantee": map[string]interface{}{
				"identity_id": "did:helm:operator#key-1",
			},
			"attestation": map[string]interface{}{
				"hash":      "sha256:" + strings.Repeat("a", 64),
				"algorithm": "sha256",
				"signature": "ed25519:" + strings.Repeat("A", 86),
				"signed_by": "did:helm:approver#key-1",
				"timestamp": now.Format(time.RFC3339),
			},
		}

		clone := func(input map[string]interface{}) map[string]interface{} {
			t.Helper()
			data, err := json.Marshal(input)
			if err != nil {
				t.Fatalf("marshal clone: %v", err)
			}
			var out map[string]interface{}
			if err := json.Unmarshal(data, &out); err != nil {
				t.Fatalf("unmarshal clone: %v", err)
			}
			return out
		}

		if err := schema.Validate(valid); err != nil {
			t.Fatalf("signed privileged access receipt should validate: %v", err)
		}

		missingGrantee := clone(valid)
		delete(missingGrantee, "grantee")
		if err := schema.Validate(missingGrantee); err == nil {
			t.Fatal("expected missing grantee to fail schema validation")
		}

		unsigned := clone(valid)
		attestation := unsigned["attestation"].(map[string]interface{})
		delete(attestation, "signature")
		delete(attestation, "signed_by")
		if err := schema.Validate(unsigned); err == nil {
			t.Fatal("expected unsigned receipt attestation to fail schema validation")
		}

		grantSmuggle := clone(valid)
		grantSmuggle["grant"].(map[string]interface{})["admin_override"] = true
		if err := schema.Validate(grantSmuggle); err == nil {
			t.Fatal("expected extra grant claim to fail schema validation")
		}

		attestationSmuggle := clone(valid)
		attestationSmuggle["attestation"].(map[string]interface{})["claims"] = map[string]interface{}{"role": "root"}
		if err := schema.Validate(attestationSmuggle); err == nil {
			t.Fatal("expected extra attestation claim to fail schema validation")
		}

		badSignature := clone(valid)
		badSignature["attestation"].(map[string]interface{})["signature"] = "unsigned"
		if err := schema.Validate(badSignature); err == nil {
			t.Fatal("expected malformed signature to fail schema validation")
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
