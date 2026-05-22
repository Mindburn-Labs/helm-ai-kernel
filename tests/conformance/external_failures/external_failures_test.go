package externalfailures

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

type replayPack struct {
	ID                    string            `json:"id"`
	Title                 string            `json:"title"`
	FailureModes          []string          `json:"failure_modes"`
	HelmControls          []string          `json:"helm_controls"`
	CounterfactualVerdict string            `json:"counterfactual_verdict"`
	ReasonCodes           []string          `json:"reason_codes"`
	CounterfactualClaim   string            `json:"counterfactual_claim"`
	Evidence              map[string]string `json:"evidence"`
	Receipt               replayReceipt     `json:"receipt"`
	Verification          map[string]string `json:"verification"`
	Limits                []string          `json:"limits"`
	SourceAssertions      []sourceAssertion `json:"source_assertions"`
	GeneratedVectors      []vector          `json:"generated_vectors"`
}

type replayReceipt struct {
	Type              string   `json:"type"`
	Verdict           string   `json:"verdict"`
	BeforeDispatch    bool     `json:"before_dispatch"`
	DispatchAttempted bool     `json:"dispatch_attempted"`
	ReasonCodes       []string `json:"reason_codes"`
}

type sourceAssertion struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	SourceURL   string `json:"source_url"`
	Title       string `json:"title"`
	Claim       string `json:"claim"`
	ContentHash string `json:"content_hash"`
}

type vector struct {
	ID                 string `json:"id"`
	FailureMode        string `json:"failure_mode"`
	Title              string `json:"title"`
	Template           string `json:"template"`
	ExpectedVerdict    string `json:"expected_verdict"`
	ExpectedReasonCode string `json:"expected_reason_code"`
	MustEmitReceipt    bool   `json:"must_emit_receipt"`
	MustNotDispatch    bool   `json:"must_not_dispatch"`
	MustBindEvidence   bool   `json:"must_bind_evidence"`
}

func TestExternalFailureReplayReferencePacksAreConformanceVectors(t *testing.T) {
	root := filepath.Join("..", "..", "..", "reference_packs", "proof_replays")
	entries, err := filepath.Glob(filepath.Join(root, "HPR-*", "replay.json"))
	if err != nil {
		t.Fatalf("glob replay packs: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one external failure replay reference pack")
	}

	for _, path := range entries {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read replay pack: %v", err)
			}
			var pack replayPack
			if err := json.Unmarshal(raw, &pack); err != nil {
				t.Fatalf("parse replay pack: %v", err)
			}
			assertReplayPack(t, pack)
			validateCounterfactualReplaySchema(t, raw)
		})
	}
}

func assertReplayPack(t *testing.T, pack replayPack) {
	t.Helper()
	if !strings.HasPrefix(pack.ID, "HPR-") {
		t.Fatalf("replay id %q must use HPR prefix", pack.ID)
	}
	if strings.Contains(strings.ToLower(pack.CounterfactualClaim), "prevented the real incident") {
		t.Fatalf("%s overclaims real-world prevention", pack.ID)
	}
	if !strings.Contains(pack.CounterfactualClaim, "modeled action produced") || !strings.Contains(pack.CounterfactualClaim, "before side-effect dispatch") {
		t.Fatalf("%s missing counterfactual verdict wording", pack.ID)
	}
	if pack.CounterfactualVerdict != "ALLOW" && pack.CounterfactualVerdict != "DENY" && pack.CounterfactualVerdict != "ESCALATE" {
		t.Fatalf("%s verdict = %s, want ALLOW, DENY, or ESCALATE", pack.ID, pack.CounterfactualVerdict)
	}
	if len(pack.FailureModes) == 0 || len(pack.HelmControls) == 0 || len(pack.ReasonCodes) == 0 {
		t.Fatalf("%s must bind modes, controls, and reason codes", pack.ID)
	}
	for key, value := range pack.Evidence {
		if !strings.HasPrefix(value, "sha256:") {
			t.Fatalf("%s evidence %s missing sha256 prefix", pack.ID, key)
		}
	}
	if pack.Receipt.Type != "KERNEL_VERDICT" || !pack.Receipt.BeforeDispatch || pack.Receipt.DispatchAttempted {
		t.Fatalf("%s receipt must be a pre-dispatch KERNEL_VERDICT with no dispatch", pack.ID)
	}
	if len(pack.SourceAssertions) == 0 {
		t.Fatalf("%s must include public source assertions", pack.ID)
	}
	for _, assertion := range pack.SourceAssertions {
		if assertion.SourceURL == "" || assertion.Claim == "" || !strings.HasPrefix(assertion.ContentHash, "sha256:") {
			t.Fatalf("%s source assertion is incomplete: %+v", pack.ID, assertion)
		}
	}
	if len(pack.GeneratedVectors) == 0 {
		t.Fatalf("%s must include generated conformance vectors", pack.ID)
	}
	for _, vector := range pack.GeneratedVectors {
		if vector.ExpectedVerdict != pack.CounterfactualVerdict {
			t.Fatalf("%s vector %s expected verdict = %s, want %s", pack.ID, vector.ID, vector.ExpectedVerdict, pack.CounterfactualVerdict)
		}
		if !strings.HasPrefix(vector.ID, "HCV-") {
			t.Fatalf("%s vector %s must use HCV prefix", pack.ID, vector.ID)
		}
		if !vector.MustEmitReceipt || !vector.MustNotDispatch || !vector.MustBindEvidence {
			t.Fatalf("%s vector %s must emit receipt, block dispatch, and bind evidence", pack.ID, vector.ID)
		}
	}
}

func validateCounterfactualReplaySchema(t *testing.T, raw []byte) {
	t.Helper()
	schemaRoot := filepath.Join("..", "..", "..", "schemas", "failure_intelligence")
	compiler := jsonschema.NewCompiler()
	for _, name := range []string{
		"failure_mode.v1.json",
		"source_registry.v1.json",
		"source_health.v1.json",
		"source_assertion.v1.json",
		"source_snapshot.v1.json",
		"artifact_ref.v1.json",
		"verification_result.v1.json",
		"run_record.v1.json",
		"export_batch.v1.json",
		"external_incident_candidate.v1.json",
		"helm_control_mapping.v1.json",
		"public_replay_policy.v1.json",
		"counterfactual_replay.v1.json",
		"public_proof_replay.v1.json",
		"conformance_vector.v1.json",
		"publication_gate.v1.json",
	} {
		data, err := os.ReadFile(filepath.Join(schemaRoot, name))
		if err != nil {
			t.Fatalf("read schema %s: %v", name, err)
		}
		if err := compiler.AddResource("https://schemas.helm.ai/failure_intelligence/"+name, bytes.NewReader(data)); err != nil {
			t.Fatalf("add schema %s: %v", name, err)
		}
	}
	schema, err := compiler.Compile("https://schemas.helm.ai/failure_intelligence/counterfactual_replay.v1.json")
	if err != nil {
		t.Fatalf("compile counterfactual replay schema: %v", err)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode replay pack: %v", err)
	}
	if err := schema.Validate(decoded); err != nil {
		t.Fatalf("replay pack does not validate against counterfactual schema: %v", err)
	}
}
