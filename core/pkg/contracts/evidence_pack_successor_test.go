package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEvidencePackSuccessorKindsSealAndPreserveFrozenIdentity(t *testing.T) {
	lineage := testEvidencePackLineage()
	predecessorRef := "evidence-pack:effect-1"
	predecessorHash := testEvidencePackSHA("sealed-effect-pack")

	for _, kind := range []EvidencePackSuccessorKind{
		EvidencePackSuccessorOperationalEvaluation,
		EvidencePackSuccessorMeasurementProgress,
		EvidencePackSuccessorMeasurementFinal,
		EvidencePackSuccessorMeasurementCensored,
	} {
		t.Run(string(kind), func(t *testing.T) {
			candidate := testEvidencePackSuccessor(kind, predecessorRef, predecessorHash, lineage)
			sealed, err := candidate.Seal()
			if err != nil {
				t.Fatalf("Seal(): %v", err)
			}
			if !isApprovalGrantSHA256(sealed.SuccessorID) || !isApprovalGrantSHA256(sealed.SuccessorHash) {
				t.Fatalf("sealed identity is not content-addressed: %+v", sealed)
			}
			if sealed.Lineage != lineage {
				t.Fatalf("frozen lineage changed: got %+v want %+v", sealed.Lineage, lineage)
			}
			if err := sealed.ValidateIntegrity(); err != nil {
				t.Fatalf("ValidateIntegrity(): %v", err)
			}
			if got := sealed.FinalizesMeasurement(); got != (kind == EvidencePackSuccessorMeasurementFinal || kind == EvidencePackSuccessorMeasurementCensored) {
				t.Fatalf("FinalizesMeasurement() = %v for %s", got, kind)
			}
		})
	}
}

func TestEvidencePackSuccessorIdentityUsesKindContractWindowAndPredecessor(t *testing.T) {
	lineage := testEvidencePackLineage()
	base := testEvidencePackSuccessor(
		EvidencePackSuccessorOperationalEvaluation,
		"evidence-pack:effect-1",
		testEvidencePackSHA("sealed-effect-pack"),
		lineage,
	)
	sealed, err := base.Seal()
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*EvidencePackSuccessor){
		"predecessor": func(value *EvidencePackSuccessor) { value.PredecessorHash = testEvidencePackSHA("other-predecessor") },
		"kind":        func(value *EvidencePackSuccessor) { value.Kind = EvidencePackSuccessorMeasurementProgress },
		"outcome contract": func(value *EvidencePackSuccessor) {
			value.Lineage.OutcomeContractHash = testEvidencePackSHA("other-outcome-contract")
		},
		"window": func(value *EvidencePackSuccessor) { value.Lineage.WindowIdentity = "window:other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			other, sealErr := changed.Seal()
			if sealErr != nil {
				t.Fatalf("Seal(): %v", sealErr)
			}
			if other.SuccessorID == sealed.SuccessorID {
				t.Fatalf("identity did not change after %s mutation", name)
			}
		})
	}

	measurement := testEvidencePackSuccessor(
		EvidencePackSuccessorMeasurementFinal,
		"successor:operational",
		testEvidencePackSHA("operational-successor"),
		lineage,
	)
	measurementSealed, err := measurement.Seal()
	if err != nil {
		t.Fatal(err)
	}
	measurement.Lineage.MeasurementPlanHash = testEvidencePackSHA("other-measurement-plan")
	measurementChanged, err := measurement.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if measurementSealed.SuccessorID == measurementChanged.SuccessorID {
		t.Fatal("measurement successor identity did not bind measurement_plan_hash")
	}
}

func TestEvidencePackSuccessorIntegrityRejectsSemanticMutation(t *testing.T) {
	sealed, err := testEvidencePackSuccessor(
		EvidencePackSuccessorMeasurementProgress,
		"successor:operational",
		testEvidencePackSHA("operational-successor"),
		testEvidencePackLineage(),
	).Seal()
	if err != nil {
		t.Fatal(err)
	}

	mutated := sealed
	mutated.EvidenceHash = testEvidencePackSHA("different-progress-evidence")
	if err := mutated.ValidateIntegrity(); !errors.Is(err, ErrEvidencePackSuccessorIntegrity) {
		t.Fatalf("tampered evidence error = %v", err)
	}

	mutated = sealed
	mutated.Lineage.ActivationRecordHash = testEvidencePackSHA("different-activation")
	if err := mutated.ValidateIntegrity(); !errors.Is(err, ErrEvidencePackSuccessorIntegrity) {
		t.Fatalf("tampered frozen lineage error = %v", err)
	}
}

func TestDecodeEvidencePackSuccessorIsStrictAndSerializationIndependent(t *testing.T) {
	sealed, err := testEvidencePackSuccessor(
		EvidencePackSuccessorMeasurementCensored,
		"successor:operational",
		testEvidencePackSHA("operational-successor"),
		testEvidencePackLineage(),
	).Seal()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEvidencePackSuccessor(payload)
	if err != nil {
		t.Fatalf("DecodeEvidencePackSuccessor(): %v", err)
	}
	if decoded.SuccessorHash != sealed.SuccessorHash || decoded.SuccessorID != sealed.SuccessorID {
		t.Fatalf("equivalent serialization changed identity: got %+v want %+v", decoded, sealed)
	}

	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	object["unbound_extension"] = true
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeEvidencePackSuccessor(unknown); !errors.Is(err, ErrEvidencePackSuccessorInvalid) || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown extension error = %v", err)
	}
	if _, err := DecodeEvidencePackSuccessor(append(payload, []byte(" {}")...)); !errors.Is(err, ErrEvidencePackSuccessorInvalid) {
		t.Fatalf("trailing JSON error = %v", err)
	}
}

func TestEvidencePackLineageRejectsIncompleteOrUnsafeBindings(t *testing.T) {
	valid := testEvidencePackLineage()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid lineage: %v", err)
	}

	for name, mutate := range map[string]func(*EvidencePackLineage){
		"cross company":       func(value *EvidencePackLineage) { value.CompanyID = "other-company" },
		"missing activation":  func(value *EvidencePackLineage) { value.ActivationRecordHash = "" },
		"malformed outcome":   func(value *EvidencePackLineage) { value.OutcomeContractHash = "sha256:bad" },
		"missing measurement": func(value *EvidencePackLineage) { value.MeasurementPlanRef = "" },
		"unsafe window":       func(value *EvidencePackLineage) { value.WindowIdentity = "window with spaces" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrEvidencePackSuccessorInvalid) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestEvidencePackJSONCarriesFrozenLineageAdditively(t *testing.T) {
	lineage := testEvidencePackLineage()
	pack := EvidencePack{PackID: "pack-1", FormatVersion: "v1", Lineage: &lineage}
	payload, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(`"lineage"`)) || !bytes.Contains(payload, []byte(lineage.MeasurementPlanHash)) {
		t.Fatalf("lineage missing from EvidencePack JSON: %s", payload)
	}
	var legacy EvidencePack
	if err := json.Unmarshal([]byte(`{"pack_id":"legacy","format_version":"v1"}`), &legacy); err != nil {
		t.Fatalf("legacy EvidencePack no longer decodes: %v", err)
	}
	if legacy.Lineage != nil {
		t.Fatal("legacy EvidencePack unexpectedly gained lineage")
	}
}

func TestEvidencePackSealHashBindsFrozenLineage(t *testing.T) {
	lineage := testEvidencePackLineage()
	pack := &EvidencePack{
		PackID: "pack-1", FormatVersion: "1.0.0",
		CreatedAt: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
		Identity:  EvidencePackIdentity{ActorID: "actor-1", ActorType: "control_loop"},
		Policy:    EvidencePackPolicy{DecisionID: "decision-1", PolicyVersion: "v1", RulesFired: []string{}},
		Effect:    EvidencePackEffect{EffectID: "effect-1", EffectType: "CRM_UPDATE"},
		Execution: EvidencePackExecution{
			ExecutionID: "execution-1", Status: "success",
		},
		Lineage: &lineage,
	}
	sealedHash, err := ComputeEvidencePackHash(pack)
	if err != nil {
		t.Fatal(err)
	}
	pack.Lineage.OutcomeContractHash = testEvidencePackSHA("mutated-outcome-contract")
	mutatedHash, err := ComputeEvidencePackHash(pack)
	if err != nil {
		t.Fatal(err)
	}
	if mutatedHash == sealedHash {
		t.Fatal("frozen lineage mutation did not change the EvidencePack seal hash")
	}
}

func testEvidencePackLineage() EvidencePackLineage {
	return EvidencePackLineage{
		SchemaVersion:        EvidencePackLineageSchemaV1,
		TenantID:             "tenant-a",
		CompanyID:            "tenant-a",
		WorkspaceID:          "workspace-a",
		EnvironmentID:        "staging-a",
		ActivationRecordRef:  "activation:company-a",
		ActivationRecordHash: testEvidencePackSHA("activation-record"),
		OutcomeContractRef:   "outcome-contract:crm-hygiene",
		OutcomeContractHash:  testEvidencePackSHA("outcome-contract"),
		MeasurementPlanRef:   "measurement-plan:crm-hygiene",
		MeasurementPlanHash:  testEvidencePackSHA("measurement-plan"),
		WindowIdentity:       "window:crm-hygiene:2026-09",
	}
}

func testEvidencePackSuccessor(kind EvidencePackSuccessorKind, predecessorRef, predecessorHash string, lineage EvidencePackLineage) EvidencePackSuccessor {
	return EvidencePackSuccessor{
		SchemaVersion:   EvidencePackSuccessorSchemaV1,
		ContractVersion: EvidencePackSuccessorContractV1,
		Kind:            kind,
		PredecessorRef:  predecessorRef,
		PredecessorHash: predecessorHash,
		SealedPackRef:   "evidence-pack:effect-1",
		SealedPackHash:  testEvidencePackSHA("sealed-effect-pack"),
		Lineage:         lineage,
		EvidenceRef:     "evidence:" + strings.ToLower(string(kind)),
		EvidenceHash:    testEvidencePackSHA("evidence-" + string(kind)),
		RecordedAt:      time.Date(2026, 9, 4, 12, 0, 0, 123456000, time.UTC),
	}
}

func testEvidencePackSHA(value string) string {
	hash, err := hashJCS(struct {
		Value string `json:"value"`
	}{Value: value})
	if err != nil {
		panic(err)
	}
	return hash
}
