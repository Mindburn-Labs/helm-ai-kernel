package approvalceremony

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
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

func TestEffectCloseReferencePackMatchesGoImplementation(t *testing.T) {
	files := buildEffectCloseReferencePack(t)
	root := filepath.Join("..", "..", "..", "..", "reference_packs", "effect-close-v1")
	if os.Getenv("UPDATE_EFFECT_CLOSE_VECTORS") == "1" {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("create effect close reference pack: %v", err)
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(root, name), content, 0o644); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s differs from source-owned Go fixture; run UPDATE_EFFECT_CLOSE_VECTORS=1 go test ./pkg/boundary/approvalceremony -run TestEffectCloseReferencePackMatchesGoImplementation", name)
		}
	}
}

func buildEffectCloseReferencePack(t *testing.T) map[string][]byte {
	t.Helper()
	observedAt := time.Date(2026, 7, 18, 12, 0, 0, 123456000, time.UTC)
	acknowledgement, err := (contracts.ConnectorEffectAcknowledgement{
		SchemaVersion:     contracts.ConnectorEffectAcknowledgementSchemaV1,
		ContractVersion:   contracts.ConnectorEffectAcknowledgementContractV1,
		AcknowledgementID: "effect-ack-vector-a", AdmissionID: "dispatch-admission-vector-a",
		AttemptID: "attempt-vector-a", TenantID: "tenant-a", WorkspaceID: "workspace-a",
		Audience: "packs.lifecycle", ConnectorID: "github", ConnectorVersion: "1.0.0",
		ConnectorAction: "github.create_issue", ConnectorExecutionRef: "github-request-vector-a",
		ProofSessionRef: "proof-session-vector-a", IntentRef: "intent-vector-a",
		IdempotencyKeyHash: effectCloseVectorSHA("idempotency"), EffectHash: effectCloseVectorSHA("effect"),
		Outcome: contracts.ConnectorEffectOutcomeApplied, ResponseHash: effectCloseVectorSHA("response"),
		EffectRef: "github-issue-42", ReconciliationRef: "reconciliation-vector-a",
		DispositionReceiptHash: effectCloseVectorSHA("disposition-receipt"),
		IssuerID: "publisher-a", SigningKeyRef: "kms://helm/connector-ack/key-a",
		Algorithm: contracts.ConnectorEffectAcknowledgementAlgorithm, ObservedAt: observedAt,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	ackSigner := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, ed25519.SeedSize)), "effect-ack-vector",
	)
	ackEnvelope, err := SignConnectorEffectAcknowledgement(acknowledgement, ackSigner)
	if err != nil {
		t.Fatal(err)
	}
	ackJSON := effectCloseCanonical(t, acknowledgement)
	ackEnvelopeJSON := effectCloseCanonical(t, ackEnvelope)
	ackPayload, err := ConnectorEffectAcknowledgementSigningPayload(acknowledgement)
	if err != nil {
		t.Fatal(err)
	}

	receipt, err := (contracts.EffectCloseReceipt{
		SchemaVersion: contracts.EffectCloseReceiptSchemaV1, ContractVersion: contracts.EffectCloseReceiptContractV1,
		CloseID: "effect-close-vector-a", State: contracts.EffectCloseReceiptStateClosed,
		AdmissionID: acknowledgement.AdmissionID, AttemptID: acknowledgement.AttemptID,
		TenantID: acknowledgement.TenantID, WorkspaceID: acknowledgement.WorkspaceID, Audience: acknowledgement.Audience,
		ConnectorID: acknowledgement.ConnectorID, ConnectorVersion: acknowledgement.ConnectorVersion,
		ConnectorAction: acknowledgement.ConnectorAction,
		PriorState:      contracts.EffectClosePriorStateUncertain, ReservationSequence: 3,
		ReservationHeadHash: effectCloseVectorSHA("reservation-head"),
		AcknowledgementHash: acknowledgement.AcknowledgementHash, Outcome: acknowledgement.Outcome,
		IdempotencyKeyHash: acknowledgement.IdempotencyKeyHash, EffectHash: acknowledgement.EffectHash,
		ResponseHash: acknowledgement.ResponseHash, ConnectorExecutionRef: acknowledgement.ConnectorExecutionRef,
		ProofSessionRef: acknowledgement.ProofSessionRef, IntentRef: acknowledgement.IntentRef,
		EffectRef: acknowledgement.EffectRef, ReconciliationRef: acknowledgement.ReconciliationRef,
		DispositionReceiptHash: acknowledgement.DispositionReceiptHash,
		EvidencePackRef: "evidence-pack-vector-a", EvidencePackHash: effectCloseVectorSHA("evidence-pack"),
		KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/approval/key-a",
		ClosedBy: "spiffe://helm/data-plane-a", ClosedAt: observedAt.Add(time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	kernelSigner := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{72}, ed25519.SeedSize)), "effect-close-vector",
	)
	receiptSignature, err := SignEffectCloseReceipt(receipt, kernelSigner)
	if err != nil {
		t.Fatal(err)
	}
	receiptJSON := effectCloseCanonical(t, receipt)
	receiptPayload, err := EffectCloseReceiptSigningPayload(receipt, GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}

	index := effectCloseVectorIndex{
		Comment:         "quantum_posture: classical Ed25519 effect acknowledgement and close receipt only; no hybrid or post-quantum claim.",
		SchemaVersion:   "effect-close-vectors.v1",
		ContractVersion: contracts.EffectCloseReceiptContractV1,
		QuantumPosture:  "classical_ed25519_only",
		Acknowledgement: effectCloseSignedVector{
			Artifact:       effectCloseVectorFile{Canonical: "acknowledgement.c14n.json", SHA256: effectCloseVectorHash(ackJSON)},
			Envelope:       effectCloseVectorFile{Canonical: "acknowledgement_envelope.c14n.json", SHA256: effectCloseVectorHash(ackEnvelopeJSON)},
			SigningPayload: effectCloseVectorFile{Canonical: "acknowledgement_signing_payload.c14n.json", SHA256: effectCloseVectorHash(ackPayload)},
			PublicKey:      "ed25519:" + ackSigner.PublicKey(), Signature: "ed25519:" + ackEnvelope.Signature,
			KeyNotBefore: observedAt.Add(-time.Hour).Format(time.RFC3339Nano), KeyNotAfter: observedAt.Add(time.Hour).Format(time.RFC3339Nano),
		},
		Receipt: effectCloseSignedVector{
			Artifact:       effectCloseVectorFile{Canonical: "receipt.c14n.json", SHA256: effectCloseVectorHash(receiptJSON)},
			SigningPayload: effectCloseVectorFile{Canonical: "receipt_signing_payload.c14n.json", SHA256: effectCloseVectorHash(receiptPayload)},
			PublicKey:      "ed25519:" + kernelSigner.PublicKey(), Signature: "ed25519:" + receiptSignature,
			KeyNotBefore: observedAt.Add(-time.Hour).Format(time.RFC3339Nano), KeyNotAfter: observedAt.Add(time.Hour).Format(time.RFC3339Nano),
		},
		NegativeVectors: []effectCloseNegativeVector{
			{ID: "acknowledgement_hash_tamper", Mutation: "set_acknowledgement_response_hash_to_tampered", ExpectedError: "acknowledgement_hash_mismatch"},
			{ID: "acknowledgement_signature_tamper", Mutation: "flip_acknowledgement_signature_last_bit", ExpectedError: "acknowledgement_signature_rejected"},
			{ID: "acknowledgement_key_substitution", Mutation: "set_acknowledgement_signing_key_ref_to_other_and_reseal", ExpectedError: "acknowledgement_trust_rejected"},
			{ID: "receipt_evidence_tamper", Mutation: "set_receipt_evidence_pack_hash_to_tampered", ExpectedError: "receipt_hash_mismatch"},
			{ID: "receipt_acknowledgement_substitution", Mutation: "set_receipt_acknowledgement_hash_to_other_and_reseal", ExpectedError: "acknowledgement_binding_rejected"},
			{ID: "receipt_signature_tamper", Mutation: "flip_receipt_signature_last_bit", ExpectedError: "receipt_signature_rejected"},
			{ID: "receipt_disposition_substitution", Mutation: "set_receipt_disposition_hash_to_other_and_reseal", ExpectedError: "acknowledgement_binding_rejected"},
			{ID: "uncertain_without_reconciliation", Mutation: "remove_receipt_reconciliation_ref_and_reseal", ExpectedError: "receipt_contract_rejected"},
		},
	}
	indexJSON, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"acknowledgement.c14n.json":                 append(ackJSON, '\n'),
		"acknowledgement_envelope.c14n.json":        append(ackEnvelopeJSON, '\n'),
		"acknowledgement_signing_payload.c14n.json": append(ackPayload, '\n'),
		"receipt.c14n.json":                         append(receiptJSON, '\n'),
		"receipt_signing_payload.c14n.json":         append(receiptPayload, '\n'),
		"vectors.json":                              append(indexJSON, '\n'),
	}
}

func TestEffectCloseSchemas(t *testing.T) {
	root := effectCloseRepoRoot(t)
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	for _, name := range []string{
		"connector_effect_acknowledgement.json",
		"connector_effect_acknowledgement_envelope.json",
		"effect_close_receipt.json",
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
