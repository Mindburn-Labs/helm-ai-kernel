package approvalceremony

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
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

func TestEffectDispositionReferencePackMatchesGoImplementation(t *testing.T) {
	files := buildEffectDispositionReferencePack(t)
	root := filepath.Join("..", "..", "..", "..", "reference_packs", "effect-disposition-v1")
	if os.Getenv("UPDATE_EFFECT_DISPOSITION_VECTORS") == "1" {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("create effect disposition reference pack: %v", err)
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
			t.Fatalf("%s differs from source-owned Go fixture; run UPDATE_EFFECT_DISPOSITION_VECTORS=1 go test ./pkg/boundary/approvalceremony -run TestEffectDispositionReferencePackMatchesGoImplementation", name)
		}
	}
}

func buildEffectDispositionReferencePack(t *testing.T) map[string][]byte {
	t.Helper()
	issuedAt := time.Date(2026, 7, 18, 13, 0, 0, 123456000, time.UTC)
	command, err := (contracts.EffectDispositionCommand{
		SchemaVersion: contracts.EffectDispositionCommandSchemaV1, ContractVersion: contracts.EffectDispositionCommandContractV1,
		CommandID: "disposition-command-vector-a", DispositionSequence: 2,
		PreviousReceiptHash: effectCloseVectorSHA("previous-disposition-receipt"),
		TenantID:            "tenant-a", WorkspaceID: "workspace-a", Audience: "packs.lifecycle",
		FenceCommandID: "fence-command-vector-a", FenceCommandHash: effectCloseVectorSHA("fence-command"),
		FenceEpoch: 7, FenceReceiptHash: effectCloseVectorSHA("fence-receipt"),
		AdmissionID: "dispatch-admission-vector-a", AttemptID: "attempt-vector-a",
		ReservationSequence: 3, ReservationHeadHash: effectCloseVectorSHA("reservation-head"),
		ReservationState: contracts.EffectClosePriorStateUncertain,
		ConnectorID:      "github", ConnectorVersion: "1.0.0", ConnectorAction: "github.create_issue",
		ConnectorExecutionRef: "github-request-vector-a", ProofSessionRef: "proof-session-vector-a",
		IntentRef: "intent-vector-a", EffectRef: "github-issue-42",
		IdempotencyKeyHash: effectCloseVectorSHA("idempotency"), EffectHash: effectCloseVectorSHA("effect"),
		Action: contracts.EffectDispositionActionReconcileSource, DispositionRef: "reconciliation-vector-a",
		ActorID: "operator-a", Reason: "Reconcile source state before terminal close",
		AuthorityID: "control-plane-a", SigningKeyRef: "kms://helm/control-plane/disposition/key-a",
		Algorithm: contracts.EffectDispositionAlgorithmV1, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(5 * time.Minute),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	commandSigner := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, ed25519.SeedSize)), "effect-disposition-command-vector",
	)
	envelope, err := SignEffectDispositionCommand(command, commandSigner)
	if err != nil {
		t.Fatal(err)
	}
	commandJSON := effectCloseCanonical(t, command)
	envelopeJSON := effectCloseCanonical(t, envelope)
	commandPayload, err := EffectDispositionCommandSigningPayload(command)
	if err != nil {
		t.Fatal(err)
	}

	receipt, err := (contracts.EffectDispositionReceipt{
		SchemaVersion: contracts.EffectDispositionReceiptSchemaV1, ContractVersion: contracts.EffectDispositionReceiptContractV1,
		ReceiptID: "disposition-receipt-vector-a", State: contracts.EffectDispositionReceiptStateAccepted,
		ExecutionAuthority: contracts.EffectDispositionExecutionAuthorityNone,
		CommandID:          command.CommandID, CommandHash: command.CommandHash,
		DispositionSequence: command.DispositionSequence, PreviousReceiptHash: command.PreviousReceiptHash,
		TenantID: command.TenantID, WorkspaceID: command.WorkspaceID, Audience: command.Audience,
		FenceCommandID: command.FenceCommandID, FenceCommandHash: command.FenceCommandHash,
		FenceEpoch: command.FenceEpoch, FenceReceiptHash: command.FenceReceiptHash,
		AdmissionID: command.AdmissionID, ReservationSequence: command.ReservationSequence,
		ReservationHeadHash: command.ReservationHeadHash, ReservationState: command.ReservationState,
		Action: command.Action, DispositionRef: command.DispositionRef,
		KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/approval/key-a",
		AcceptedBy: "spiffe://helm/kernel-a", AcceptedAt: issuedAt.Add(time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	receiptSigner := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{74}, ed25519.SeedSize)), "effect-disposition-receipt-vector",
	)
	receiptSignature, err := SignEffectDispositionReceipt(receipt, receiptSigner)
	if err != nil {
		t.Fatal(err)
	}
	receiptJSON := effectCloseCanonical(t, receipt)
	receiptPayload, err := EffectDispositionReceiptSigningPayload(receipt, GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}

	index := effectDispositionVectorIndex{
		Comment:         "quantum_posture: classical Ed25519 disposition command and receipt only; no hybrid or post-quantum claim.",
		SchemaVersion:   "effect-disposition-vectors.v1",
		ContractVersion: contracts.EffectDispositionReceiptContractV1,
		QuantumPosture:  "classical_ed25519_only",
		Command: effectCloseSignedVector{
			Artifact:       effectCloseVectorFile{Canonical: "command.c14n.json", SHA256: effectCloseVectorHash(commandJSON)},
			Envelope:       effectCloseVectorFile{Canonical: "command_envelope.c14n.json", SHA256: effectCloseVectorHash(envelopeJSON)},
			SigningPayload: effectCloseVectorFile{Canonical: "command_signing_payload.c14n.json", SHA256: effectCloseVectorHash(commandPayload)},
			PublicKey:      "ed25519:" + commandSigner.PublicKey(), Signature: "ed25519:" + envelope.Signature,
			KeyNotBefore: issuedAt.Add(-time.Hour).Format(time.RFC3339Nano), KeyNotAfter: issuedAt.Add(time.Hour).Format(time.RFC3339Nano),
		},
		Receipt: effectCloseSignedVector{
			Artifact:       effectCloseVectorFile{Canonical: "receipt.c14n.json", SHA256: effectCloseVectorHash(receiptJSON)},
			SigningPayload: effectCloseVectorFile{Canonical: "receipt_signing_payload.c14n.json", SHA256: effectCloseVectorHash(receiptPayload)},
			PublicKey:      "ed25519:" + receiptSigner.PublicKey(), Signature: "ed25519:" + receiptSignature,
			KeyNotBefore: issuedAt.Add(-time.Hour).Format(time.RFC3339Nano), KeyNotAfter: issuedAt.Add(time.Hour).Format(time.RFC3339Nano),
		},
		NegativeVectors: []effectCloseNegativeVector{
			{ID: "command_reservation_head_tamper", Mutation: "set_command_reservation_head_hash_to_tampered", ExpectedError: "command_hash_mismatch"},
			{ID: "command_signature_tamper", Mutation: "flip_command_signature_last_bit", ExpectedError: "command_signature_rejected"},
			{ID: "command_authority_substitution", Mutation: "set_command_authority_id_to_other_and_reseal", ExpectedError: "command_trust_rejected"},
			{ID: "receipt_command_substitution", Mutation: "set_receipt_command_hash_to_other_and_reseal", ExpectedError: "command_binding_rejected"},
			{ID: "receipt_execution_authority_escalation", Mutation: "set_receipt_execution_authority_to_effect_and_reseal", ExpectedError: "receipt_contract_rejected"},
			{ID: "receipt_signature_tamper", Mutation: "flip_receipt_signature_last_bit", ExpectedError: "receipt_signature_rejected"},
			{ID: "receipt_chain_predecessor_mismatch", Mutation: "set_receipt_previous_hash_to_other_and_reseal", ExpectedError: "command_binding_rejected"},
		},
	}
	indexJSON, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"command.c14n.json":                 append(commandJSON, '\n'),
		"command_envelope.c14n.json":        append(envelopeJSON, '\n'),
		"command_signing_payload.c14n.json": append(commandPayload, '\n'),
		"receipt.c14n.json":                 append(receiptJSON, '\n'),
		"receipt_signing_payload.c14n.json": append(receiptPayload, '\n'),
		"vectors.json":                      append(indexJSON, '\n'),
	}
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
