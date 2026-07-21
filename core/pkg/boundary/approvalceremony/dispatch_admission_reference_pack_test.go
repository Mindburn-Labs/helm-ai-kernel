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

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type dispatchAdmissionVectorIndex struct {
	Comment          string                            `json:"$comment"`
	SchemaVersion    string                            `json:"schema_version"`
	ContractVersion  string                            `json:"contract_version"`
	QuantumPosture   string                            `json:"quantum_posture"`
	VerificationTime string                            `json:"verification_time"`
	Consumption      consumptionVectorFile             `json:"consumption"`
	Admission        dispatchAdmissionVectorDescriptor `json:"admission"`
	NegativeVectors  []consumptionNegativeVector       `json:"negative_vectors"`
}

type dispatchAdmissionVectorDescriptor struct {
	consumptionVectorFile
	SigningPayload consumptionVectorFile `json:"signing_payload"`
	PublicKey      string                `json:"public_key"`
	Signature      string                `json:"signature"`
}

func TestApprovalDispatchAdmissionReferencePackMatchesGoImplementation(t *testing.T) {
	files := buildApprovalDispatchAdmissionReferencePack(t)
	root := filepath.Join("..", "..", "..", "..", "reference_packs", "approval-dispatch-admission-v1")
	if os.Getenv("UPDATE_APPROVAL_DISPATCH_ADMISSION_VECTORS") == "1" {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("create approval dispatch admission reference pack: %v", err)
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
			t.Fatalf("%s differs from source-owned Go fixture; run UPDATE_APPROVAL_DISPATCH_ADMISSION_VECTORS=1 go test ./pkg/boundary/approvalceremony -run TestApprovalDispatchAdmissionReferencePackMatchesGoImplementation", name)
		}
	}
}

func buildApprovalDispatchAdmissionReferencePack(t *testing.T) map[string][]byte {
	t.Helper()
	_, _, _, grant := ceremonyFixtures(t)
	consumption := consumptionForGrant(t, grant, "spiffe://helm/data-plane-a", grant.IssuedAt.Add(time.Minute))
	issuedAt := consumption.ConsumedAt.Add(time.Second)
	admission, err := (contracts.ApprovalDispatchAdmission{
		SchemaVersion: contracts.ApprovalDispatchAdmissionSchemaV1, ContractVersion: contracts.ApprovalDispatchAdmissionContractV1,
		Coverage: contracts.ApprovalDispatchAdmissionCoverageV1, AdmissionID: "dispatch-admission-vector-a",
		AttemptID: "attempt-vector-a", State: contracts.ApprovalDispatchAdmissionStateV1,
		ApprovalID: consumption.ApprovalID, GrantID: consumption.GrantID, GrantHash: consumption.GrantHash,
		ConsumptionHash: consumption.ConsumptionHash, TenantID: consumption.TenantID, WorkspaceID: consumption.WorkspaceID,
		Audience: consumption.Audience, AdmittedBy: consumption.ConsumedBy,
		IdempotencyKeyHash: "sha256:" + strings.Repeat("a", 64), EffectHash: consumption.EffectHash,
		Action: consumption.Action, ConnectorAuthority: consumption.ConnectorAuthority,
		KernelTrustRootID: consumption.KernelTrustRootID, SigningKeyRef: consumption.SigningKeyRef,
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(30 * time.Second),
	}).Seal()
	if err != nil {
		t.Fatalf("seal dispatch admission: %v", err)
	}
	if err := admission.ValidateConsumption(consumption); err != nil {
		t.Fatalf("validate dispatch admission consumption binding: %v", err)
	}
	admissionJSON, err := canonicalize.JCS(admission)
	if err != nil {
		t.Fatalf("canonicalize dispatch admission: %v", err)
	}
	consumptionJSON, err := canonicalize.JCS(consumption)
	if err != nil {
		t.Fatalf("canonicalize dispatch admission consumption: %v", err)
	}
	payload, err := ApprovalDispatchAdmissionSigningPayload(admission, GrantSignatureEd25519)
	if err != nil {
		t.Fatalf("dispatch admission signing payload: %v", err)
	}
	signer := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, ed25519.SeedSize)),
		"approval-dispatch-admission-vector",
	)
	signature, err := SignApprovalDispatchAdmission(admission, signer)
	if err != nil {
		t.Fatalf("sign dispatch admission: %v", err)
	}
	index := dispatchAdmissionVectorIndex{
		Comment:          "quantum_posture: classical Ed25519 approval dispatch admission only; no hybrid or post-quantum claim.",
		SchemaVersion:    "approval-dispatch-admission-vectors.v1",
		ContractVersion:  admission.ContractVersion,
		QuantumPosture:   "classical_ed25519_only",
		VerificationTime: admission.IssuedAt.Add(time.Second).Format(time.RFC3339Nano),
		Consumption:      consumptionVectorFile{Canonical: "consumption.c14n.json", SHA256: consumptionVectorHash(consumptionJSON)},
		Admission: dispatchAdmissionVectorDescriptor{
			consumptionVectorFile: consumptionVectorFile{Canonical: "admission.c14n.json", SHA256: consumptionVectorHash(admissionJSON)},
			SigningPayload:        consumptionVectorFile{Canonical: "signing_payload.c14n.json", SHA256: consumptionVectorHash(payload)},
			PublicKey:             "ed25519:" + signer.PublicKey(),
			Signature:             "ed25519:" + signature,
		},
		NegativeVectors: []consumptionNegativeVector{
			{ID: "attempt_substitution", Mutation: "set_attempt_id_to_attempt-b", ExpectedError: "hash_mismatch"},
			{ID: "connector_authority_substitution", Mutation: "set_connector_authority_certification_hash_to_tampered", ExpectedError: "connector_authority_rejected"},
			{ID: "consumption_substitution", Mutation: "set_consumption_hash_to_tampered_and_reseal", ExpectedError: "consumption_binding_rejected"},
			{ID: "expiry_boundary", Mutation: "set_verification_time_to_expires_at", ExpectedError: "inactive_admission"},
			{ID: "signature_tamper", Mutation: "flip_signature_last_bit", ExpectedError: "signature_rejected"},
		},
	}
	indexJSON, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatalf("marshal dispatch admission vector index: %v", err)
	}
	return map[string][]byte{
		"admission.c14n.json":       append(admissionJSON, '\n'),
		"consumption.c14n.json":     append(consumptionJSON, '\n'),
		"signing_payload.c14n.json": append(payload, '\n'),
		"vectors.json":              append(indexJSON, '\n'),
	}
}
