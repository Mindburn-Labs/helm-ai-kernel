package approvalceremony

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type consumptionVectorFile struct {
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

type consumptionNegativeVector struct {
	ID            string `json:"id"`
	Mutation      string `json:"mutation"`
	ExpectedError string `json:"expected_error"`
}

type consumptionVectorIndex struct {
	Comment         string                      `json:"$comment"`
	SchemaVersion   string                      `json:"schema_version"`
	ContractVersion string                      `json:"contract_version"`
	QuantumPosture  string                      `json:"quantum_posture"`
	Consumption     consumptionVectorDescriptor `json:"consumption"`
	NegativeVectors []consumptionNegativeVector `json:"negative_vectors"`
}

type consumptionVectorDescriptor struct {
	consumptionVectorFile
	SigningPayload consumptionVectorFile `json:"signing_payload"`
	PublicKey      string                `json:"public_key"`
	Signature      string                `json:"signature"`
}

func TestApprovalConsumptionReferencePackMatchesGoImplementation(t *testing.T) {
	files := buildApprovalConsumptionReferencePack(t)
	root := filepath.Join("..", "..", "..", "..", "reference_packs", "approval-consumption-v1")
	if os.Getenv("UPDATE_APPROVAL_CONSUMPTION_VECTORS") == "1" {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("create approval consumption reference pack: %v", err)
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
			t.Fatalf("%s differs from source-owned Go fixture; run UPDATE_APPROVAL_CONSUMPTION_VECTORS=1 go test ./pkg/boundary/approvalceremony -run TestApprovalConsumptionReferencePackMatchesGoImplementation", name)
		}
	}
}

func buildApprovalConsumptionReferencePack(t *testing.T) map[string][]byte {
	t.Helper()
	_, _, _, grant := ceremonyFixtures(t)
	consumption := consumptionForGrant(t, grant, "spiffe://helm/data-plane-a", grant.IssuedAt.Add(time.Minute))
	consumptionJSON, err := canonicalize.JCS(consumption)
	if err != nil {
		t.Fatalf("canonicalize consumption: %v", err)
	}
	payload, err := ApprovalGrantConsumptionSigningPayload(consumption, GrantSignatureEd25519)
	if err != nil {
		t.Fatalf("consumption signing payload: %v", err)
	}
	signer := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)),
		"approval-consumption-vector",
	)
	signature, err := SignApprovalGrantConsumption(consumption, signer)
	if err != nil {
		t.Fatalf("sign consumption: %v", err)
	}
	index := consumptionVectorIndex{
		Comment:         "quantum_posture: classical Ed25519 approval grant consumption only; no hybrid or post-quantum claim.",
		SchemaVersion:   "approval-grant-consumption-vectors.v1",
		ContractVersion: consumption.ContractVersion,
		QuantumPosture:  "classical_ed25519_only",
		Consumption: consumptionVectorDescriptor{
			consumptionVectorFile: consumptionVectorFile{Canonical: "consumption.c14n.json", SHA256: consumptionVectorHash(consumptionJSON)},
			SigningPayload:        consumptionVectorFile{Canonical: "signing_payload.c14n.json", SHA256: consumptionVectorHash(payload)},
			PublicKey:             "ed25519:" + signer.PublicKey(),
			Signature:             "ed25519:" + signature,
		},
		NegativeVectors: []consumptionNegativeVector{
			{ID: "consumer_substitution", Mutation: "set_consumed_by_to_data-plane-b", ExpectedError: "hash_mismatch"},
			{ID: "expiry_boundary", Mutation: "set_consumed_at_to_grant_expiry", ExpectedError: "inactive_consumption"},
			{ID: "signature_tamper", Mutation: "flip_signature_last_bit", ExpectedError: "signature_rejected"},
		},
	}
	indexJSON, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatalf("marshal consumption vector index: %v", err)
	}
	return map[string][]byte{
		"consumption.c14n.json":     append(consumptionJSON, '\n'),
		"signing_payload.c14n.json": append(payload, '\n'),
		"vectors.json":              append(indexJSON, '\n'),
	}
}

func consumptionVectorHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
