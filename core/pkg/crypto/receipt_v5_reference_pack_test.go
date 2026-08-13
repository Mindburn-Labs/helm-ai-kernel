// quantum_posture: this reference pack exercises the classical Ed25519
// profile only; it makes no hybrid or post-quantum receipt claim.
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const receiptV5ReferenceKeyID = "receipt-v5-reference-key-v1"

type receiptV5VectorFile struct {
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

type receiptV5Vector struct {
	ID             string              `json:"id"`
	Receipt        receiptV5VectorFile `json:"receipt"`
	SigningPayload receiptV5VectorFile `json:"signing_payload"`
	Signature      string              `json:"signature"`
}

type receiptV5NegativeVector struct {
	ID            string `json:"id"`
	VectorID      string `json:"vector_id"`
	Mutation      string `json:"mutation"`
	ExpectedError string `json:"expected_error"`
}

type receiptV5Canonicalization struct {
	Specification  string `json:"specification"`
	Profile        string `json:"profile"`
	MaxSafeInteger int64  `json:"max_safe_integer"`
}

type receiptV5VectorIndex struct {
	Comment          string                    `json:"$comment"`
	SchemaVersion    string                    `json:"schema_version"`
	SignatureVersion string                    `json:"signature_version"`
	QuantumPosture   string                    `json:"quantum_posture"`
	Canonicalization receiptV5Canonicalization `json:"canonicalization"`
	KeyID            string                    `json:"key_id"`
	PublicKey        string                    `json:"public_key"`
	Vectors          []receiptV5Vector         `json:"vectors"`
	NegativeVectors  []receiptV5NegativeVector `json:"negative_vectors"`
}

type receiptV5ManifestFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

type receiptV5SourceManifest struct {
	SourceRepository  string                  `json:"source_repository"`
	SourcePath        string                  `json:"source_path"`
	PinningAuthority  string                  `json:"pinning_authority"`
	Verifier          string                  `json:"verifier"`
	ImmutablePayloads []receiptV5ManifestFile `json:"immutable_payloads"`
	Comment           string                  `json:"$comment"`
	Purpose           string                  `json:"purpose"`
}

func TestReceiptV5ReferencePackMatchesGoImplementation(t *testing.T) {
	files := buildReceiptV5ReferencePack(t)
	root := filepath.Join("..", "..", "..", "reference_packs", "receipt-v5")
	if os.Getenv("UPDATE_RECEIPT_V5_VECTORS") == "1" {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("create receipt.v5 reference pack: %v", err)
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
		if !utf8.Valid(got) || !json.Valid(got) {
			t.Fatalf("%s is not valid UTF-8 JSON", name)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s differs from source-owned Go fixture; run UPDATE_RECEIPT_V5_VECTORS=1 go test ./pkg/crypto -run TestReceiptV5ReferencePackMatchesGoImplementation", name)
		}
	}
	canonicalFiles, err := filepath.Glob(filepath.Join(root, "*.c14n.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(canonicalFiles) != 6 {
		t.Fatalf("receipt.v5 pack has %d canonical files, want 6", len(canonicalFiles))
	}
}

func buildReceiptV5ReferencePack(t *testing.T) map[string][]byte {
	t.Helper()
	// Deliberately public test material: a repeated-byte seed keeps the pack
	// reproducible and MUST NOT be reused for any non-test signature.
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x2a}, ed25519.SeedSize))
	signer := NewEd25519SignerFromKey(privateKey, receiptV5ReferenceKeyID)

	files := map[string][]byte{}
	vectors := make([]receiptV5Vector, 0, 3)
	manifestFiles := make([]receiptV5ManifestFile, 0, 6)
	for _, fixture := range receiptV5Fixtures() {
		if err := signer.SignReceipt(fixture.receipt); err != nil {
			t.Fatalf("sign %s: %v", fixture.id, err)
		}

		payload := interoperableReceiptV5Payload(t, fixture.receipt)
		productionPayload, err := ReceiptVerifyPayload(fixture.receipt)
		if err != nil {
			t.Fatalf("production payload %s: %v", fixture.id, err)
		}
		if !bytes.Equal(productionPayload, payload) {
			t.Fatalf("%s production payload is not InteroperableJCS", fixture.id)
		}
		ok, version, err := VerifyReceiptSignature(signer.PublicKey(), fixture.receipt)
		if err != nil || !ok || version != ReceiptPreimageSignedFieldsV5 {
			t.Fatalf("verify %s: ok=%v version=%q err=%v", fixture.id, ok, version, err)
		}

		receiptJSON, err := canonicalize.InteroperableJCS(fixture.receipt)
		if err != nil {
			t.Fatalf("canonicalize receipt %s: %v", fixture.id, err)
		}
		receiptFile := fixture.id + ".receipt.c14n.json"
		payloadFile := fixture.id + ".signing_payload.c14n.json"
		files[receiptFile] = append(receiptJSON, '\n')
		files[payloadFile] = append(payload, '\n')
		receiptHash := receiptV5Hash(receiptJSON)
		payloadHash := receiptV5Hash(payload)
		manifestFiles = append(manifestFiles,
			receiptV5ManifestFile{File: receiptFile, SHA256: strings.TrimPrefix(receiptHash, "sha256:")},
			receiptV5ManifestFile{File: payloadFile, SHA256: strings.TrimPrefix(payloadHash, "sha256:")},
		)
		vectors = append(vectors, receiptV5Vector{
			ID:             fixture.id,
			Receipt:        receiptV5VectorFile{Canonical: receiptFile, SHA256: receiptHash},
			SigningPayload: receiptV5VectorFile{Canonical: payloadFile, SHA256: payloadHash},
			Signature:      "ed25519:" + fixture.receipt.Signature,
		})
	}

	index := receiptV5VectorIndex{
		Comment:          "quantum_posture: classical Ed25519 receipt.v5 vectors only; no hybrid or post-quantum claim.",
		SchemaVersion:    "receipt-v5-vectors.v1",
		SignatureVersion: contracts.ReceiptSignatureV5,
		QuantumPosture:   "classical_ed25519_only",
		Canonicalization: receiptV5Canonicalization{
			Specification:  "protocols/specs/rfc/canonical-json-v1.md",
			Profile:        "interoperable_subset",
			MaxSafeInteger: canonicalize.MaxSafeInteger,
		},
		KeyID:     receiptV5ReferenceKeyID,
		PublicKey: "ed25519:" + signer.PublicKey(),
		Vectors:   vectors,
		NegativeVectors: []receiptV5NegativeVector{
			{ID: "governance_substitution", VectorID: "decision_deny_genesis", Mutation: "set_verdict_to_ALLOW", ExpectedError: "signature_rejected"},
			{ID: "signature_tamper", VectorID: "escaped_string_members", Mutation: "flip_signature_last_bit", ExpectedError: "signature_rejected"},
			{ID: "unsafe_lamport_clock", VectorID: "executor_success_empty_governance", Mutation: "set_lamport_clock_above_max_safe_integer", ExpectedError: "non_interoperable_number"},
			{ID: "missing_signed_member", VectorID: "executor_success_empty_governance", Mutation: "remove_empty_policy_hash", ExpectedError: "contract_mismatch"},
		},
	}
	indexJSON, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatalf("marshal receipt.v5 vector index: %v", err)
	}
	files["vectors.json"] = append(indexJSON, '\n')

	manifest := receiptV5SourceManifest{
		SourceRepository:  "Mindburn-Labs/helm-ai-kernel",
		SourcePath:        "reference_packs/receipt-v5",
		PinningAuthority:  "reference_packs/receipt-v5/vectors.json",
		Verifier:          "reference_packs/receipt-v5/verify_vectors.py",
		ImmutablePayloads: manifestFiles,
		Comment:           "quantum_posture: classical_ed25519_only. Listed hashes cover canonical JSON text after removing the repository file's single trailing LF; Ed25519 covers each derived 13-member signing payload, not every receipt-file byte.",
		Purpose:           "Receipt.v5 canonical-text inventory; vectors.json remains the hash-pinning authority.",
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal receipt.v5 source manifest: %v", err)
	}
	files["SOURCE-MANIFEST.json"] = append(manifestJSON, '\n')
	return files
}

func interoperableReceiptV5Payload(t *testing.T, receipt *contracts.Receipt) []byte {
	t.Helper()
	payload, err := canonicalize.InteroperableJCS(receiptV5SigningEnvelope{
		SignatureVersion: contracts.ReceiptSignatureV5,
		ReceiptID:        receipt.ReceiptID,
		DecisionID:       receipt.DecisionID,
		EffectID:         receipt.EffectID,
		Status:           receipt.Status,
		OutputHash:       receipt.OutputHash,
		PrevHash:         receipt.PrevHash,
		LamportClock:     receipt.LamportClock,
		ArgsHash:         receipt.ArgsHash,
		Verdict:          receipt.Verdict,
		ReasonCode:       receipt.ReasonCode,
		PolicyHash:       receipt.PolicyHash,
		SessionID:        receipt.SessionID,
	})
	if err != nil {
		t.Fatalf("canonicalize receipt.v5 payload: %v", err)
	}
	return payload
}

func receiptV5Hash(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func receiptV5Fixtures() []struct {
	id      string
	receipt *contracts.Receipt
} {
	timestamp := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	return []struct {
		id      string
		receipt *contracts.Receipt
	}{
		{
			id: "decision_deny_genesis",
			receipt: &contracts.Receipt{
				ReceiptID: "rcpt-01K0RCPTDENY0000000000000A", DecisionID: "dec-01K0DECIDENY0000000000000A",
				CorrelationID: "corr-01K0CORRDENY000000000000A", EffectID: "eff-01K0EFFCDENY0000000000000A",
				Status: "DENY", BlobHash: "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
				OutputHash: "sha256:3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea",
				Timestamp:  timestamp, ExecutorID: "agent-alpha", Metadata: map[string]any{"tenant_id": "tenant-a"},
				LamportClock: 1, ArgsHash: "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
				DecisionHash: "sha256:3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea",
				Verdict:      "DENY", ReasonCode: "POLICY_VIOLATION",
				PolicyHash:   "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
				SessionID:    "sess-01K0SESSDENY000000000000A",
				Transparency: &contracts.TransparencyAnchor{Backend: "translog", LogID: "translog-reference-a"},
				LogID:        "translog-reference-a", LeafIndex: 41,
			},
		},
		{
			id: "executor_success_empty_governance",
			receipt: &contracts.Receipt{
				ReceiptID: "rcpt-01K0RCPTOKAY0000000000000B", DecisionID: "dec-01K0DECIOKAY0000000000000B",
				EffectID: "eff-01K0EFFCOKAY0000000000000B", Status: "SUCCESS",
				OutputHash: "sha256:6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d",
				Timestamp:  timestamp.Add(time.Second), ExecutorID: "executor-beta",
				PrevHash:     "1f4a2b6bd9f6d0e5c40a4a4ee6a1cd4f3d2f6de5e4b2c0f1a9d8c7b6a5948372",
				LamportClock: canonicalize.MaxSafeInteger, SessionID: "sess-01K0SESSOKAY000000000000B",
			},
		},
		{
			id: "escaped_string_members",
			receipt: &contracts.Receipt{
				ReceiptID: "rcpt-01K0RCPTESCP0000000000000C", DecisionID: "dec-01K0DECIESCP0000000000000C",
				EffectID: "eff-01K0EFFCESCP0000000000000C", Status: "ALLOW",
				OutputHash: "sha256:d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
				Timestamp:  timestamp.Add(2 * time.Second), ExecutorID: "agent-gamma",
				PrevHash:     "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
				LamportClock: 2, ArgsHash: "sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
				Verdict: "ALLOW", ReasonCode: "ALLOWED_BY_POLICY",
				PolicyHash: "sha256:ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
				SessionID:  "sess-\"quote\\solidus\ttab\u2028ls\u2029ps🔐lock",
			},
		},
	}
}
