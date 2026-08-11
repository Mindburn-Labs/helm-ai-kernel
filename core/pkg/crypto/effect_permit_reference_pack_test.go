// quantum_posture: these fixtures use classical Ed25519 only; the
// effect_permit.v1 preimage remains algorithm-neutral.
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

type effectPermitVectorFile struct {
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

type effectPermitVector struct {
	ID             string                 `json:"id"`
	Description    string                 `json:"description"`
	Artifact       effectPermitVectorFile `json:"artifact"`
	SigningPayload effectPermitVectorFile `json:"signing_payload"`
	Signature      string                 `json:"signature"`
}

type effectPermitNegativeVector struct {
	ID            string `json:"id"`
	Vector        string `json:"vector"`
	Mutation      string `json:"mutation"`
	ExpectedError string `json:"expected_error"`
}

type effectPermitVectorIndex struct {
	Comment          string                       `json:"$comment"`
	SchemaVersion    string                       `json:"schema_version"`
	SignatureVersion string                       `json:"signature_version"`
	ContractVersion  string                       `json:"contract_version"`
	QuantumPosture   string                       `json:"quantum_posture"`
	Status           string                       `json:"status"`
	Specification    string                       `json:"specification"`
	IssuerPublicKey  string                       `json:"issuer_public_key"`
	Vectors          []effectPermitVector         `json:"vectors"`
	NegativeVectors  []effectPermitNegativeVector `json:"negative_vectors"`
}

func TestEffectPermitReferencePackMatchesGoImplementation(t *testing.T) {
	files := buildEffectPermitReferencePack(t)
	root := filepath.Join("..", "..", "..", "reference_packs", "effect-permit-v1")
	if os.Getenv("UPDATE_EFFECT_PERMIT_VECTORS") == "1" {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("create effect permit reference pack: %v", err)
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
			t.Fatalf("%s differs from the source-owned Go fixture; run "+
				"UPDATE_EFFECT_PERMIT_VECTORS=1 go test ./pkg/crypto -run TestEffectPermitReferencePackMatchesGoImplementation", name)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read effect permit reference pack: %v", err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			if _, expected := files[entry.Name()]; !expected {
				t.Fatalf("stale effect permit reference artifact: %s", entry.Name())
			}
		}
	}
}

func effectPermitVectorHash(payload []byte) string {
	return "sha256:" + canonicalize.HashBytes(payload)
}

func effectPermitCanonical(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := canonicalize.InteroperableJCS(value)
	if err != nil {
		t.Fatalf("canonicalize interoperable permit: %v", err)
	}
	return payload
}

func signEffectPermitVector(t *testing.T, signer *Ed25519Signer, p *effects.EffectPermit) (wire, payload []byte) {
	t.Helper()
	if err := SignPermit(signer, p); err != nil {
		t.Fatalf("SignPermit: %v", err)
	}
	ok, err := VerifyPermit(signer.PublicKey(), p)
	if err != nil || !ok {
		t.Fatalf("sealed permit must verify: ok=%v err=%v", ok, err)
	}
	payload, err = EffectPermitSigningPayload(p)
	if err != nil {
		t.Fatalf("EffectPermitSigningPayload: %v", err)
	}
	return effectPermitCanonical(t, p), payload
}

func buildEffectPermitReferencePack(t *testing.T) map[string][]byte {
	t.Helper()
	issuer := NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize)),
		"effect-permit-vector-issuer",
	)
	issuedAt := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

	bridgePermit := &effects.EffectPermit{
		PermitID:    "permit-9f2c41a7b0d3e58c",
		IntentHash:  "sha256:1f0c2b6d4a8e7c5b39d1e0f4a2c6b8d0e3f5a7c9b1d3e5f7a9c1b3d5e7f9a1c3",
		VerdictHash: "sha256:2a1d3c5e7f9b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f",
		PlanHash:    "sha256:3b2e4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b",
		PolicyHash:  "sha256:4c3f5e7a9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a",
		EffectType:  effects.EffectTypeWrite,
		ConnectorID: "linear",
		Scope: effects.EffectScope{
			AllowedAction: "linear.create_issue",
			AllowedParams: []string{"team_id=s:team-1", "title=s:Ship the permit spec"},
			DenyPatterns:  []string{"^secret", "^token"},
		},
		ResourceRef:      "linear:team:team-1",
		ExpiresAt:        issuedAt.Add(5 * time.Minute),
		SingleUse:        true,
		Nonce:            "d3f1a7c92b4e6081d3f1a7c92b4e6081d3f1a7c92b4e6081d3f1a7c92b4e6081",
		IssuedAt:         issuedAt,
		IssuerID:         "mcp-governed-bridge-v1",
		EvidenceBindings: map[string]string{"decision_id": "dec-7f31", "sandbox_grant_hash": "sha256:5d4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a"},
	}
	bridgeWire, bridgePayload := signEffectPermitVector(t, issuer, bridgePermit)

	plusTwo := time.FixedZone("UTC+2", 2*60*60)
	minimalPermit := &effects.EffectPermit{
		PermitID:    "permit-0c7e5a91d2b46f38",
		IntentHash:  "sha256:6e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b",
		VerdictHash: "sha256:7f6c8e0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d",
		EffectType:  effects.EffectTypeRead,
		ConnectorID: "linear",
		Scope:       effects.EffectScope{AllowedAction: "linear.get_issue"},
		ResourceRef: "linear:issue:ISS-1",
		ExpiresAt:   time.Date(2026, 8, 6, 12, 30, 0, 0, time.UTC),
		SingleUse:   true,
		Nonce:       "8a7d9f1b3c5e7a9d1f3b5c7e9a1d3f5b7c9e1a3d5f7b9c1e3a5d7f9b1c3e5a7d",
		IssuedAt:    time.Date(2026, 8, 6, 14, 0, 0, 500000000, plusTwo),
		IssuerID:    "mcp-governed-bridge-v1",
	}
	minimalWire, minimalPayload := signEffectPermitVector(t, issuer, minimalPermit)

	index := effectPermitVectorIndex{
		Comment:          "quantum_posture: classical Ed25519 test vectors only; the effect_permit.v1 preimage is algorithm-neutral.",
		SchemaVersion:    "effect-permit-vectors.v1",
		SignatureVersion: EffectPermitSignatureV1,
		ContractVersion:  "2026-08-10",
		QuantumPosture:   "classical_ed25519_test_vectors",
		Status:           "final",
		Specification:    "protocols/specs/effects/effect-permit-v1.md",
		IssuerPublicKey:  "ed25519:" + issuer.PublicKey(),
		Vectors: []effectPermitVector{
			{
				ID:             "bridge_write_permit",
				Description:    "Fully populated WRITE permit with ordered scope lists and two evidence bindings.",
				Artifact:       effectPermitVectorFile{Canonical: "bridge_permit.c14n.json", SHA256: effectPermitVectorHash(bridgeWire)},
				SigningPayload: effectPermitVectorFile{Canonical: "bridge_permit_signing_payload.c14n.json", SHA256: effectPermitVectorHash(bridgePayload)},
				Signature:      "ed25519:" + bridgePermit.Signature,
			},
			{
				ID:             "minimal_read_permit",
				Description:    "Normalization vector for empty optional fields, nil collections, UTC conversion, and fractional seconds.",
				Artifact:       effectPermitVectorFile{Canonical: "minimal_permit.c14n.json", SHA256: effectPermitVectorHash(minimalWire)},
				SigningPayload: effectPermitVectorFile{Canonical: "minimal_permit_signing_payload.c14n.json", SHA256: effectPermitVectorHash(minimalPayload)},
				Signature:      "ed25519:" + minimalPermit.Signature,
			},
		},
		NegativeVectors: []effectPermitNegativeVector{
			{ID: "unsigned_permit", Vector: "bridge_write_permit", Mutation: "remove_signature", ExpectedError: "permit_unsigned"},
			{ID: "uppercase_signature_hex", Vector: "bridge_write_permit", Mutation: "uppercase_signature_hex", ExpectedError: "invalid_encoding"},
			{ID: "signature_bit_flip", Vector: "bridge_write_permit", Mutation: "flip_signature_last_bit", ExpectedError: "permit_signature_rejected"},
			{ID: "tamper_permit_id", Vector: "bridge_write_permit", Mutation: "set_permit_id", ExpectedError: "permit_signature_rejected"},
			{ID: "tamper_scope_order", Vector: "bridge_write_permit", Mutation: "reverse_scope_allowed_params", ExpectedError: "permit_signature_rejected"},
			{ID: "omit_signature_version", Vector: "bridge_write_permit", Mutation: "build_payload_without_signature_version", ExpectedError: "permit_signature_rejected"},
			{ID: "null_empty_scope_lists", Vector: "minimal_read_permit", Mutation: "build_payload_with_null_scope_lists", ExpectedError: "permit_signature_rejected"},
			{ID: "retain_timestamp_offset", Vector: "minimal_read_permit", Mutation: "build_payload_without_utc_normalization", ExpectedError: "permit_signature_rejected"},
		},
	}

	indexJSON, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"bridge_permit.c14n.json":                  append(bridgeWire, '\n'),
		"bridge_permit_signing_payload.c14n.json":  append(bridgePayload, '\n'),
		"minimal_permit.c14n.json":                 append(minimalWire, '\n'),
		"minimal_permit_signing_payload.c14n.json": append(minimalPayload, '\n'),
		"vectors.json":                             append(indexJSON, '\n'),
	}
}
