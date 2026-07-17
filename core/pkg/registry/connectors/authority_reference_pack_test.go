package connectors

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
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type releaseAuthorityVectorFile struct {
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

type releaseAuthorityVectorDescriptor struct {
	Authority      releaseAuthorityVectorFile `json:"authority"`
	Envelope       releaseAuthorityVectorFile `json:"envelope"`
	SigningPayload releaseAuthorityVectorFile `json:"signing_payload"`
}

type releaseAuthorityNegativeVector struct {
	ID            string `json:"id"`
	Mutation      string `json:"mutation"`
	ExpectedError string `json:"expected_error"`
}

type releaseAuthorityVectorIndex struct {
	Comment          string                           `json:"$comment"`
	SchemaVersion    string                           `json:"schema_version"`
	ContractVersion  string                           `json:"contract_version"`
	QuantumPosture   string                           `json:"quantum_posture"`
	AuthorityID      string                           `json:"authority_id"`
	PublicKey        string                           `json:"public_key"`
	KeyNotBefore     string                           `json:"key_not_before"`
	KeyNotAfter      string                           `json:"key_not_after"`
	VerificationTime string                           `json:"verification_time"`
	Certified        releaseAuthorityVectorDescriptor `json:"certified"`
	Revoked          releaseAuthorityVectorDescriptor `json:"revoked"`
	NegativeVectors  []releaseAuthorityNegativeVector `json:"negative_vectors"`
}

func TestConnectorReleaseAuthorityReferencePackMatchesGoImplementation(t *testing.T) {
	files := buildConnectorReleaseAuthorityReferencePack(t)
	root := filepath.Join("..", "..", "..", "..", "reference_packs", "connector-release-authority-v1")
	if os.Getenv("UPDATE_CONNECTOR_RELEASE_AUTHORITY_VECTORS") == "1" {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("create connector release authority reference pack: %v", err)
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
			t.Fatalf("%s differs from source-owned Go fixture; run UPDATE_CONNECTOR_RELEASE_AUTHORITY_VECTORS=1 go test ./pkg/registry/connectors -run TestConnectorReleaseAuthorityReferencePackMatchesGoImplementation", name)
		}
	}
}

func buildConnectorReleaseAuthorityReferencePack(t *testing.T) map[string][]byte {
	t.Helper()
	certified := signedReleaseAuthorityFixture(t)
	revoked := certified
	revoked.RegistryRevision = 2
	revoked.State = contracts.ConnectorReleaseAuthorityStateRevoked
	revoked.SignedAt = certified.ValidFrom.Add(time.Minute)
	revoked.ValidFrom = revoked.SignedAt
	revoked.ValidUntil = nil
	revoked.PreviousAuthorityHash = certified.AuthorityHash
	revoked.RevokesAuthorityHash = certified.AuthorityHash
	revoked.AuthorityHash = ""
	var err error
	revoked, err = revoked.Seal()
	if err != nil {
		t.Fatalf("seal revocation: %v", err)
	}

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize))
	signer := crypto.NewEd25519SignerFromKey(privateKey, certified.SigningKeyRef)
	certifiedEnvelope, err := SignConnectorReleaseAuthority(certified, signer)
	if err != nil {
		t.Fatalf("sign certified authority: %v", err)
	}
	revokedEnvelope, err := SignConnectorReleaseAuthority(revoked, signer)
	if err != nil {
		t.Fatalf("sign revoked authority: %v", err)
	}

	certifiedAuthorityJSON := releaseAuthorityCanonical(t, certified)
	certifiedEnvelopeJSON := releaseAuthorityCanonical(t, certifiedEnvelope)
	certifiedPayload, err := ConnectorReleaseAuthoritySigningPayload(certified)
	if err != nil {
		t.Fatalf("certified signing payload: %v", err)
	}
	revokedAuthorityJSON := releaseAuthorityCanonical(t, revoked)
	revokedEnvelopeJSON := releaseAuthorityCanonical(t, revokedEnvelope)
	revokedPayload, err := ConnectorReleaseAuthoritySigningPayload(revoked)
	if err != nil {
		t.Fatalf("revoked signing payload: %v", err)
	}

	index := releaseAuthorityVectorIndex{
		Comment:          "quantum_posture: classical Ed25519 connector release authority only; no hybrid or post-quantum claim.",
		SchemaVersion:    "connector-release-authority-vectors.v1",
		ContractVersion:  contracts.ConnectorReleaseAuthorityContractV1,
		QuantumPosture:   "classical_ed25519_only",
		AuthorityID:      certified.AuthorityID,
		PublicKey:        "ed25519:" + signer.PublicKey(),
		KeyNotBefore:     certified.SignedAt.Add(-time.Hour).Format(time.RFC3339Nano),
		KeyNotAfter:      revoked.SignedAt.Add(time.Hour).Format(time.RFC3339Nano),
		VerificationTime: certified.ValidFrom.Add(2 * time.Minute).Format(time.RFC3339Nano),
		Certified: releaseAuthorityVectorDescriptor{
			Authority:      releaseAuthorityVectorFile{Canonical: "certified_authority.c14n.json", SHA256: releaseAuthorityHash(certifiedAuthorityJSON)},
			Envelope:       releaseAuthorityVectorFile{Canonical: "certified_envelope.c14n.json", SHA256: releaseAuthorityHash(certifiedEnvelopeJSON)},
			SigningPayload: releaseAuthorityVectorFile{Canonical: "certified_signing_payload.c14n.json", SHA256: releaseAuthorityHash(certifiedPayload)},
		},
		Revoked: releaseAuthorityVectorDescriptor{
			Authority:      releaseAuthorityVectorFile{Canonical: "revoked_authority.c14n.json", SHA256: releaseAuthorityHash(revokedAuthorityJSON)},
			Envelope:       releaseAuthorityVectorFile{Canonical: "revoked_envelope.c14n.json", SHA256: releaseAuthorityHash(revokedEnvelopeJSON)},
			SigningPayload: releaseAuthorityVectorFile{Canonical: "revoked_signing_payload.c14n.json", SHA256: releaseAuthorityHash(revokedPayload)},
		},
		NegativeVectors: []releaseAuthorityNegativeVector{
			{ID: "version_substitution", Mutation: "set_certified_connector_version_to_2", ExpectedError: "hash_mismatch"},
			{ID: "artifact_signature_substitution", Mutation: "set_certified_connector_signature_hash_to_tampered", ExpectedError: "hash_mismatch"},
			{ID: "authority_substitution", Mutation: "set_certified_authority_id_and_reseal", ExpectedError: "authority_rejected"},
			{ID: "key_substitution", Mutation: "set_certified_signing_key_ref_and_reseal", ExpectedError: "trust_rejected"},
			{ID: "revision_zero", Mutation: "set_certified_registry_revision_to_zero", ExpectedError: "contract_rejected"},
			{ID: "stale_after_revocation", Mutation: "treat_certified_as_current_after_revocation", ExpectedError: "current_state_rejected"},
			{ID: "expiry_boundary", Mutation: "hide_revocation_and_verify_at_certified_expiry", ExpectedError: "inactive_authority"},
			{ID: "signature_tamper", Mutation: "flip_certified_envelope_signature_last_bit", ExpectedError: "signature_rejected"},
		},
	}
	indexJSON, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatalf("marshal connector release authority vector index: %v", err)
	}
	return map[string][]byte{
		"certified_authority.c14n.json":       append(certifiedAuthorityJSON, '\n'),
		"certified_envelope.c14n.json":        append(certifiedEnvelopeJSON, '\n'),
		"certified_signing_payload.c14n.json": append(certifiedPayload, '\n'),
		"revoked_authority.c14n.json":         append(revokedAuthorityJSON, '\n'),
		"revoked_envelope.c14n.json":          append(revokedEnvelopeJSON, '\n'),
		"revoked_signing_payload.c14n.json":   append(revokedPayload, '\n'),
		"vectors.json":                        append(indexJSON, '\n'),
	}
}

func releaseAuthorityCanonical(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := canonicalize.JCS(value)
	if err != nil {
		t.Fatalf("canonicalize release authority vector: %v", err)
	}
	return payload
}

func releaseAuthorityHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
