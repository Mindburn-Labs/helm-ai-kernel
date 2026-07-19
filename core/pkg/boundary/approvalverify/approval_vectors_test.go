// quantum_posture: these fixtures cover classical Ed25519 approval assertions;
// they do not establish hybrid or post-quantum approval support.
package approvalverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type approvalVectorFile struct {
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

type approvalAssertionVector struct {
	KeyID          string                      `json:"key_id"`
	SigningPayload string                      `json:"signing_payload"`
	SigningDigest  string                      `json:"signing_digest"`
	PublicKey      string                      `json:"public_key"`
	Signature      string                      `json:"signature"`
	Assertion      contracts.ApprovalAssertion `json:"assertion"`
	AssertionHash  string                      `json:"assertion_hash"`
}

type approvalVectorCase struct {
	ID                 string             `json:"id"`
	AssertionKeyIDs    []string           `json:"assertion_key_ids"`
	SignerSet          approvalVectorFile `json:"signer_set"`
	VerifiedProjection approvalVectorFile `json:"verified_projection"`
	ExpectedStatus     string             `json:"expected_status"`
}

type approvalNegativeVector struct {
	ID            string `json:"id"`
	Mutation      string `json:"mutation"`
	ExpectedError string `json:"expected_error"`
}

type approvalVectorIndex struct {
	Comment           string                    `json:"$comment"`
	SchemaVersion     string                    `json:"schema_version"`
	ContractVersion   string                    `json:"contract_version"`
	QuantumPosture    string                    `json:"quantum_posture"`
	VerifiedAt        string                    `json:"verified_at"`
	AuthoritySnapshot approvalVectorFile        `json:"authority_snapshot"`
	Challenge         approvalVectorFile        `json:"challenge"`
	Assertions        []approvalAssertionVector `json:"assertions"`
	Cases             []approvalVectorCase      `json:"cases"`
	NegativeVectors   []approvalNegativeVector  `json:"negative_vectors"`
}

type approvalSnapshotKey struct {
	KeyID        string   `json:"key_id"`
	TenantID     string   `json:"tenant_id"`
	PrincipalID  string   `json:"principal_id"`
	CredentialID string   `json:"credential_id"`
	DeviceID     string   `json:"device_id"`
	PublicKey    string   `json:"public_key"`
	WorkspaceIDs []string `json:"workspace_ids"`
	Roles        []string `json:"roles"`
	Actions      []string `json:"actions"`
	Audiences    []string `json:"audiences"`
	Enabled      bool     `json:"enabled"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
}

type approvalAuthoritySnapshot struct {
	Domain           string                `json:"domain"`
	AuthoritySource  string                `json:"authority_source"`
	AuthorityVersion string                `json:"authority_version"`
	Keys             []approvalSnapshotKey `json:"keys"`
}

type approvalSignerSet struct {
	Domain                string           `json:"domain"`
	ChallengeHash         string           `json:"challenge_hash"`
	AuthoritySnapshotHash string           `json:"authority_snapshot_hash"`
	Signers               []VerifiedSigner `json:"signers"`
}

func TestApprovalReferencePackMatchesGoImplementation(t *testing.T) {
	files := buildApprovalReferencePack(t)
	root := filepath.Join("..", "..", "..", "..", "reference_packs", "approval")
	if os.Getenv("UPDATE_APPROVAL_VECTORS") == "1" {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("create approval reference pack: %v", err)
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
			t.Fatalf("%s differs from source-owned Go fixture; run UPDATE_APPROVAL_VECTORS=1 go test ./pkg/boundary/approvalverify -run TestApprovalReferencePackMatchesGoImplementation", name)
		}
	}
}

func buildApprovalReferencePack(t *testing.T) map[string][]byte {
	t.Helper()
	challenge := sealedChallenge(t)
	store, privateKeys := trustedStore(challenge)
	privateC := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	privateKeys["key-c"] = privateC
	store.Keys["key-c"] = TrustedApproverKey{
		KeyID: "key-c", TenantID: challenge.TenantID, PrincipalID: "principal-c",
		CredentialID: "credential-c", DeviceID: "device-c", PublicKey: privateC.Public().(ed25519.PublicKey),
		WorkspaceIDs: []string{challenge.WorkspaceID}, Roles: []string{challenge.RequiredRole},
		Actions: []string{challenge.Action}, Audiences: []string{challenge.Audience}, Enabled: true,
		NotBefore: challenge.HoldStartedAt.Add(-time.Hour), NotAfter: challenge.ExpiresAt.Add(time.Hour),
	}

	snapshotKeys := make([]approvalSnapshotKey, 0, len(store.Keys))
	for _, keyID := range []string{"key-a", "key-b", "key-c"} {
		key := store.Keys[keyID]
		snapshotKeys = append(snapshotKeys, approvalSnapshotKey{
			KeyID: key.KeyID, TenantID: key.TenantID, PrincipalID: key.PrincipalID,
			CredentialID: key.CredentialID, DeviceID: key.DeviceID,
			PublicKey:    "ed25519:" + hex.EncodeToString(key.PublicKey),
			WorkspaceIDs: key.WorkspaceIDs, Roles: key.Roles, Actions: key.Actions,
			Audiences: key.Audiences, Enabled: key.Enabled,
			NotBefore: key.NotBefore.UTC().Format(time.RFC3339Nano),
			NotAfter:  key.NotAfter.UTC().Format(time.RFC3339Nano),
		})
	}
	snapshot := approvalAuthoritySnapshot{
		Domain: "HELM/ApprovalAuthoritySnapshot/v1", AuthoritySource: challenge.AuthoritySource,
		AuthorityVersion: challenge.AuthorityVersion, Keys: snapshotKeys,
	}
	snapshotHash := canonicalHashRef(t, snapshot)
	challenge.ChallengeHash = ""
	challenge.AuthoritySnapshotHash = snapshotHash
	var err error
	challenge, err = challenge.Seal()
	if err != nil {
		t.Fatalf("seal fixture challenge: %v", err)
	}

	store, privateKeys = trustedStore(challenge)
	privateKeys["key-c"] = privateC
	store.Keys["key-c"] = TrustedApproverKey{
		KeyID: "key-c", TenantID: challenge.TenantID, PrincipalID: "principal-c",
		CredentialID: "credential-c", DeviceID: "device-c", PublicKey: privateC.Public().(ed25519.PublicKey),
		WorkspaceIDs: []string{challenge.WorkspaceID}, Roles: []string{challenge.RequiredRole},
		Actions: []string{challenge.Action}, Audiences: []string{challenge.Audience}, Enabled: true,
		NotBefore: challenge.HoldStartedAt.Add(-time.Hour), NotAfter: challenge.ExpiresAt.Add(time.Hour),
	}
	assertionByKey := map[string]contracts.ApprovalAssertion{
		"key-a": signedAssertion(t, challenge, "key-a", privateKeys["key-a"]),
		"key-b": signedAssertion(t, challenge, "key-b", privateKeys["key-b"]),
		"key-c": signedAssertion(t, challenge, "key-c", privateKeys["key-c"]),
	}
	now := challenge.IssuedAt.Add(time.Minute)
	cases := []struct {
		id             string
		keys           []string
		signerFile     string
		projectionFile string
		expectedStatus string
	}{
		{id: "quorum_2_of_2", keys: []string{"key-b", "key-a"}, signerFile: "signer_set.c14n.json", projectionFile: "verified_projection.c14n.json", expectedStatus: "verified"},
		{id: "quorum_2_of_3", keys: []string{"key-c", "key-a", "key-b"}, signerFile: "over_quorum_signer_set.c14n.json", projectionFile: "over_quorum_verified_projection.c14n.json", expectedStatus: "verified_over_quorum"},
	}

	files := map[string][]byte{}
	authorityJSON := canonicalJSON(t, snapshot)
	files["authority_snapshot.c14n.json"] = authorityJSON
	unsealedChallenge := challenge
	unsealedChallenge.ChallengeHash = ""
	files["challenge.c14n.json"] = canonicalJSON(t, unsealedChallenge)

	assertionVectors := make([]approvalAssertionVector, 0, len(assertionByKey))
	for _, keyID := range []string{"key-a", "key-b", "key-c"} {
		assertion := assertionByKey[keyID]
		payload := struct {
			Domain          string `json:"domain"`
			SchemaVersion   string `json:"schema_version"`
			ContractVersion string `json:"contract_version"`
			ChallengeID     string `json:"challenge_id"`
			ChallengeHash   string `json:"challenge_hash"`
			KeyID           string `json:"key_id"`
			Algorithm       string `json:"algorithm"`
		}{assertion.Domain, assertion.SchemaVersion, assertion.ContractVersion, assertion.ChallengeID, assertion.ChallengeHash, assertion.KeyID, assertion.Algorithm}
		payloadFile := keyID + "_signing_payload.c14n.json"
		files[payloadFile] = canonicalJSON(t, payload)
		digest, err := assertion.SigningDigest()
		if err != nil {
			t.Fatalf("signing digest %s: %v", keyID, err)
		}
		assertionVectors = append(assertionVectors, approvalAssertionVector{
			KeyID: keyID, SigningPayload: payloadFile,
			SigningDigest: "sha256:" + hex.EncodeToString(digest),
			PublicKey:     "ed25519:" + hex.EncodeToString(store.Keys[keyID].PublicKey),
			Signature:     assertion.Signature, Assertion: assertion,
			AssertionHash: canonicalHashRef(t, assertion),
		})
	}

	caseIndexes := make([]approvalVectorCase, 0, len(cases))
	for _, vectorCase := range cases {
		assertions := make([]contracts.ApprovalAssertion, 0, len(vectorCase.keys))
		for _, keyID := range vectorCase.keys {
			assertions = append(assertions, assertionByKey[keyID])
		}
		projection, err := VerifyQuorum(challenge, assertions, store, optionsFor(challenge), now)
		if err != nil {
			t.Fatalf("verify %s: %v", vectorCase.id, err)
		}
		signers := append([]VerifiedSigner(nil), projection.Signers...)
		sort.Slice(signers, func(i, j int) bool {
			if signers[i].PrincipalID != signers[j].PrincipalID {
				return signers[i].PrincipalID < signers[j].PrincipalID
			}
			if signers[i].CredentialID != signers[j].CredentialID {
				return signers[i].CredentialID < signers[j].CredentialID
			}
			if signers[i].DeviceID != signers[j].DeviceID {
				return signers[i].DeviceID < signers[j].DeviceID
			}
			return signers[i].KeyID < signers[j].KeyID
		})
		signerSet := approvalSignerSet{
			Domain: "HELM/ApprovalSignerSet/v1", ChallengeHash: challenge.ChallengeHash,
			AuthoritySnapshotHash: challenge.AuthoritySnapshotHash, Signers: signers,
		}
		files[vectorCase.signerFile] = canonicalJSON(t, signerSet)
		files[vectorCase.projectionFile] = canonicalJSON(t, projection)
		caseIndexes = append(caseIndexes, approvalVectorCase{
			ID: vectorCase.id, AssertionKeyIDs: vectorCase.keys,
			SignerSet:          approvalVectorFile{Canonical: vectorCase.signerFile, SHA256: canonicalHashRef(t, signerSet)},
			VerifiedProjection: approvalVectorFile{Canonical: vectorCase.projectionFile, SHA256: canonicalHashRef(t, projection)},
			ExpectedStatus:     vectorCase.expectedStatus,
		})
	}

	index := approvalVectorIndex{
		Comment:           "quantum_posture: classical Ed25519 approval vectors only; no hybrid or post-quantum claim.",
		SchemaVersion:     "approval-vectors.v1",
		ContractVersion:   contracts.ApprovalChallengeContractV1,
		QuantumPosture:    "classical_ed25519_only",
		VerifiedAt:        now.UTC().Format(time.RFC3339Nano),
		AuthoritySnapshot: approvalVectorFile{Canonical: "authority_snapshot.c14n.json", SHA256: snapshotHash},
		Challenge:         approvalVectorFile{Canonical: "challenge.c14n.json", SHA256: challenge.ChallengeHash},
		Assertions:        assertionVectors,
		Cases:             caseIndexes,
		NegativeVectors: []approvalNegativeVector{
			{ID: "tampered_signature", Mutation: "flip_key-a_signature_last_bit", ExpectedError: "signature_rejected"},
			{ID: "cross_key_signature", Mutation: "verify_key-a_with_key-b", ExpectedError: "signature_rejected"},
			{ID: "challenge_tenant_substitution", Mutation: "set_challenge_tenant_id_to_tenant-b", ExpectedError: "challenge_hash_mismatch"},
			{ID: "assertion_key_substitution", Mutation: "set_key-a_assertion_key_id_to_key-b", ExpectedError: "signature_rejected"},
			{ID: "invalid_surplus_signature", Mutation: "flip_key-c_signature_in_over_quorum", ExpectedError: "signature_rejected"},
		},
	}
	indexJSON, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatalf("marshal approval vector index: %v", err)
	}
	files["vectors.json"] = append(indexJSON, '\n')
	return files
}

func canonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := canonicalize.JCS(value)
	if err != nil {
		t.Fatalf("canonicalize fixture: %v", err)
	}
	return append(raw, '\n')
}

func canonicalHashRef(t *testing.T, value any) string {
	t.Helper()
	hash, err := canonicalize.CanonicalHash(value)
	if err != nil {
		t.Fatalf("hash fixture: %v", err)
	}
	return "sha256:" + hash
}
