// quantum_posture: this test verifies classical Ed25519 reference vectors;
// it does not claim hybrid or post-quantum approval support.
package approvalverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type approvalVectorRef struct {
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

type approvalVectorIndex struct {
	AuthoritySnapshot approvalVectorRef `json:"authority_snapshot"`
	Challenge         approvalVectorRef `json:"challenge"`
	Assertions        []struct {
		KeyID          string                      `json:"key_id"`
		SigningPayload string                      `json:"signing_payload"`
		SigningDigest  string                      `json:"signing_digest"`
		PublicKey      string                      `json:"public_key"`
		Signature      string                      `json:"signature"`
		Assertion      contracts.ApprovalAssertion `json:"assertion"`
		AssertionHash  string                      `json:"assertion_hash"`
	} `json:"assertions"`
	Cases []struct {
		ID                 string            `json:"id"`
		AssertionKeyIDs    []string          `json:"assertion_key_ids"`
		SignerSet          approvalVectorRef `json:"signer_set"`
		VerifiedProjection approvalVectorRef `json:"verified_projection"`
	} `json:"cases"`
}

type approvalAuthoritySnapshot struct {
	Domain           string `json:"domain"`
	AuthoritySource  string `json:"authority_source"`
	AuthorityVersion string `json:"authority_version"`
	Keys             []struct {
		KeyID        string    `json:"key_id"`
		TenantID     string    `json:"tenant_id"`
		PrincipalID  string    `json:"principal_id"`
		CredentialID string    `json:"credential_id"`
		DeviceID     string    `json:"device_id"`
		PublicKey    string    `json:"public_key"`
		WorkspaceIDs []string  `json:"workspace_ids"`
		Roles        []string  `json:"roles"`
		Actions      []string  `json:"actions"`
		Audiences    []string  `json:"audiences"`
		Enabled      bool      `json:"enabled"`
		NotBefore    time.Time `json:"not_before"`
		NotAfter     time.Time `json:"not_after"`
	} `json:"keys"`
}

func TestApprovalReferencePack(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", "..", "..", "reference_packs", "approval"))
	var index approvalVectorIndex
	readJSON(t, filepath.Join(root, "vectors.json"), &index)

	var snapshot approvalAuthoritySnapshot
	readCanonicalJSON(t, root, index.AuthoritySnapshot, &snapshot)
	var challenge contracts.ApprovalChallenge
	readCanonicalJSON(t, root, index.Challenge, &challenge)
	challenge.ChallengeHash = index.Challenge.SHA256
	sealed, err := challenge.Seal()
	if err != nil || sealed.ChallengeHash != challenge.ChallengeHash {
		t.Fatalf("challenge seal = %q, %v; want %q", sealed.ChallengeHash, err, challenge.ChallengeHash)
	}

	store := TrustStore{
		AuthoritySource:       snapshot.AuthoritySource,
		AuthorityVersion:      snapshot.AuthorityVersion,
		AuthoritySnapshotHash: index.AuthoritySnapshot.SHA256,
		Keys:                  make(map[string]TrustedApproverKey, len(snapshot.Keys)),
	}
	for _, source := range snapshot.Keys {
		publicKey := decodeEd25519Vector(t, source.PublicKey, ed25519.PublicKeySize)
		store.Keys[source.KeyID] = TrustedApproverKey{
			KeyID: source.KeyID, TenantID: source.TenantID, PrincipalID: source.PrincipalID,
			CredentialID: source.CredentialID, DeviceID: source.DeviceID, PublicKey: publicKey,
			WorkspaceIDs: source.WorkspaceIDs, Roles: source.Roles, Actions: source.Actions,
			Audiences: source.Audiences, Enabled: source.Enabled,
			NotBefore: source.NotBefore, NotAfter: source.NotAfter,
		}
	}

	assertions := make(map[string]contracts.ApprovalAssertion, len(index.Assertions))
	for _, vector := range index.Assertions {
		var payload any
		readCanonicalJSON(t, root, approvalVectorRef{Canonical: vector.SigningPayload, SHA256: vector.SigningDigest}, &payload)
		if vector.KeyID != vector.Assertion.KeyID || vector.Signature != vector.Assertion.Signature {
			t.Fatalf("%s: assertion envelope mismatch", vector.KeyID)
		}
		key, ok := store.Keys[vector.KeyID]
		if !ok || vector.PublicKey != "ed25519:"+hex.EncodeToString(key.PublicKey) {
			t.Fatalf("%s: authority public key mismatch", vector.KeyID)
		}
		digest, err := vector.Assertion.SigningDigest()
		if err != nil || "sha256:"+hex.EncodeToString(digest) != vector.SigningDigest {
			t.Fatalf("%s: signing digest = %x, %v; want %s", vector.KeyID, digest, err, vector.SigningDigest)
		}
		assertionHash, err := canonicalize.CanonicalHash(vector.Assertion)
		if err != nil || "sha256:"+assertionHash != vector.AssertionHash {
			t.Fatalf("%s: assertion hash = %s, %v; want %s", vector.KeyID, assertionHash, err, vector.AssertionHash)
		}
		assertions[vector.KeyID] = vector.Assertion
	}

	for _, vectorCase := range index.Cases {
		t.Run(vectorCase.ID, func(t *testing.T) {
			var expected VerifiedApprovalRef
			readCanonicalJSON(t, root, vectorCase.VerifiedProjection, &expected)
			var signerSet any
			readCanonicalJSON(t, root, vectorCase.SignerSet, &signerSet)
			selected := make([]contracts.ApprovalAssertion, 0, len(vectorCase.AssertionKeyIDs))
			for _, keyID := range vectorCase.AssertionKeyIDs {
				assertion, ok := assertions[keyID]
				if !ok {
					t.Fatalf("unknown assertion key %s", keyID)
				}
				selected = append(selected, assertion)
			}
			got, err := VerifyQuorum(challenge, selected, store, VerifyOptions{
				Expected: bindingFromProjection(expected), MinHoldDuration: 5 * time.Minute,
				MaxChallengeTTL: 20 * time.Minute, MaxAssertions: 4,
			}, expected.VerifiedAt)
			if err != nil {
				t.Fatalf("VerifyQuorum() error = %v", err)
			}
			if !reflect.DeepEqual(got, expected) {
				t.Fatalf("VerifyQuorum() = %#v, want %#v", got, expected)
			}
		})
	}
}

func readJSON(t *testing.T, path string, target any) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return raw
}

func readCanonicalJSON(t *testing.T, root string, ref approvalVectorRef, target any) {
	t.Helper()
	raw := strings.TrimSuffix(string(readJSON(t, filepath.Join(root, ref.Canonical), target)), "\n")
	hash := sha256.Sum256([]byte(raw))
	if got := "sha256:" + hex.EncodeToString(hash[:]); got != ref.SHA256 {
		t.Fatalf("%s: hash = %s, want %s", ref.Canonical, got, ref.SHA256)
	}
	canonical, err := canonicalize.JCSString(target)
	if err != nil || canonical != raw {
		t.Fatalf("%s is not canonical JSON: %v", ref.Canonical, err)
	}
}

func decodeEd25519Vector(t *testing.T, value string, size int) []byte {
	t.Helper()
	if !strings.HasPrefix(value, "ed25519:") {
		t.Fatalf("expected ed25519 vector, got %q", value)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "ed25519:"))
	if err != nil || len(raw) != size {
		t.Fatalf("invalid ed25519 vector %q", value)
	}
	return raw
}
