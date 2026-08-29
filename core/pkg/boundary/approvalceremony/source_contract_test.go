package approvalceremony

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestAuthoritySnapshotSealAndTamperDetection(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	publicKey := make([]byte, 32)
	for index := range publicKey {
		publicKey[index] = byte(index + 1)
	}
	snapshot, err := SealAuthoritySnapshot(AuthoritySnapshot{
		AuthoritySource: "control-plane-approver-registry", AuthorityVersion: "authority-v1",
		Keys: []AuthoritySnapshotKey{{
			KeyID: "key-1", TenantID: "tenant-1", PrincipalID: "approver-1",
			CredentialID: "credential-1", DeviceID: "device-1", PublicKey: hex.EncodeToString(publicKey),
			WorkspaceIDs: []string{"workspace-1", "workspace-1"}, Roles: []string{"reviewer", "reviewer"},
			Actions: []string{contracts.ApprovalGrantActionInstall}, Audiences: []string{"packs.lifecycle"},
			Enabled: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		}},
	})
	if err != nil {
		t.Fatalf("SealAuthoritySnapshot() error = %v", err)
	}
	if snapshot.Domain != AuthoritySnapshotDomainV1 || snapshot.SchemaVersion != AuthoritySnapshotSchemaV1 ||
		!strings.HasPrefix(snapshot.AuthoritySnapshotHash, "sha256:") || len(snapshot.Keys[0].Roles) != 1 {
		t.Fatalf("sealed snapshot = %#v", snapshot)
	}
	store, err := snapshot.TrustStore()
	if err != nil {
		t.Fatalf("TrustStore() error = %v", err)
	}
	if len(store.Keys) != 1 || len(store.Keys["key-1"].WorkspaceIDs) != 1 ||
		store.AuthoritySnapshotHash != snapshot.AuthoritySnapshotHash {
		t.Fatalf("trust store projection = %#v", store)
	}

	tampered := snapshot
	tampered.Keys = append([]AuthoritySnapshotKey(nil), snapshot.Keys...)
	tampered.Keys[0].Roles = []string{"administrator"}
	if _, err := tampered.TrustStore(); err == nil {
		t.Fatal("tampered authority snapshot must not verify")
	}
}

func TestAuthoritySnapshotRejectsAmbiguousOrUnusableKeys(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	base := AuthoritySnapshot{
		AuthoritySource: "control-plane-approver-registry", AuthorityVersion: "authority-v1",
		Keys: []AuthoritySnapshotKey{{
			KeyID: "key-1", TenantID: "tenant-1", PrincipalID: "approver-1", CredentialID: "credential-1",
			DeviceID: "device-1", PublicKey: strings.Repeat("ab", 32), WorkspaceIDs: []string{"workspace-1"},
			Roles: []string{"reviewer"}, Actions: []string{contracts.ApprovalGrantActionInstall},
			Audiences: []string{"packs.lifecycle"}, Enabled: true,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		}},
	}
	tests := map[string]func(*AuthoritySnapshot){
		"duplicate key id": func(snapshot *AuthoritySnapshot) {
			snapshot.Keys = append(snapshot.Keys, snapshot.Keys[0])
		},
		"non canonical public key": func(snapshot *AuthoritySnapshot) {
			snapshot.Keys[0].PublicKey = strings.ToUpper(snapshot.Keys[0].PublicKey)
		},
		"empty authority scope": func(snapshot *AuthoritySnapshot) {
			snapshot.Keys[0].WorkspaceIDs = nil
		},
		"no enabled key": func(snapshot *AuthoritySnapshot) {
			snapshot.Keys[0].Enabled = false
		},
		"non utc lifetime": func(snapshot *AuthoritySnapshot) {
			snapshot.Keys[0].NotBefore = snapshot.Keys[0].NotBefore.In(time.FixedZone("offset", 3600))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Keys = append([]AuthoritySnapshotKey(nil), base.Keys...)
			mutate(&candidate)
			if _, err := SealAuthoritySnapshot(candidate); err == nil {
				t.Fatal("SealAuthoritySnapshot() accepted invalid key material")
			}
		})
	}
}
