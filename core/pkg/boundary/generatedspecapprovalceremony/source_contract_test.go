package generatedspecapprovalceremony

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestAuthoritySnapshotSealAndTamperDetection(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	publicKey := make([]byte, 32)
	for index := range publicKey {
		publicKey[index] = byte(index + 1)
	}
	snapshot, err := SealAuthoritySnapshot(AuthoritySnapshot{
		AuthoritySource:  "control-plane-approver-registry",
		AuthorityVersion: "authority-v1",
		Keys: []AuthoritySnapshotKey{{
			KeyID: "key-1", TenantID: "tenant-1", PrincipalID: "approver-1",
			CredentialID: "credential-1", DeviceID: "device-1", PublicKey: hex.EncodeToString(publicKey),
			WorkspaceIDs: []string{"workspace-1", "workspace-1"}, Roles: []string{"reviewer"},
			Actions:   []string{contracts.GeneratedSpecApprovalActionV1},
			Audiences: []string{contracts.GeneratedSpecApprovalAudienceV1}, Enabled: true,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		}},
	})
	if err != nil {
		t.Fatalf("seal authority snapshot: %v", err)
	}
	store, err := snapshot.TrustStore()
	if err != nil {
		t.Fatalf("project trust store: %v", err)
	}
	if len(store.Keys) != 1 || len(store.Keys["key-1"].WorkspaceIDs) != 1 || store.AuthoritySnapshotHash != snapshot.AuthoritySnapshotHash {
		t.Fatalf("unexpected trust store projection: %#v", store)
	}

	tampered := snapshot
	tampered.Keys = append([]AuthoritySnapshotKey(nil), snapshot.Keys...)
	tampered.Keys[0].Roles = []string{"administrator"}
	if _, err := tampered.TrustStore(); err == nil {
		t.Fatal("tampered authority snapshot must not verify")
	}
}
