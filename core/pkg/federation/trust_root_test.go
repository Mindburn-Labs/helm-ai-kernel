package federation

import (
	"testing"
	"time"
)

func makeTestRoot(orgID string) OrgTrustRoot {
	return OrgTrustRoot{
		OrgID:         orgID,
		OrgDID:        "did:helm:" + orgID,
		OrgName:       "Org " + orgID,
		PublicKey:     "aabbccdd" + orgID,
		Algorithm:     "ed25519",
		EstablishedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestTrustRootStore_Register(t *testing.T) {
	store := NewTrustRootStore()

	root := makeTestRoot("org-alpha")
	if err := store.Register(root); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	got, ok := store.Get("org-alpha")
	if !ok {
		t.Fatal("Get returned false for registered org")
	}
	if got.OrgID != "org-alpha" {
		t.Errorf("OrgID = %q, want %q", got.OrgID, "org-alpha")
	}
	if got.ContentHash == "" {
		t.Error("ContentHash should be computed on register")
	}
	if got.Revoked {
		t.Error("Revoked should be false for new org")
	}
}

func TestTrustRootStore_Register_EmptyOrgID(t *testing.T) {
	store := NewTrustRootStore()
	root := OrgTrustRoot{PublicKey: "abc123"}
	if err := store.Register(root); err == nil {
		t.Fatal("Register should fail with empty org_id")
	}
}

func TestTrustRootStore_Register_EmptyPublicKey(t *testing.T) {
	store := NewTrustRootStore()
	root := OrgTrustRoot{OrgID: "org-1"}
	if err := store.Register(root); err == nil {
		t.Fatal("Register should fail with empty public key")
	}
}

func TestTrustRootStore_Register_Duplicate(t *testing.T) {
	store := NewTrustRootStore()
	root := makeTestRoot("org-alpha")
	if err := store.Register(root); err != nil {
		t.Fatalf("first Register failed: %v", err)
	}
	if err := store.Register(root); err == nil {
		t.Fatal("duplicate Register should fail")
	}
}

func TestTrustRootStore_Register_AfterRevoke(t *testing.T) {
	store := NewTrustRootStore()
	root := makeTestRoot("org-alpha")
	if err := store.Register(root); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if err := store.Revoke("org-alpha"); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	// Re-registering after revoke should succeed.
	newRoot := makeTestRoot("org-alpha")
	newRoot.PublicKey = "newkey123"
	if err := store.Register(newRoot); err != nil {
		t.Fatalf("re-Register after revoke failed: %v", err)
	}
}

func TestTrustRootStore_Revoke(t *testing.T) {
	store := NewTrustRootStore()
	root := makeTestRoot("org-beta")
	if err := store.Register(root); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if !store.IsTrusted("org-beta") {
		t.Fatal("org should be trusted before revoke")
	}

	if err := store.Revoke("org-beta"); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	if store.IsTrusted("org-beta") {
		t.Fatal("org should not be trusted after revoke")
	}

	got, ok := store.Get("org-beta")
	if !ok {
		t.Fatal("Get should still return revoked org")
	}
	if !got.Revoked {
		t.Error("Revoked flag should be true")
	}
}

func TestTrustRootStore_Revoke_NotFound(t *testing.T) {
	store := NewTrustRootStore()
	if err := store.Revoke("nonexistent"); err == nil {
		t.Fatal("Revoke should fail for nonexistent org")
	}
}

func TestTrustRootStore_Get_NotFound(t *testing.T) {
	store := NewTrustRootStore()
	_, ok := store.Get("nonexistent")
	if ok {
		t.Fatal("Get should return false for nonexistent org")
	}
}

func TestTrustRootStore_IsTrusted_NotFound(t *testing.T) {
	store := NewTrustRootStore()
	if store.IsTrusted("nonexistent") {
		t.Fatal("IsTrusted should return false for nonexistent org")
	}
}

func TestTrustRootStore_ListTrusted(t *testing.T) {
	store := NewTrustRootStore()

	// Register three orgs, revoke one.
	for _, id := range []string{"org-c", "org-a", "org-b"} {
		root := makeTestRoot(id)
		if err := store.Register(root); err != nil {
			t.Fatalf("Register %s failed: %v", id, err)
		}
	}
	if err := store.Revoke("org-b"); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	trusted := store.ListTrusted()
	if len(trusted) != 2 {
		t.Fatalf("ListTrusted returned %d orgs, want 2", len(trusted))
	}

	// Verify sorted order (org-a, org-c).
	if trusted[0].OrgID != "org-a" {
		t.Errorf("trusted[0].OrgID = %q, want %q", trusted[0].OrgID, "org-a")
	}
	if trusted[1].OrgID != "org-c" {
		t.Errorf("trusted[1].OrgID = %q, want %q", trusted[1].OrgID, "org-c")
	}
}

func TestTrustRootStore_ListTrusted_Empty(t *testing.T) {
	store := NewTrustRootStore()
	trusted := store.ListTrusted()
	if len(trusted) != 0 {
		t.Fatalf("ListTrusted returned %d orgs for empty store, want 0", len(trusted))
	}
}
