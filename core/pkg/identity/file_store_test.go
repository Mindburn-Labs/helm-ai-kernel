package identity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileStore_StoreAndLoad(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	session := NewDelegationSession(
		"sess-001", "delegator-1", "delegate-1",
		"nonce-abc", "policy-hash-1", "trust-root-1",
		42, time.Now().Add(1*time.Hour), true, nil,
	)
	session.AddAllowedTool("read_file")
	session.AddAllowedTool("write_file")

	if err := store.Store(session); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	loaded, err := store.Load("sess-001")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.SessionID != "sess-001" {
		t.Errorf("SessionID mismatch: got %s", loaded.SessionID)
	}
	if loaded.DelegatorPrincipal != "delegator-1" {
		t.Errorf("Delegator mismatch: got %s", loaded.DelegatorPrincipal)
	}
	if len(loaded.AllowedTools) != 2 {
		t.Errorf("AllowedTools count: got %d, want 2", len(loaded.AllowedTools))
	}
}

func TestFileStore_LoadNotFound(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileStore(dir)

	// Not found returns nil, nil (matching InMemoryDelegationStore behavior).
	session, err := store.Load("nonexistent")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if session != nil {
		t.Error("expected nil session for nonexistent ID")
	}
}

func TestFileStore_Revoke(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileStore(dir)

	session := NewDelegationSession(
		"sess-revoke", "d1", "d2", "n", "p", "t", 0,
		time.Now().Add(1*time.Hour), false, nil,
	)
	store.Store(session)

	if err := store.Revoke("sess-revoke"); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	_, err := store.Load("sess-revoke")
	if err == nil {
		t.Error("expected error loading revoked session")
	}
}

func TestFileStore_NonceAntiReplay(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileStore(dir)

	if store.IsNonceUsed("nonce-001") {
		t.Error("fresh nonce should not be used")
	}

	store.MarkNonceUsed("nonce-001")

	if !store.IsNonceUsed("nonce-001") {
		t.Error("marked nonce should be used")
	}

	if store.IsNonceUsed("nonce-002") {
		t.Error("different nonce should not be used")
	}
}

func TestFileStore_ListSessions(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileStore(dir)

	for _, id := range []string{"sess-a", "sess-b", "sess-c"} {
		s := NewDelegationSession(id, "d", "d", "n", "p", "t", 0,
			time.Now().Add(1*time.Hour), false, nil)
		store.Store(s)
	}

	ids, err := store.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 {
		t.Errorf("expected 3 sessions, got %d", len(ids))
	}
}

func TestFileStore_Permissions(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileStore(dir)

	s := NewDelegationSession("perm-test", "d", "d", "n", "p", "t", 0,
		time.Now().Add(1*time.Hour), false, nil)
	store.Store(s)

	path := filepath.Join(dir, "perm-test.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected 0600 permissions, got %o", perm)
	}
}
