package registry

import (
	"crypto/ed25519"
	"testing"
)

func TestTrustRegistry_AddAndResolve(t *testing.T) {
	r := NewTrustRegistry()

	_, privKey, _ := ed25519.GenerateKey(nil)
	pubKey := privKey.Public().(ed25519.PublicKey)

	err := r.Apply(LegacyTrustEvent{
		EventType: "KEY_ADDED",
		TenantID:  "tenant-1",
		KeyID:     "k-1",
		PublicKey: pubKey,
		Lamport:   1,
	})
	if err != nil {
		t.Fatal(err)
	}

	keys, err := r.ResolveAuthorizedKeys("tenant-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

func TestTrustRegistry_RevokeKey(t *testing.T) {
	r := NewTrustRegistry()

	_, privKey, _ := ed25519.GenerateKey(nil)
	pubKey := privKey.Public().(ed25519.PublicKey)

	_ = r.Apply(LegacyTrustEvent{EventType: "KEY_ADDED", TenantID: "t1", KeyID: "k1", PublicKey: pubKey, Lamport: 1})
	_ = r.Apply(LegacyTrustEvent{EventType: "KEY_REVOKED", TenantID: "t1", KeyID: "k1", Lamport: 2})

	if r.IsAuthorized("t1", "k1") {
		t.Error("key should be revoked")
	}

	keys, _ := r.ResolveAuthorizedKeys("t1", 0)
	if len(keys) != 0 {
		t.Errorf("expected 0 keys after revoke, got %d", len(keys))
	}
}

func TestTrustRegistry_PointInTimeResolution(t *testing.T) {
	r := NewTrustRegistry()

	_, privKey, _ := ed25519.GenerateKey(nil)
	pubKey := privKey.Public().(ed25519.PublicKey)

	_ = r.Apply(LegacyTrustEvent{EventType: "KEY_ADDED", TenantID: "t1", KeyID: "k1", PublicKey: pubKey, Lamport: 1})
	_ = r.Apply(LegacyTrustEvent{EventType: "KEY_REVOKED", TenantID: "t1", KeyID: "k1", Lamport: 5})

	// At Lamport 3, key should still exist
	keys, _ := r.ResolveAuthorizedKeys("t1", 3)
	if len(keys) != 1 {
		t.Fatalf("at lamport 3, expected 1 key, got %d", len(keys))
	}

	// At Lamport 6, key should be revoked
	keys, _ = r.ResolveAuthorizedKeys("t1", 6)
	if len(keys) != 0 {
		t.Fatalf("at lamport 6, expected 0 keys, got %d", len(keys))
	}
}

func TestTrustRegistry_KeyRotation(t *testing.T) {
	r := NewTrustRegistry()

	_, privKey1, _ := ed25519.GenerateKey(nil)
	pubKey1 := privKey1.Public().(ed25519.PublicKey)

	_, privKey2, _ := ed25519.GenerateKey(nil)
	pubKey2 := privKey2.Public().(ed25519.PublicKey)

	_ = r.Apply(LegacyTrustEvent{EventType: "KEY_ADDED", TenantID: "t1", KeyID: "k1", PublicKey: pubKey1, Lamport: 1})
	_ = r.Apply(LegacyTrustEvent{EventType: "KEY_ROTATED", TenantID: "t1", KeyID: "k1", PublicKey: pubKey2, Lamport: 3})

	if !r.IsAuthorized("t1", "k1") {
		t.Error("rotated key should still be authorized")
	}

	if r.EventCount() != 2 {
		t.Errorf("expected 2 events, got %d", r.EventCount())
	}
}

func TestTrustRegistry_UnknownEventType(t *testing.T) {
	r := NewTrustRegistry()
	err := r.Apply(LegacyTrustEvent{EventType: "UNKNOWN", TenantID: "t1", KeyID: "k1"})
	if err == nil {
		t.Error("expected error for unknown event type")
	}
}
