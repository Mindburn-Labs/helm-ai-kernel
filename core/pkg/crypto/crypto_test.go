package crypto

import (
	"testing"
)

func TestCanonicalHasher_Hash(t *testing.T) {
	h := NewCanonicalHasher()

	// Test map sorting determinism
	m1 := map[string]int{"a": 1, "b": 2}
	m2 := map[string]int{"b": 2, "a": 1}

	h1, err := h.Hash(m1)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}
	h2, err := h.Hash(m2)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if h1 != h2 {
		t.Errorf("Maps with different key order should produce same hash")
	}
}

func TestEd25519Signer_SignVerify(t *testing.T) {
	signer, err := NewEd25519Signer("key-1")
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	data := []byte("hello world")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pubKey := signer.PublicKey()

	valid, err := Verify(pubKey, sig, data)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("Signature verification failed")
	}

	// Test tampering
	valid, _ = Verify(pubKey, sig, []byte("hello world modified"))
	if valid {
		t.Error("Tampered data should not verify")
	}
}

func TestAuditLog_Append(t *testing.T) {
	log := NewMemoryAuditLog()

	err := log.Append("user-1", "login", map[string]string{"ip": "127.0.0.1"})
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	entries := log.Entries()
	if len(entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(entries))
	}
	if entries[0].Hash == "" {
		t.Error("Expected hash to be populated")
	}
}
