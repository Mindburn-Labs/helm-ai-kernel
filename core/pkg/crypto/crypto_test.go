package crypto

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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

func TestEd25519Signer_SignReceiptSetsProfileMetadata(t *testing.T) {
	signer, err := NewEd25519Signer("key-1")
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	receipt := &contracts.Receipt{
		ReceiptID:    "rcpt-ed-001",
		DecisionID:   "dec-ed-001",
		EffectID:     "eff-ed-001",
		Status:       "EXECUTED",
		OutputHash:   "sha256:out",
		PrevHash:     "sha256:prev",
		LamportClock: 1,
		ArgsHash:     "sha256:args",
		Timestamp:    time.Now(),
	}
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatalf("SignReceipt failed: %v", err)
	}
	if receipt.SignatureProfile != ReceiptProfileClassical {
		t.Fatalf("signature_profile = %q", receipt.SignatureProfile)
	}
	if receipt.SignatureAlgorithm != SigPrefixEd25519 {
		t.Fatalf("signature_algorithm = %q", receipt.SignatureAlgorithm)
	}
	if receipt.KeyID != "key-1" {
		t.Fatalf("key_id = %q", receipt.KeyID)
	}
	if receipt.PublicKeySet[SigPrefixEd25519] != signer.PublicKey() {
		t.Fatalf("public_key_set = %#v", receipt.PublicKeySet)
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
