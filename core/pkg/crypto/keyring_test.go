package crypto

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func TestKeyRing_DeterministicSigning(t *testing.T) {
	kr := NewKeyRing()

	// Add multiple keys with specific IDs
	k1, _ := NewEd25519Signer("key1")
	k2, _ := NewEd25519Signer("key2")
	k3, _ := NewEd25519Signer("key3")

	kr.AddKey(k1)
	kr.AddKey(k2)
	kr.AddKey(k3)

	// Sign a decision
	d := &contracts.DecisionRecord{
		ID:      "decision-1",
		Verdict: "ALLOW",
		Reason:  "Test",
	}

	if err := kr.SignDecision(d); err != nil {
		t.Fatalf("SignDecision failed: %v", err)
	}

	// Verify the signature is from the lexicographically last key ("key3")
	if !strings.HasSuffix(d.SignatureType, ":key3") {
		t.Errorf("Expected signature from key3, got %s", d.SignatureType)
	}

	// Verify the signature works
	valid, err := kr.VerifyDecision(d)
	if err != nil {
		t.Fatalf("VerifyDecision failed: %v", err)
	}
	if !valid {
		t.Error("VerifyDecision returned false")
	}
}

func TestKeyRing_VerifyKey(t *testing.T) {
	kr := NewKeyRing()
	k1, _ := NewEd25519Signer("key1")
	kr.AddKey(k1)

	msg := []byte("hello world")
	sigHex, err := k1.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	sigBytes, _ := hex.DecodeString(sigHex)

	valid, err := kr.VerifyKey("key1", msg, sigBytes)
	if err != nil {
		t.Fatalf("VerifyKey failed: %v", err)
	}
	if !valid {
		t.Error("VerifyKey returned false")
	}

	// Test unknown key
	_, err = kr.VerifyKey("unknown", msg, sigBytes)
	if err == nil {
		t.Error("VerifyKey should fail for unknown key")
	}
}
