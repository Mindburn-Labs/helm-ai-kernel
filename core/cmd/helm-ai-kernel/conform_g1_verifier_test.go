package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestConformG1ReceiptVerifierFromEnv(t *testing.T) {
	t.Setenv("HELM_CONFORM_RECEIPT_PUBLIC_KEY_HEX", "")

	verifier, err := conformG1ReceiptVerifierFromEnv()
	if err != nil {
		t.Fatalf("empty env verifier returned error: %v", err)
	}
	if verifier != nil {
		t.Fatal("empty env should not configure a verifier")
	}

	t.Setenv("HELM_CONFORM_RECEIPT_PUBLIC_KEY_HEX", "not-hex")
	if _, err := conformG1ReceiptVerifierFromEnv(); err == nil {
		t.Fatal("invalid public key hex should fail")
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t.Setenv("HELM_CONFORM_RECEIPT_PUBLIC_KEY_HEX", hex.EncodeToString(publicKey))

	verifier, err = conformG1ReceiptVerifierFromEnv()
	if err != nil {
		t.Fatalf("configured verifier returned error: %v", err)
	}
	if verifier == nil {
		t.Fatal("configured env should return verifier")
	}

	data := []byte("receipt canonical bytes")
	sig := hex.EncodeToString(ed25519.Sign(privateKey, data))
	if err := verifier(data, sig); err != nil {
		t.Fatalf("valid receipt signature rejected: %v", err)
	}
	if err := verifier([]byte("tampered"), sig); err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("tampered receipt signature accepted: %v", err)
	}
}
