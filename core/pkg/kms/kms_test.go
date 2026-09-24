package kms

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testBinding = Binding{Tenant: "tenant-a", Connection: "anthropic/access_token"}

func mustEncrypt(t *testing.T, k *LocalKMS, plaintext string, b Binding) string {
	t.Helper()
	ct, err := k.Encrypt(plaintext, b)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return ct
}

func mustDecrypt(t *testing.T, k *LocalKMS, ciphertext string, b Binding) string {
	t.Helper()
	pt, err := k.Decrypt(ciphertext, b)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	return pt
}

func tempKeystore(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "keys", "credentials.key")
}

func TestLocalKMS_NewGeneratesKey(t *testing.T) {
	path := tempKeystore(t)

	k, err := NewLocalKMS(path)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	if k.ActiveVersion() != 1 {
		t.Errorf("expected active version 1, got %d", k.ActiveVersion())
	}

	// File should exist with restricted perms
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("keystore file missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("keystore permissions = %o, want 0600", perm)
	}
}

func TestLocalKMS_EncryptDecrypt(t *testing.T) {
	k, err := NewLocalKMS(tempKeystore(t))
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	plaintext := "sk-secret-api-key-1234567890"

	ct, err := k.Encrypt(plaintext, testBinding)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if ct == plaintext {
		t.Error("ciphertext equals plaintext")
	}

	// Must start with the bound version prefix
	if !strings.HasPrefix(ct, "aad1:v1:") {
		t.Errorf("ciphertext = %q, want aad1:v1: prefix", ct)
	}

	pt, err := k.Decrypt(ct, testBinding)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if pt != plaintext {
		t.Errorf("round-trip failed: got %q, want %q", pt, plaintext)
	}
}

func TestLocalKMS_EncryptEmpty(t *testing.T) {
	k, err := NewLocalKMS(tempKeystore(t))
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	ct, err := k.Encrypt("", testBinding)
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	if ct != "" {
		t.Errorf("expected empty ciphertext for empty plaintext, got %q", ct)
	}

	pt, err := k.Decrypt("", testBinding)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if pt != "" {
		t.Errorf("expected empty plaintext for empty ciphertext, got %q", pt)
	}
}

func TestLocalKMS_Rotate(t *testing.T) {
	k, err := NewLocalKMS(tempKeystore(t))
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	// Encrypt with v1
	ct1, err := k.Encrypt("secret-v1", testBinding)
	if err != nil {
		t.Fatalf("Encrypt v1: %v", err)
	}

	// Rotate to v2
	v, err := k.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if v != 2 {
		t.Errorf("new version = %d, want 2", v)
	}
	if k.ActiveVersion() != 2 {
		t.Errorf("active version = %d, want 2", k.ActiveVersion())
	}

	// Encrypt with v2
	ct2, err := k.Encrypt("secret-v2", testBinding)
	if err != nil {
		t.Fatalf("Encrypt v2: %v", err)
	}

	if !strings.HasPrefix(ct2, "aad1:v2:") {
		t.Errorf("v2 ciphertext = %q, want aad1:v2: prefix", ct2)
	}

	// Old v1 ciphertext still decryptable
	pt1, err := k.Decrypt(ct1, testBinding)
	if err != nil {
		t.Fatalf("Decrypt v1 after rotate: %v", err)
	}
	if pt1 != "secret-v1" {
		t.Errorf("v1 decrypt = %q, want %q", pt1, "secret-v1")
	}

	// v2 ciphertext decryptable
	pt2, err := k.Decrypt(ct2, testBinding)
	if err != nil {
		t.Fatalf("Decrypt v2: %v", err)
	}
	if pt2 != "secret-v2" {
		t.Errorf("v2 decrypt = %q, want %q", pt2, "secret-v2")
	}
}

func TestLocalKMS_Persistence(t *testing.T) {
	path := tempKeystore(t)

	// Create and encrypt
	k1, err := NewLocalKMS(path)
	if err != nil {
		t.Fatalf("NewLocalKMS 1: %v", err)
	}

	ct, err := k1.Encrypt("persistent-secret", testBinding)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Reload from disk
	k2, err := NewLocalKMS(path)
	if err != nil {
		t.Fatalf("NewLocalKMS 2: %v", err)
	}

	pt, err := k2.Decrypt(ct, testBinding)
	if err != nil {
		t.Fatalf("Decrypt after reload: %v", err)
	}
	if pt != "persistent-secret" {
		t.Errorf("persistence round-trip = %q, want %q", pt, "persistent-secret")
	}
}

func TestLocalKMS_ImportKey(t *testing.T) {
	path := tempKeystore(t)

	k, err := NewLocalKMS(path)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	// Simulate importing an env-sourced key
	legacyKey := make([]byte, 32)
	for i := range legacyKey {
		legacyKey[i] = byte(i)
	}

	if err := k.ImportKey(legacyKey, 0); err != nil {
		t.Fatalf("ImportKey: %v", err)
	}

	// Imported for decryption only: the generated v1 stays active (16-02).
	if k.ActiveVersion() != 1 {
		t.Errorf("active version = %d, want 1", k.ActiveVersion())
	}

	// Bad key size
	if err := k.ImportKey([]byte("short"), 99); err == nil {
		t.Error("ImportKey should reject short key")
	}
}
