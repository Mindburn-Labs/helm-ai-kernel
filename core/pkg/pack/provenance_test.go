package pack_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/pack"
)

func makeProvenanceFixture() (ed25519.PublicKey, ed25519.PrivateKey, []byte, *pack.ProvenanceRecord) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	content := []byte(`{"name":"test-pack","version":"1.0.0"}`)

	h := sha256.Sum256(content)
	contentHash := "sha256:" + hex.EncodeToString(h[:])
	sig := ed25519.Sign(priv, []byte(contentHash))

	record := &pack.ProvenanceRecord{
		PackID:         "pack-prov-1",
		ContentHash:    contentHash,
		PublisherKeyID: "publisher-1",
		PublisherSig:   hex.EncodeToString(sig),
		Timestamp:      time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC),
		Version:        "1.0.0",
	}

	return pub, priv, content, record
}

func TestProvenanceVerifier_ValidProvenance(t *testing.T) {
	pub, _, content, record := makeProvenanceFixture()

	verifier := pack.NewProvenanceVerifier()
	verifier.AddTrustedKey("publisher-1", pub)

	result := verifier.Verify(record, content)
	if !result.Valid {
		t.Fatalf("expected valid provenance, got reason: %s", result.Reason)
	}
	if result.PackID != record.PackID {
		t.Errorf("PackID = %s, want %s", result.PackID, record.PackID)
	}
	if result.PublisherKeyID != record.PublisherKeyID {
		t.Errorf("PublisherKeyID = %s, want %s", result.PublisherKeyID, record.PublisherKeyID)
	}
}

func TestProvenanceVerifier_UntrustedPublisher(t *testing.T) {
	_, _, content, record := makeProvenanceFixture()

	verifier := pack.NewProvenanceVerifier()
	// Do NOT add the publisher key.

	result := verifier.Verify(record, content)
	if result.Valid {
		t.Fatal("expected provenance to be rejected for untrusted publisher")
	}
	if result.Reason == "" {
		t.Error("expected reason to be set")
	}
}

func TestProvenanceVerifier_ContentTampered(t *testing.T) {
	pub, _, _, record := makeProvenanceFixture()

	verifier := pack.NewProvenanceVerifier()
	verifier.AddTrustedKey("publisher-1", pub)

	tamperedContent := []byte(`{"name":"test-pack","version":"1.0.0","malicious":true}`)
	result := verifier.Verify(record, tamperedContent)
	if result.Valid {
		t.Fatal("expected provenance to be rejected for tampered content")
	}
	if result.Reason == "" {
		t.Error("expected reason to describe content hash mismatch")
	}
}

func TestProvenanceVerifier_SignatureInvalid(t *testing.T) {
	pub, _, content, record := makeProvenanceFixture()

	verifier := pack.NewProvenanceVerifier()
	verifier.AddTrustedKey("publisher-1", pub)

	// Corrupt the signature.
	sigBytes, _ := hex.DecodeString(record.PublisherSig)
	sigBytes[0] ^= 0xFF
	record.PublisherSig = hex.EncodeToString(sigBytes)

	result := verifier.Verify(record, content)
	if result.Valid {
		t.Fatal("expected provenance to be rejected for invalid signature")
	}
}

func TestProvenanceVerifier_KeyRotation(t *testing.T) {
	pub1, priv1, content, _ := makeProvenanceFixture()
	pub2, _, _, _ := makeProvenanceFixture()

	verifier := pack.NewProvenanceVerifier()
	verifier.AddTrustedKey("key-1", pub1)
	verifier.AddTrustedKey("key-2", pub2)

	// Verify with key-1.
	h := sha256.Sum256(content)
	contentHash := "sha256:" + hex.EncodeToString(h[:])
	sig := ed25519.Sign(priv1, []byte(contentHash))

	record := &pack.ProvenanceRecord{
		PackID:         "pack-rotation",
		ContentHash:    contentHash,
		PublisherKeyID: "key-1",
		PublisherSig:   hex.EncodeToString(sig),
		Timestamp:      time.Now().UTC(),
		Version:        "2.0.0",
	}

	result := verifier.Verify(record, content)
	if !result.Valid {
		t.Fatalf("expected valid with key-1: %s", result.Reason)
	}

	// Rotate: remove key-1.
	verifier.RemoveTrustedKey("key-1")

	if verifier.IsTrusted("key-1") {
		t.Error("key-1 should no longer be trusted after removal")
	}
	if !verifier.IsTrusted("key-2") {
		t.Error("key-2 should still be trusted")
	}

	// key-1 should now be rejected.
	result = verifier.Verify(record, content)
	if result.Valid {
		t.Fatal("expected provenance to be rejected after key rotation")
	}
}

func TestProvenanceVerifier_NilRecord(t *testing.T) {
	verifier := pack.NewProvenanceVerifier()

	result := verifier.Verify(nil, []byte("content"))
	if result.Valid {
		t.Fatal("expected invalid result for nil record")
	}
}

func TestProvenanceVerifier_IsTrusted(t *testing.T) {
	verifier := pack.NewProvenanceVerifier()

	if verifier.IsTrusted("nonexistent") {
		t.Error("expected false for nonexistent key")
	}

	verifier.AddTrustedKey("test-key", make([]byte, ed25519.PublicKeySize))
	if !verifier.IsTrusted("test-key") {
		t.Error("expected true after adding key")
	}
}

func TestProvenanceVerifier_ConcurrentVerification(t *testing.T) {
	pub, _, content, record := makeProvenanceFixture()

	verifier := pack.NewProvenanceVerifier()
	verifier.AddTrustedKey("publisher-1", pub)

	var wg sync.WaitGroup
	const goroutines = 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := verifier.Verify(record, content)
			if !result.Valid {
				t.Errorf("concurrent verification failed: %s", result.Reason)
			}
		}()
	}

	wg.Wait()
}

func TestProvenanceVerifier_BadSignatureEncoding(t *testing.T) {
	pub, _, content, record := makeProvenanceFixture()

	verifier := pack.NewProvenanceVerifier()
	verifier.AddTrustedKey("publisher-1", pub)

	record.PublisherSig = "not-valid-hex-$$$$"

	result := verifier.Verify(record, content)
	if result.Valid {
		t.Fatal("expected invalid result for bad signature encoding")
	}
}

func TestProvenanceVerifier_InvalidKeySize(t *testing.T) {
	_, _, content, record := makeProvenanceFixture()

	verifier := pack.NewProvenanceVerifier()
	verifier.AddTrustedKey("publisher-1", []byte("too-short"))

	result := verifier.Verify(record, content)
	if result.Valid {
		t.Fatal("expected invalid result for wrong key size")
	}
}
