package trust

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifySignatures_ThresholdEnforcement(t *testing.T) {
	// 1. Setup Keys
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyID := "key-1"

	verifier := NewSignatureVerifier(map[string]crypto.PublicKey{
		keyID: pub,
	})

	// 2. Create Content
	content := []byte(`{"test":"content"}`)
	hash := sha256.Sum256(content)

	// 3. Sign Content
	sig := ed25519.Sign(priv, hash[:])

	role := &SignedRole{
		Signed: content,
		Signatures: []TUFSignature{
			{
				KeyID:     keyID,
				Signature: base64.StdEncoding.EncodeToString(sig),
			},
		},
	}

	// 4. Test Thresholds
	if err := verifier.VerifySignatures(role, 1); err != nil {
		t.Errorf("Expected success with threshold 1, got %v", err)
	}

	if err := verifier.VerifySignatures(role, 2); err == nil {
		t.Error("Expected failure with threshold 2, got success")
	}
}

func TestVerifySignatures_UnknownKey(t *testing.T) {
	// 1. Setup Verifier with NO keys
	verifier := NewSignatureVerifier(map[string]crypto.PublicKey{})

	// 2. Create Signed Content (with a valid key that the verifier doesn't know)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	content := []byte(`{"test":"content"}`)
	hash := sha256.Sum256(content)
	sig := ed25519.Sign(priv, hash[:])

	role := &SignedRole{
		Signed: content,
		Signatures: []TUFSignature{
			{
				KeyID:     "unknown-key",
				Signature: base64.StdEncoding.EncodeToString(sig),
			},
		},
	}

	// 3. Verify -> Should fail because verifier has no trusted keys for this signature
	if err := verifier.VerifySignatures(role, 1); err == nil {
		t.Error("Expected failure for unknown key, got success")
	}
}

func TestVerifySignatures_TamperedContent(t *testing.T) {
	// 1. Setup Keys
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyID := "key-tamper"

	verifier := NewSignatureVerifier(map[string]crypto.PublicKey{
		keyID: pub,
	})

	// 2. Sign Original Content
	original := []byte(`{"legit":"data"}`)
	hash := sha256.Sum256(original)
	sig := ed25519.Sign(priv, hash[:])

	// 3. Tamper with Content
	tampered := []byte(`{"legit":"hacked"}`)

	role := &SignedRole{
		Signed: tampered, // <--- CHANGED
		Signatures: []TUFSignature{
			{
				KeyID:     keyID,
				Signature: base64.StdEncoding.EncodeToString(sig), // Signature matches ORIGINAL
			},
		},
	}

	// 4. Verify -> Should fail
	if err := verifier.VerifySignatures(role, 1); err == nil {
		t.Error("Expected failure for tampered content, got success")
	}
}
