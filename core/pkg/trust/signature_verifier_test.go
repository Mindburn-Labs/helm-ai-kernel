package trust

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

func TestVerifySignatures_EdgeCases(t *testing.T) {
	verifier := NewSignatureVerifier(map[string]crypto.PublicKey{})
	if err := verifier.VerifySignatures(nil, 1); err == nil {
		t.Fatal("expected nil signed role error")
	}
	if err := verifier.VerifySignatures(&SignedRole{}, 1); err == nil {
		t.Fatal("expected missing signatures error")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"test":"content"}`)
	hash := sha256.Sum256(content)
	sig := ed25519.Sign(priv, hash[:])
	verifier = NewSignatureVerifier(map[string]crypto.PublicKey{"key-1": pub})
	role := &SignedRole{
		Signed: content,
		Signatures: []TUFSignature{
			{KeyID: "key-1", Signature: base64.StdEncoding.EncodeToString(sig)},
			{KeyID: "key-1", Signature: base64.StdEncoding.EncodeToString(sig)},
			{KeyID: "key-1", Signature: "not-decodable"},
		},
	}
	if err := verifier.VerifySignatures(role, 0); err != nil {
		t.Fatalf("threshold default with duplicate signature: %v", err)
	}
	if data, err := decodeSignature("ff"); err != nil || len(data) != 1 || data[0] != 0xff {
		t.Fatalf("hex decode got %x err=%v", data, err)
	}
	if _, err := decodeSignature("!"); err == nil {
		t.Fatal("expected undecodable signature error")
	}

	unsupported := NewSignatureVerifier(map[string]crypto.PublicKey{"key-1": struct{}{}})
	if err := unsupported.VerifySignatures(&SignedRole{
		Signed:     content,
		Signatures: []TUFSignature{{KeyID: "key-1", Signature: hex.EncodeToString([]byte("sig"))}},
	}, 1); err == nil {
		t.Fatal("expected unsupported key type to fail")
	}

	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig2 := ed25519.Sign(priv2, hash[:])
	twoKeys := NewSignatureVerifier(map[string]crypto.PublicKey{"key-1": pub, "key-2": pub2})
	duplicateRole := &SignedRole{
		Signed: content,
		Signatures: []TUFSignature{
			{KeyID: "key-1", Signature: base64.StdEncoding.EncodeToString(sig)},
			{KeyID: "key-1", Signature: base64.StdEncoding.EncodeToString(sig)},
			{KeyID: "key-2", Signature: base64.StdEncoding.EncodeToString(sig2)},
		},
	}
	if err := twoKeys.VerifySignatures(duplicateRole, 2); err != nil {
		t.Fatalf("duplicate key skip with second key: %v", err)
	}

	invalidEncoding := NewSignatureVerifier(map[string]crypto.PublicKey{"key-1": pub})
	if err := invalidEncoding.VerifySignatures(&SignedRole{
		Signed:     content,
		Signatures: []TUFSignature{{KeyID: "key-1", Signature: "!"}},
	}, 1); err == nil {
		t.Fatal("expected invalid signature encoding to fail")
	}
}

func TestVerifySignature_RSAAndECDSA(t *testing.T) {
	content := []byte(`{"test":"content"}`)
	hash := sha256.Sum256(content)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(&rsaKey.PublicKey, hash[:], rsaSig); err != nil {
		t.Fatalf("RSA verify: %v", err)
	}
	if err := verifySignature(&rsaKey.PublicKey, hash[:], []byte("wrong")); err == nil {
		t.Fatal("expected bad RSA signature to fail")
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaSig, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(&ecdsaKey.PublicKey, hash[:], ecdsaSig); err != nil {
		t.Fatalf("ECDSA verify: %v", err)
	}
	if err := verifySignature(&ecdsaKey.PublicKey, hash[:], []byte("wrong")); err == nil {
		t.Fatal("expected bad ECDSA signature to fail")
	}
}
