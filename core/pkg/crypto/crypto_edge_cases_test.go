package crypto

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ── Ed25519 Tests ────────────────────────────────────────────────

func TestDeepEd25519Sign1000Messages(t *testing.T) {
	signer, err := NewEd25519Signer("key-1")
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]bool{}
	for i := 0; i < 1000; i++ {
		msg := []byte(fmt.Sprintf("message-%d", i))
		sig, err := signer.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		if sigs[sig] {
			t.Fatalf("duplicate signature at message %d", i)
		}
		sigs[sig] = true
	}
}

func TestDeepEd25519SignVerifyRoundTrip(t *testing.T) {
	signer, _ := NewEd25519Signer("key-1")
	msg := []byte("hello world")
	sig, _ := signer.Sign(msg)
	valid, err := Verify(signer.PublicKey(), sig, msg)
	if err != nil || !valid {
		t.Fatal("signature should verify")
	}
}

func TestDeepEd25519VerifyWrongMessage(t *testing.T) {
	signer, _ := NewEd25519Signer("key-1")
	sig, _ := signer.Sign([]byte("original"))
	valid, _ := Verify(signer.PublicKey(), sig, []byte("tampered"))
	if valid {
		t.Fatal("tampered message should not verify")
	}
}

func TestDeepEd25519VerifyInvalidPubKey(t *testing.T) {
	_, err := Verify("invalid-hex", "0000", []byte("msg"))
	if err == nil {
		t.Fatal("invalid public key hex should error")
	}
}

func TestDeepEd25519VerifyInvalidSig(t *testing.T) {
	signer, _ := NewEd25519Signer("key-1")
	_, err := Verify(signer.PublicKey(), "invalid-hex!!!", []byte("msg"))
	if err == nil {
		t.Fatal("invalid signature hex should error")
	}
}

func TestDeepEd25519SignDecision(t *testing.T) {
	signer, _ := NewEd25519Signer("key-1")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "ALLOW", Reason: "test"}
	if err := signer.SignDecision(d); err != nil {
		t.Fatal(err)
	}
	if d.Signature == "" || d.SignatureType == "" {
		t.Fatal("signature should be populated")
	}
}

func TestDeepEd25519VerifyDecisionRoundTrip(t *testing.T) {
	signer, _ := NewEd25519Signer("key-1")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "DENY", Reason: "test"}
	signer.SignDecision(d)
	valid, err := signer.VerifyDecision(d)
	if err != nil || !valid {
		t.Fatal("signed decision should verify")
	}
}

func TestDeepEd25519VerifyDecisionMissingSig(t *testing.T) {
	signer, _ := NewEd25519Signer("key-1")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "ALLOW"}
	_, err := signer.VerifyDecision(d)
	if err == nil {
		t.Fatal("missing signature should error")
	}
}

func TestDeepEd25519SignReceipt(t *testing.T) {
	signer, _ := NewEd25519Signer("key-1")
	r := &contracts.Receipt{ReceiptID: "r1", DecisionID: "d1", EffectID: "e1", Status: "ok"}
	if err := signer.SignReceipt(r); err != nil {
		t.Fatal(err)
	}
	valid, err := signer.VerifyReceipt(r)
	if err != nil || !valid {
		t.Fatal("signed receipt should verify")
	}
}

func TestDeepEd25519SignIntent(t *testing.T) {
	signer, _ := NewEd25519Signer("key-1")
	i := &contracts.AuthorizedExecutionIntent{ID: "i1", DecisionID: "d1", AllowedTool: "tool1"}
	if err := signer.SignIntent(i); err != nil {
		t.Fatal(err)
	}
	valid, err := signer.VerifyIntent(i)
	if err != nil || !valid {
		t.Fatal("signed intent should verify")
	}
}

// ── ML-DSA-65 Tests ──────────────────────────────────────────────

func TestDeepMLDSASign100Messages(t *testing.T) {
	signer, err := NewMLDSASigner("pq-key-1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		msg := []byte(fmt.Sprintf("pq-message-%d", i))
		sig, err := signer.Sign(msg)
		if err != nil {
			t.Fatalf("sign %d failed: %v", i, err)
		}
		sigBytes, _ := hex.DecodeString(sig)
		if !signer.Verify(msg, sigBytes) {
			t.Fatalf("verify %d failed", i)
		}
	}
}

func TestDeepMLDSASignDecisionVerify(t *testing.T) {
	signer, _ := NewMLDSASigner("pq-key-1")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "ALLOW", Reason: "test"}
	signer.SignDecision(d)
	valid, err := signer.VerifyDecision(d)
	if err != nil || !valid {
		t.Fatal("ML-DSA signed decision should verify")
	}
}

func TestDeepMLDSAVerifyTamperedMessage(t *testing.T) {
	signer, _ := NewMLDSASigner("pq-key-1")
	msg := []byte("original")
	sig, _ := signer.Sign(msg)
	sigBytes, _ := hex.DecodeString(sig)
	if signer.Verify([]byte("tampered"), sigBytes) {
		t.Fatal("tampered message should not verify")
	}
}

func TestDeepMLDSAPublicKeyNonEmpty(t *testing.T) {
	signer, _ := NewMLDSASigner("pq-key-1")
	if signer.PublicKey() == "" {
		t.Fatal("public key should be non-empty")
	}
	if len(signer.PublicKeyBytes()) == 0 {
		t.Fatal("public key bytes should be non-empty")
	}
}

// ── KeyRing Tests ────────────────────────────────────────────────

func TestDeepKeyRingWith10Keys(t *testing.T) {
	kr := NewKeyRing()
	for i := 0; i < 5; i++ {
		s, _ := NewEd25519Signer(fmt.Sprintf("ed-key-%d", i))
		kr.AddKey(s)
	}
	for i := 0; i < 5; i++ {
		s, _ := NewMLDSASigner(fmt.Sprintf("pq-key-%d", i))
		kr.AddKey(s)
	}
	// Sign with the keyring
	sig, err := kr.Sign([]byte("test"))
	if err != nil || sig == "" {
		t.Fatal("keyring should be able to sign")
	}
}

func TestDeepKeyRingRevokeKey(t *testing.T) {
	kr := NewKeyRing()
	s, _ := NewEd25519Signer("key-to-revoke")
	kr.AddKey(s)
	kr.RevokeKey("key-to-revoke")
	// After revoke, sign with empty keyring should fail
	_, err := kr.Sign([]byte("test"))
	if err == nil {
		t.Fatal("sign with empty keyring should error")
	}
}

func TestDeepKeyRingVerifyDecisionAfterRotation(t *testing.T) {
	kr := NewKeyRing()
	s1, _ := NewEd25519Signer("key-v1")
	kr.AddKey(s1)
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "ALLOW"}
	s1.SignDecision(d)
	// Add new key, keep old
	s2, _ := NewEd25519Signer("key-v2")
	kr.AddKey(s2)
	valid, err := kr.VerifyDecision(d)
	if err != nil || !valid {
		t.Fatal("old key should still verify after rotation")
	}
}

func TestDeepKeyRingSignDecisionEmptyRing(t *testing.T) {
	kr := NewKeyRing()
	d := &contracts.DecisionRecord{ID: "d1"}
	err := kr.SignDecision(d)
	if err == nil {
		t.Fatal("sign with empty keyring should error")
	}
}

func TestDeepKeyRingVerifyKeyUnknown(t *testing.T) {
	kr := NewKeyRing()
	_, err := kr.VerifyKey("nonexistent", []byte("msg"), []byte("sig"))
	if err == nil {
		t.Fatal("unknown key should error")
	}
}

func TestDeepKeyRingPublicKey(t *testing.T) {
	kr := NewKeyRing()
	if kr.PublicKey() != "keyring-aggregate" {
		t.Fatal("keyring public key should be aggregate marker")
	}
	if kr.PublicKeyBytes() != nil {
		t.Fatal("keyring public key bytes should be nil")
	}
}

// ── Canonical Tests ──────────────────────────────────────────────

func TestDeepCanonicalMarshalDeterministic(t *testing.T) {
	v := map[string]any{"z": 1, "a": 2, "m": 3}
	b1, _ := CanonicalMarshal(v)
	b2, _ := CanonicalMarshal(v)
	if string(b1) != string(b2) {
		t.Fatal("canonical marshal should be deterministic")
	}
}

func TestDeepCanonicalMarshalNoTrailingNewline(t *testing.T) {
	b, _ := CanonicalMarshal("hello")
	if len(b) > 0 && b[len(b)-1] == '\n' {
		t.Fatal("should not have trailing newline")
	}
}

func TestDeepCanonicalMarshalDeeplyNested(t *testing.T) {
	// Build 10-level nested structure
	var v any = "leaf"
	for i := 0; i < 10; i++ {
		v = map[string]any{fmt.Sprintf("level-%d", i): v}
	}
	b1, err := CanonicalMarshal(v)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := CanonicalMarshal(v)
	if string(b1) != string(b2) {
		t.Fatal("deeply nested struct should produce deterministic output")
	}
}

func TestDeepCanonicalizeDecisionStrict(t *testing.T) {
	_, err := CanonicalizeDecisionStrict("", "ALLOW", "r", "ph", "pch", "ed")
	if err == nil {
		t.Fatal("empty ID should error in strict mode")
	}
	_, err = CanonicalizeDecisionStrict("id", "", "r", "ph", "pch", "ed")
	if err == nil {
		t.Fatal("empty verdict should error in strict mode")
	}
	s, err := CanonicalizeDecisionStrict("id", "ALLOW", "r", "ph", "pch", "ed")
	if err != nil || s == "" {
		t.Fatal("valid inputs should succeed")
	}
}

// ── SoftHSM Tests ────────────────────────────────────────────────

func TestDeepSoftHSMGetSignerPersistence(t *testing.T) {
	dir := t.TempDir()
	hsm, err := NewSoftHSM(dir)
	if err != nil {
		t.Fatal(err)
	}
	s1, err := hsm.GetSigner("test-key")
	if err != nil {
		t.Fatal(err)
	}
	pub1 := s1.PublicKey()
	// Create new HSM instance to test persistence
	hsm2, _ := NewSoftHSM(dir)
	s2, _ := hsm2.GetSigner("test-key")
	if s2.PublicKey() != pub1 {
		t.Fatal("persisted key should produce same public key")
	}
}

func TestDeepSoftHSM50Operations(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	for i := 0; i < 50; i++ {
		label := fmt.Sprintf("key-%d", i%10)
		s, err := hsm.GetSigner(label)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Sign([]byte(fmt.Sprintf("data-%d", i)))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestDeepSoftHSMMLDSAKey(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	s, err := hsm.GetSignerWithAlgorithm("pq-key", AlgorithmMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign([]byte("post-quantum"))
	if err != nil || sig == "" {
		t.Fatal("ML-DSA sign should succeed")
	}
}

func TestDeepSoftHSMMLDSAPersistence(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	s1, _ := hsm.GetSignerWithAlgorithm("pq-persist", AlgorithmMLDSA65)
	pub1 := s1.PublicKey()
	hsm2, _ := NewSoftHSM(dir)
	s2, _ := hsm2.GetSignerWithAlgorithm("pq-persist", AlgorithmMLDSA65)
	if s2.PublicKey() != pub1 {
		t.Fatal("ML-DSA key should persist across HSM instances")
	}
}

func TestDeepSoftHSMUnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	_, err := hsm.GetSignerWithAlgorithm("key", "unknown-algo")
	if err == nil {
		t.Fatal("unsupported algorithm should error")
	}
}

func TestDeepSoftHSMInvalidKeyFile(t *testing.T) {
	dir := t.TempDir()
	// Write invalid key data
	os.WriteFile(filepath.Join(dir, "bad.key"), []byte("too-short"), 0o600)
	hsm, _ := NewSoftHSM(dir)
	_, err := hsm.GetSigner("bad")
	if err == nil {
		t.Fatal("invalid key file should error")
	}
}

func TestDeepConcurrentKeyRing(t *testing.T) {
	kr := NewKeyRing()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s, _ := NewEd25519Signer(fmt.Sprintf("k-%d", idx))
			kr.AddKey(s)
			kr.Sign([]byte("test"))
		}(i)
	}
	wg.Wait()
}
