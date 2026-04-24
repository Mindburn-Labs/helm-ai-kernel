package crypto

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ── Ed25519 Signer ───────────────────────────────────────────

func TestEd25519_SignAndVerify(t *testing.T) {
	s, err := NewEd25519Signer("k1")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(s.PublicKey(), sig, []byte("hello"))
	if err != nil || !ok {
		t.Errorf("valid signature should verify, ok=%v err=%v", ok, err)
	}
}

func TestEd25519_VerifyWrongData(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	sig, _ := s.Sign([]byte("hello"))
	ok, _ := Verify(s.PublicKey(), sig, []byte("world"))
	if ok {
		t.Error("signature should not verify against different data")
	}
}

func TestEd25519_PublicKeyLength(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	pub := s.PublicKeyBytes()
	if len(pub) != 32 {
		t.Errorf("Ed25519 public key should be 32 bytes, got %d", len(pub))
	}
}

func TestEd25519_GetKeyID(t *testing.T) {
	s, _ := NewEd25519Signer("my-key")
	if s.GetKeyID() != "my-key" {
		t.Errorf("expected key ID 'my-key', got %s", s.GetKeyID())
	}
}

// ── ML-DSA Signer ────────────────────────────────────────────

func TestMLDSA_SignAndVerify(t *testing.T) {
	s, err := NewMLDSASigner("pq1")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign([]byte("test-data"))
	if err != nil {
		t.Fatal(err)
	}
	sigBytes, _ := hex.DecodeString(sig)
	if !s.Verify([]byte("test-data"), sigBytes) {
		t.Error("ML-DSA signature should verify")
	}
}

func TestMLDSA_VerifyWrongData(t *testing.T) {
	s, _ := NewMLDSASigner("pq1")
	sig, _ := s.Sign([]byte("correct"))
	sigBytes, _ := hex.DecodeString(sig)
	if s.Verify([]byte("wrong"), sigBytes) {
		t.Error("ML-DSA signature should not verify wrong data")
	}
}

func TestMLDSA_GetKeyID(t *testing.T) {
	s, _ := NewMLDSASigner("pq-key")
	if s.GetKeyID() != "pq-key" {
		t.Errorf("expected key ID 'pq-key', got %s", s.GetKeyID())
	}
}

// ── KeyRing Routing ──────────────────────────────────────────

func TestKeyRing_AddAndSign(t *testing.T) {
	kr := NewKeyRing()
	s, _ := NewEd25519Signer("k1")
	kr.AddKey(s)
	sig, err := kr.Sign([]byte("data"))
	if err != nil || sig == "" {
		t.Errorf("keyring Sign should succeed, err=%v", err)
	}
}

func TestKeyRing_EmptySignFails(t *testing.T) {
	kr := NewKeyRing()
	_, err := kr.Sign([]byte("data"))
	if err == nil {
		t.Error("Sign on empty keyring should fail")
	}
}

func TestKeyRing_RevokeKey(t *testing.T) {
	kr := NewKeyRing()
	s, _ := NewEd25519Signer("k1")
	kr.AddKey(s)
	kr.RevokeKey("k1")
	_, err := kr.Sign([]byte("data"))
	if err == nil {
		t.Error("Sign after revoking only key should fail")
	}
}

func TestKeyRing_VerifyAcrossKeys(t *testing.T) {
	kr := NewKeyRing()
	s1, _ := NewEd25519Signer("k1")
	s2, _ := NewEd25519Signer("k2")
	kr.AddKey(s1)
	kr.AddKey(s2)
	msg := []byte("msg")
	sig, _ := s1.Sign(msg)
	sigBytes, _ := hex.DecodeString(sig)
	if !kr.Verify(msg, sigBytes) {
		t.Error("keyring should verify signature from any registered key")
	}
}

// ── Canonical Functions ──────────────────────────────────────

func TestCanonicalizeDecision_Deterministic(t *testing.T) {
	a := CanonicalizeDecision("id1", "ALLOW", "ok", "ph1", "pc1", "ed1")
	b := CanonicalizeDecision("id1", "ALLOW", "ok", "ph1", "pc1", "ed1")
	if a != b {
		t.Error("canonicalize should be deterministic")
	}
}

func TestCanonicalizeDecisionStrict_EmptyID(t *testing.T) {
	_, err := CanonicalizeDecisionStrict("", "ALLOW", "ok", "ph", "pc", "ed")
	if err == nil {
		t.Error("strict canonicalize should reject empty ID")
	}
}

func TestCanonicalMarshal_NoHTMLEscape(t *testing.T) {
	data := map[string]string{"url": "http://example.com?a=1&b=2"}
	b, err := CanonicalMarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	// Should NOT escape & to \u0026
	if string(b) != `{"url":"http://example.com?a=1&b=2"}` {
		t.Errorf("canonical marshal should not HTML-escape, got %s", string(b))
	}
}

func TestCanonicalizeIntent_Format(t *testing.T) {
	result := CanonicalizeIntent("i1", "d1", "tool1")
	if result != "i1:d1:tool1" {
		t.Errorf("expected 'i1:d1:tool1', got %s", result)
	}
}

// ── HSM Operations ───────────────────────────────────────────

func TestSoftHSM_GetSignerCreatesKey(t *testing.T) {
	dir := t.TempDir()
	hsm, err := NewSoftHSM(dir)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := hsm.GetSigner("test-label")
	if err != nil {
		t.Fatal(err)
	}
	if signer.PublicKey() == "" {
		t.Error("signer should have a non-empty public key")
	}
	// Key file should exist
	if _, err := os.Stat(filepath.Join(dir, "test-label.key")); os.IsNotExist(err) {
		t.Error("key file should be persisted to disk")
	}
}

func TestSoftHSM_GetSignerMLDSA(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	signer, err := hsm.GetSignerWithAlgorithm("pq-label", AlgorithmMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign([]byte("test"))
	if err != nil || sig == "" {
		t.Errorf("ML-DSA signer from HSM should sign, err=%v", err)
	}
}

func TestSoftHSM_ReloadsSameKey(t *testing.T) {
	dir := t.TempDir()
	hsm1, _ := NewSoftHSM(dir)
	s1, _ := hsm1.GetSigner("reload-test")
	pub1 := s1.PublicKey()
	// Create a new HSM pointing at same dir
	hsm2, _ := NewSoftHSM(dir)
	s2, _ := hsm2.GetSigner("reload-test")
	if s2.PublicKey() != pub1 {
		t.Error("reloading from disk should produce same public key")
	}
}

func TestSoftHSM_UnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	_, err := hsm.GetSignerWithAlgorithm("label", "rsa-2048")
	if err == nil {
		t.Error("unsupported algorithm should return error")
	}
}

func TestEd25519_SignDecisionRoundTrip(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "ALLOW", Reason: "ok"}
	if err := s.SignDecision(d); err != nil {
		t.Fatal(err)
	}
	ok, err := s.VerifyDecision(d)
	if err != nil || !ok {
		t.Errorf("signed decision should verify, ok=%v err=%v", ok, err)
	}
}
