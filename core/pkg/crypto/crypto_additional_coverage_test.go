package crypto

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ─── 1: ML-DSA signature rejected by Ed25519 verifier ─────────

func TestExt_MLDSASignatureRejectedByEd25519(t *testing.T) {
	mldsa, _ := NewMLDSASigner("pq1")
	ed, _ := NewEd25519Signer("ed1")
	sig, _ := mldsa.Sign([]byte("test"))
	ok, _ := Verify(ed.PublicKey(), sig, []byte("test"))
	if ok {
		t.Fatal("ML-DSA signature should not verify with Ed25519 key")
	}
}

// ─── 2: Ed25519 signature rejected by ML-DSA verifier ─────────

func TestExt_Ed25519SignatureRejectedByMLDSA(t *testing.T) {
	ed, _ := NewEd25519Signer("ed1")
	mldsa, _ := NewMLDSASigner("pq1")
	sig, _ := ed.Sign([]byte("test"))
	sigBytes, _ := hex.DecodeString(sig)
	ok := mldsa.Verify([]byte("test"), sigBytes)
	if ok {
		t.Fatal("Ed25519 signature should not verify with ML-DSA key")
	}
}

// ─── 3: KeyRing with mixed algorithms — sign uses latest ──────

func TestExt_KeyRingMixedAlgorithmsSign(t *testing.T) {
	kr := NewKeyRing()
	ed, _ := NewEd25519Signer("aaa")
	mldsa, _ := NewMLDSASigner("zzz") // lexicographically last
	kr.AddKey(ed)
	kr.AddKey(mldsa)
	sig, err := kr.Sign([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	// Should use "zzz" (ML-DSA) since lexicographically last
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}
}

// ─── 4: KeyRing empty — sign returns error ────────────────────

func TestExt_KeyRingEmptySignError(t *testing.T) {
	kr := NewKeyRing()
	_, err := kr.Sign([]byte("test"))
	if err == nil {
		t.Fatal("expected error signing with empty keyring")
	}
}

// ─── 5: KeyRing empty — SignDecision returns error ────────────

func TestExt_KeyRingEmptySignDecisionError(t *testing.T) {
	kr := NewKeyRing()
	err := kr.SignDecision(&contracts.DecisionRecord{ID: "d1"})
	if err == nil {
		t.Fatal("expected error signing decision with empty keyring")
	}
}

// ─── 6: KeyRing RevokeKey removes key ─────────────────────────

func TestExt_KeyRingRevokeKey(t *testing.T) {
	kr := NewKeyRing()
	ed, _ := NewEd25519Signer("k1")
	kr.AddKey(ed)
	kr.RevokeKey("k1")
	_, err := kr.Sign([]byte("test"))
	if err == nil {
		t.Fatal("expected error after revoking only key")
	}
}

// ─── 7: KeyRing VerifyDecision — revoked key ──────────────────

func TestExt_KeyRingVerifyDecisionRevokedKey(t *testing.T) {
	kr := NewKeyRing()
	ed, _ := NewEd25519Signer("k1")
	kr.AddKey(ed)
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "ALLOW"}
	kr.SignDecision(d)
	kr.RevokeKey("k1")
	_, err := kr.VerifyDecision(d)
	if err == nil {
		t.Fatal("expected error verifying with revoked key")
	}
}

// ─── 8: Canonical hash determinism — same input same output ──

func TestExt_CanonicalHashDeterminism(t *testing.T) {
	h1 := CanonicalizeDecision("id1", "ALLOW", "ok", "ph", "pch", "ed")
	h2 := CanonicalizeDecision("id1", "ALLOW", "ok", "ph", "pch", "ed")
	if h1 != h2 {
		t.Fatal("same inputs should produce same canonical string")
	}
}

// ─── 9: Canonical hash differs with different inputs ──────────

func TestExt_CanonicalHashDiffers(t *testing.T) {
	h1 := CanonicalizeDecision("id1", "ALLOW", "ok", "ph", "pch", "ed")
	h2 := CanonicalizeDecision("id1", "DENY", "ok", "ph", "pch", "ed")
	if h1 == h2 {
		t.Fatal("different verdicts should produce different canonical strings")
	}
}

// ─── 10: CanonicalizeDecisionStrict rejects empty ID ──────────

func TestExt_CanonicalizeStrictRejectsEmptyID(t *testing.T) {
	_, err := CanonicalizeDecisionStrict("", "ALLOW", "ok", "ph", "pch", "ed")
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

// ─── 11: CanonicalizeDecisionStrict rejects empty verdict ─────

func TestExt_CanonicalizeStrictRejectsEmptyVerdict(t *testing.T) {
	_, err := CanonicalizeDecisionStrict("id", "", "ok", "ph", "pch", "ed")
	if err == nil {
		t.Fatal("expected error for empty verdict")
	}
}

// ─── 12: CanonicalMarshal produces compact JSON ───────────────

func TestExt_CanonicalMarshalCompact(t *testing.T) {
	data, err := CanonicalMarshal(map[string]int{"b": 2, "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if strings.Contains(s, "\n") || strings.Contains(s, "  ") {
		t.Fatal("canonical JSON should be compact")
	}
}

// ─── 13: CanonicalMarshal no trailing newline ─────────────────

func TestExt_CanonicalMarshalNoTrailingNewline(t *testing.T) {
	data, _ := CanonicalMarshal(map[string]int{"a": 1})
	if data[len(data)-1] == '\n' {
		t.Fatal("canonical JSON should not have trailing newline")
	}
}

// ─── 14: SoftHSM generates and persists Ed25519 key ───────────

func TestExt_SoftHSMPersistence(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	s1, _ := hsm.GetSigner("test-key")
	pub1 := s1.PublicKey()
	// Second call should return same key
	s2, _ := hsm.GetSigner("test-key")
	if s2.PublicKey() != pub1 {
		t.Fatal("cached key should have same public key")
	}
}

// ─── 15: SoftHSM persists to disk ────────────────────────────

func TestExt_SoftHSMPersistsToDisk(t *testing.T) {
	dir := t.TempDir()
	hsm1, _ := NewSoftHSM(dir)
	s1, _ := hsm1.GetSigner("persist-key")
	pub1 := s1.PublicKey()
	// New HSM instance from same dir
	hsm2, _ := NewSoftHSM(dir)
	s2, _ := hsm2.GetSigner("persist-key")
	if s2.PublicKey() != pub1 {
		t.Fatal("key loaded from disk should match")
	}
}

// ─── 16: SoftHSM ML-DSA key generation ───────────────────────

func TestExt_SoftHSMMLDSAKey(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	s, err := hsm.GetSignerWithAlgorithm("pq-key", AlgorithmMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := s.Sign([]byte("pq-test"))
	if sig == "" {
		t.Fatal("ML-DSA signer should produce non-empty signature")
	}
}

// ─── 17: SoftHSM unsupported algorithm ────────────────────────

func TestExt_SoftHSMUnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	_, err := hsm.GetSignerWithAlgorithm("key", "rsa-4096")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

// ─── 18: SoftHSM ML-DSA persistence ──────────────────────────

func TestExt_SoftHSMMLDSAPersistence(t *testing.T) {
	dir := t.TempDir()
	hsm1, _ := NewSoftHSM(dir)
	s1, _ := hsm1.GetSignerWithAlgorithm("pq-persist", AlgorithmMLDSA65)
	pub1 := s1.PublicKey()
	hsm2, _ := NewSoftHSM(dir)
	s2, _ := hsm2.GetSignerWithAlgorithm("pq-persist", AlgorithmMLDSA65)
	if s2.PublicKey() != pub1 {
		t.Fatal("ML-DSA key loaded from disk should match")
	}
}

// ─── 19: SoftHSM invalid key file ────────────────────────────

func TestExt_SoftHSMInvalidKeyFile(t *testing.T) {
	dir := t.TempDir()
	// Write invalid data to key file
	os.WriteFile(filepath.Join(dir, "bad.key"), []byte("x"), 0o600)
	hsm, _ := NewSoftHSM(dir)
	_, err := hsm.GetSigner("bad")
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

// ─── 20: KeyRing PublicKey returns aggregate marker ───────────

func TestExt_KeyRingPublicKeyMarker(t *testing.T) {
	kr := NewKeyRing()
	if kr.PublicKey() != "keyring-aggregate" {
		t.Fatalf("expected keyring-aggregate, got %s", kr.PublicKey())
	}
}

// ─── 21: KeyRing PublicKeyBytes returns nil ───────────────────

func TestExt_KeyRingPublicKeyBytesNil(t *testing.T) {
	kr := NewKeyRing()
	if kr.PublicKeyBytes() != nil {
		t.Fatal("expected nil for keyring public key bytes")
	}
}

// ─── 22: KeyRing concurrent sign ──────────────────────────────

func TestExt_KeyRingConcurrentSign(t *testing.T) {
	kr := NewKeyRing()
	ed, _ := NewEd25519Signer("k1")
	kr.AddKey(ed)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kr.Sign([]byte("data"))
		}()
	}
	wg.Wait()
}

// ─── 23: Verify rejects invalid public key hex ───────────────

func TestExt_VerifyRejectsInvalidPubKeyHex(t *testing.T) {
	_, err := Verify("not-hex", "00", []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid pub key hex")
	}
}

// ─── 24: Verify rejects wrong public key size ────────────────

func TestExt_VerifyRejectsWrongPubKeySize(t *testing.T) {
	_, err := Verify("0011", "0022", []byte("data"))
	if err == nil || !strings.Contains(err.Error(), "invalid public key size") {
		t.Fatal("expected error for wrong public key size")
	}
}

// ─── 25: Ed25519Signer SignReceipt populates signature ────────

func TestExt_Ed25519SignReceiptPopulatesSig(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	r := &contracts.Receipt{ReceiptID: "r1", DecisionID: "d1", EffectID: "e1", Status: "SUCCESS"}
	if err := s.SignReceipt(r); err != nil {
		t.Fatal(err)
	}
	if r.Signature == "" {
		t.Fatal("receipt signature should be populated")
	}
}
