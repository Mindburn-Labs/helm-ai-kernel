package crypto

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestFinal_NewEd25519Signer(t *testing.T) {
	s, err := NewEd25519Signer("test-key")
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Fatal("signer should not be nil")
	}
}

func TestFinal_Ed25519SignerPublicKey(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	pk := s.PublicKey()
	if pk == "" {
		t.Fatal("public key should not be empty")
	}
	if len(s.PublicKeyBytes()) != 32 {
		t.Fatal("ed25519 public key should be 32 bytes")
	}
}

func TestFinal_Ed25519SignVerify(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	sig, err := s.Sign([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(s.PublicKey(), sig, []byte("hello"))
	if err != nil || !ok {
		t.Fatal("signature should verify")
	}
}

func TestFinal_Ed25519SignVerifyWrongData(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	sig, _ := s.Sign([]byte("hello"))
	ok, _ := Verify(s.PublicKey(), sig, []byte("world"))
	if ok {
		t.Fatal("wrong data should not verify")
	}
}

func TestFinal_Ed25519VerifyBadHex(t *testing.T) {
	_, err := Verify("not-hex", "not-hex", []byte("data"))
	if err == nil {
		t.Fatal("should error on bad hex")
	}
}

func TestFinal_Ed25519VerifyBadKeySize(t *testing.T) {
	_, err := Verify("aabb", "aabb", []byte("data"))
	if err == nil {
		t.Fatal("should error on wrong key size")
	}
}

func TestFinal_SignDecision(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "ALLOW", Reason: "ok"}
	if err := s.SignDecision(d); err != nil {
		t.Fatal(err)
	}
	if d.Signature == "" {
		t.Fatal("signature should be set")
	}
}

func TestFinal_VerifyDecision(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "ALLOW", Reason: "ok"}
	s.SignDecision(d)
	ok, err := s.VerifyDecision(d)
	if err != nil || !ok {
		t.Fatal("decision should verify")
	}
}

func TestFinal_SignAndVerifyReceipt(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	r := &contracts.Receipt{ReceiptID: "r1", DecisionID: "d1", EffectID: "e1", Status: "OK"}
	if err := s.SignReceipt(r); err != nil {
		t.Fatal(err)
	}
	ok, err := s.VerifyReceipt(r)
	if err != nil || !ok {
		t.Fatal("receipt should verify")
	}
}

func TestFinal_SignAndVerifyIntent(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	i := &contracts.AuthorizedExecutionIntent{ID: "i1", DecisionID: "d1", AllowedTool: "tool1"}
	if err := s.SignIntent(i); err != nil {
		t.Fatal(err)
	}
	ok, err := s.VerifyIntent(i)
	if err != nil || !ok {
		t.Fatal("intent should verify")
	}
}

func TestFinal_VerifyDecisionMissingSig(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	d := &contracts.DecisionRecord{ID: "d1"}
	_, err := s.VerifyDecision(d)
	if err == nil {
		t.Fatal("should error on missing signature")
	}
}

func TestFinal_VerifyReceiptMissingSig(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	r := &contracts.Receipt{ReceiptID: "r1"}
	_, err := s.VerifyReceipt(r)
	if err == nil {
		t.Fatal("should error on missing signature")
	}
}

func TestFinal_CanonicalHasherInterface(t *testing.T) {
	var _ Hasher = (*CanonicalHasher)(nil)
}

func TestFinal_CanonicalHasherHash(t *testing.T) {
	h := &CanonicalHasher{}
	result, err := h.Hash("hello world")
	if err != nil || result == "" {
		t.Fatal("hash should not be empty")
	}
}

func TestFinal_CanonicalHasherDeterminism(t *testing.T) {
	h := &CanonicalHasher{}
	a, _ := h.Hash("test")
	b, _ := h.Hash("test")
	if a != b {
		t.Fatal("hash should be deterministic")
	}
}

func TestFinal_CanonicalHasherDifferentInputs(t *testing.T) {
	h := &CanonicalHasher{}
	a, _ := h.Hash("hello")
	b, _ := h.Hash("world")
	if a == b {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestFinal_Ed25519SignerGetKeyID(t *testing.T) {
	s, _ := NewEd25519Signer("my-key-id")
	if s.GetKeyID() != "my-key-id" {
		t.Fatal("key ID mismatch")
	}
}

func TestFinal_SignerInterface(t *testing.T) {
	var _ Signer = (*Ed25519Signer)(nil)
}

func TestFinal_VerifierInterface(t *testing.T) {
	var _ Verifier = (*Ed25519Verifier)(nil)
}

func TestFinal_Ed25519VerifierFromKey(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	v, err := NewEd25519Verifier(s.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	sigHex, _ := s.Sign([]byte("data"))
	sigBytes := mustDecodeHex(t, sigHex)
	if !v.Verify([]byte("data"), sigBytes) {
		t.Fatal("should verify")
	}
}

func TestFinal_KeyRingAddGet(t *testing.T) {
	kr := NewKeyRing()
	s, _ := NewEd25519Signer("k1")
	kr.AddKey(s)
	pk := kr.PublicKey()
	if pk == "" {
		t.Fatal("keyring should expose public key after AddKey")
	}
}

func TestFinal_KeyRingSign(t *testing.T) {
	kr := NewKeyRing()
	s, _ := NewEd25519Signer("k1")
	kr.AddKey(s)
	sig, err := kr.Sign([]byte("data"))
	if err != nil || sig == "" {
		t.Fatal("keyring should sign")
	}
}

func TestFinal_ConcurrentSign(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Sign([]byte("data"))
		}()
	}
	wg.Wait()
}

func TestFinal_DecisionRecordSignatureJSON(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "DENY", Reason: "r"}
	s.SignDecision(d)
	data, _ := json.Marshal(d)
	var d2 contracts.DecisionRecord
	json.Unmarshal(data, &d2)
	if d2.Signature != d.Signature {
		t.Fatal("signature should survive JSON round-trip")
	}
}

func TestFinal_TwoSignersDifferentKeys(t *testing.T) {
	s1, _ := NewEd25519Signer("k1")
	s2, _ := NewEd25519Signer("k2")
	if s1.PublicKey() == s2.PublicKey() {
		t.Fatal("two signers should have different keys")
	}
}

func TestFinal_VerifyMethodOnSigner(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	msg := []byte("hello")
	sig, _ := s.Sign(msg)
	sigBytes := mustDecodeHex(t, sig)
	if !s.Verify(msg, sigBytes) {
		t.Fatal("Verify method should succeed")
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var val byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			switch {
			case c >= '0' && c <= '9':
				val = val*16 + (c - '0')
			case c >= 'a' && c <= 'f':
				val = val*16 + (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				val = val*16 + (c - 'A' + 10)
			}
		}
		b[i/2] = val
	}
	return b
}
