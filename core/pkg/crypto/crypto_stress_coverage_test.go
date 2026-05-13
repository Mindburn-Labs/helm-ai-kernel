package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ── Ed25519: sign 500 messages ──────────────────────────────────────────

func TestStress_Ed25519Sign500Messages(t *testing.T) {
	signer, err := NewEd25519Signer("stress-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	for i := range 500 {
		msg := []byte(fmt.Sprintf("message-%d", i))
		sig, err := signer.Sign(msg)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		if sig == "" {
			t.Fatalf("empty sig at %d", i)
		}
	}
}

func TestStress_Ed25519VerifyRoundTrip(t *testing.T) {
	signer, _ := NewEd25519Signer("rt-key")
	msg := []byte("roundtrip-test")
	sig, _ := signer.Sign(msg)
	sigBytes, _ := hex.DecodeString(sig)
	if !signer.Verify(msg, sigBytes) {
		t.Fatal("verify failed")
	}
}

// ── ML-DSA: sign 50 messages ────────────────────────────────────────────

func TestStress_MLDSASign50Messages(t *testing.T) {
	signer, err := NewMLDSASigner("mldsa-stress")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	for i := range 50 {
		msg := []byte(fmt.Sprintf("pq-message-%d", i))
		sig, err := signer.Sign(msg)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		if sig == "" {
			t.Fatalf("empty sig at %d", i)
		}
	}
}

func TestStress_MLDSAVerifyRoundTrip(t *testing.T) {
	signer, _ := NewMLDSASigner("mldsa-rt")
	msg := []byte("pq-roundtrip")
	sig, _ := signer.Sign(msg)
	sigBytes, _ := hex.DecodeString(sig)
	if !signer.Verify(msg, sigBytes) {
		t.Fatal("ML-DSA verify failed")
	}
}

func TestStress_MLDSAPublicKey(t *testing.T) {
	signer, _ := NewMLDSASigner("mldsa-pk")
	pk := signer.PublicKey()
	if pk == "" {
		t.Fatal("public key should not be empty")
	}
	pkBytes := signer.PublicKeyBytes()
	if len(pkBytes) == 0 {
		t.Fatal("public key bytes should not be empty")
	}
}

func TestStress_MLDSAKeyID(t *testing.T) {
	signer, _ := NewMLDSASigner("my-key-id")
	if signer.GetKeyID() != "my-key-id" {
		t.Fatalf("expected my-key-id, got %s", signer.GetKeyID())
	}
}

// ── KeyRing with 20 keys ────────────────────────────────────────────────

func TestStress_KeyRing20Keys(t *testing.T) {
	ring := NewKeyRing()
	for i := range 20 {
		signer, _ := NewEd25519Signer(fmt.Sprintf("key-%d", i))
		ring.AddKey(signer)
	}
	d := &contracts.DecisionRecord{ID: "d-1", Verdict: "ALLOW", Reason: "ok"}
	if err := ring.SignDecision(d); err != nil {
		t.Fatalf("sign decision: %v", err)
	}
	if d.Signature == "" {
		t.Fatal("decision should be signed")
	}
}

func TestStress_KeyRingRevoke(t *testing.T) {
	ring := NewKeyRing()
	signer, _ := NewEd25519Signer("revoke-key")
	ring.AddKey(signer)
	ring.RevokeKey("revoke-key")
	d := &contracts.DecisionRecord{ID: "d-2", Verdict: "DENY", Reason: "test"}
	err := ring.SignDecision(d)
	if err == nil {
		t.Fatal("signing with empty ring should fail")
	}
}

func TestStress_KeyRingMLDSA(t *testing.T) {
	ring := NewKeyRing()
	signer, _ := NewMLDSASigner("pq-ring-key")
	ring.AddKey(signer)
	msg := []byte("ring-verify-test")
	sig, _ := signer.Sign(msg)
	sigBytes, _ := hex.DecodeString(sig)
	ok, err := ring.VerifyKey("pq-ring-key", msg, sigBytes)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("ML-DSA ring verification failed")
	}
}

// ── Canonical hash with 100 objects ─────────────────────────────────────

func TestStress_CanonicalHash100Objects(t *testing.T) {
	for i := range 100 {
		obj := map[string]any{"index": i, "name": fmt.Sprintf("obj-%d", i)}
		data, err := CanonicalMarshal(obj)
		if err != nil {
			t.Fatalf("canonical %d: %v", i, err)
		}
		if len(data) == 0 {
			t.Fatalf("empty canonical output at %d", i)
		}
	}
}

func TestStress_CanonicalDeterministic(t *testing.T) {
	obj := map[string]any{"z": 3, "a": 1, "m": 2}
	d1, _ := CanonicalMarshal(obj)
	d2, _ := CanonicalMarshal(obj)
	if string(d1) != string(d2) {
		t.Fatal("canonical marshal should be deterministic")
	}
}

func TestStress_CanonicalNoTrailingNewline(t *testing.T) {
	data, _ := CanonicalMarshal(map[string]string{"k": "v"})
	if data[len(data)-1] == '\n' {
		t.Fatal("should not have trailing newline")
	}
}

// ── HSM: create 20 keys ────────────────────────────────────────────────

func TestStress_HSMCreate20Keys(t *testing.T) {
	dir := t.TempDir()
	hsm, err := NewSoftHSM(dir)
	if err != nil {
		t.Fatalf("hsm: %v", err)
	}
	for i := range 20 {
		signer, err := hsm.GetSigner(fmt.Sprintf("key-%d", i))
		if err != nil {
			t.Fatalf("get signer %d: %v", i, err)
		}
		if signer.PublicKey() == "" {
			t.Fatalf("empty public key at %d", i)
		}
	}
}

func TestStress_HSMKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	hsm1, _ := NewSoftHSM(dir)
	s1, _ := hsm1.GetSigner("persist-key")
	pk1 := s1.PublicKey()
	hsm2, _ := NewSoftHSM(dir)
	s2, _ := hsm2.GetSigner("persist-key")
	pk2 := s2.PublicKey()
	if pk1 != pk2 {
		t.Fatal("persisted key should produce same public key")
	}
}

// ── mTLS (SoftHSM is used for cert-like key gen) ────────────────────────

func TestStress_HSM10CertKeys(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	for i := range 10 {
		s, err := hsm.GetSigner(fmt.Sprintf("cert-%d", i))
		if err != nil {
			t.Fatalf("cert key %d: %v", i, err)
		}
		sig, _ := s.Sign([]byte("tls-test"))
		if sig == "" {
			t.Fatalf("empty sig for cert %d", i)
		}
	}
}

// ── Sign every contract type x Ed25519 ──────────────────────────────────

func TestStress_Ed25519SignDecision(t *testing.T) {
	signer, _ := NewEd25519Signer("ed-dec")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "ALLOW", Reason: "ok"}
	if err := signer.SignDecision(d); err != nil {
		t.Fatalf("sign decision: %v", err)
	}
	ok, _ := signer.VerifyDecision(d)
	if !ok {
		t.Fatal("verify decision failed")
	}
}

func TestStress_Ed25519SignIntent(t *testing.T) {
	signer, _ := NewEd25519Signer("ed-int")
	i := &contracts.AuthorizedExecutionIntent{ID: "i1", DecisionID: "d1", AllowedTool: "tool"}
	if err := signer.SignIntent(i); err != nil {
		t.Fatalf("sign intent: %v", err)
	}
	ok, _ := signer.VerifyIntent(i)
	if !ok {
		t.Fatal("verify intent failed")
	}
}

func TestStress_Ed25519SignReceipt(t *testing.T) {
	signer, _ := NewEd25519Signer("ed-rec")
	r := &contracts.Receipt{ReceiptID: "r1", DecisionID: "d1", EffectID: "e1", Status: "SUCCESS"}
	if err := signer.SignReceipt(r); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	ok, _ := signer.VerifyReceipt(r)
	if !ok {
		t.Fatal("verify receipt failed")
	}
}

// ── Sign every contract type x ML-DSA ───────────────────────────────────

func TestStress_MLDSASignDecision(t *testing.T) {
	signer, _ := NewMLDSASigner("pq-dec")
	d := &contracts.DecisionRecord{ID: "d2", Verdict: "DENY", Reason: "blocked"}
	if err := signer.SignDecision(d); err != nil {
		t.Fatalf("sign decision: %v", err)
	}
}

func TestStress_MLDSASignIntent(t *testing.T) {
	signer, _ := NewMLDSASigner("pq-int")
	i := &contracts.AuthorizedExecutionIntent{ID: "i2", DecisionID: "d2", AllowedTool: "tool-pq"}
	if err := signer.SignIntent(i); err != nil {
		t.Fatalf("sign intent: %v", err)
	}
}

func TestStress_MLDSASignReceipt(t *testing.T) {
	signer, _ := NewMLDSASigner("pq-rec")
	r := &contracts.Receipt{ReceiptID: "r2", DecisionID: "d2", EffectID: "e2", Status: "SUCCESS"}
	if err := signer.SignReceipt(r); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
}

// ── Canonicalization functions ───────────────────────────────────────────

func TestStress_CanonicalizeDecisionStrict(t *testing.T) {
	_, err := CanonicalizeDecisionStrict("", "ALLOW", "ok", "ph", "pch", "ed")
	if err == nil {
		t.Fatal("empty ID should fail strict")
	}
	_, err = CanonicalizeDecisionStrict("d1", "", "ok", "ph", "pch", "ed")
	if err == nil {
		t.Fatal("empty verdict should fail strict")
	}
	result, err := CanonicalizeDecisionStrict("d1", "ALLOW", "ok", "ph", "pch", "ed")
	if err != nil || result == "" {
		t.Fatalf("valid strict failed: %v", err)
	}
}

func TestStress_CanonicalizeIntent(t *testing.T) {
	result := CanonicalizeIntent("i1", "d1", "tool")
	if result == "" {
		t.Fatal("intent canonical should not be empty")
	}
}

func TestStress_CanonicalizeReceipt(t *testing.T) {
	result := CanonicalizeReceipt("r1", "d1", "e1", "OK", "hash", "prev", 42, "args")
	if result == "" {
		t.Fatal("receipt canonical should not be empty")
	}
}

// ── Verifier ────────────────────────────────────────────────────────────

func TestStress_VerifierFromSignerPubKey(t *testing.T) {
	signer, _ := NewEd25519Signer("v-key")
	verifier, err := NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	msg := []byte("verify-me")
	sig, _ := signer.Sign(msg)
	sigBytes, _ := hex.DecodeString(sig)
	if !verifier.Verify(msg, sigBytes) {
		t.Fatal("verifier should accept valid sig")
	}
}

func TestStress_VerifierInvalidPubKeySize(t *testing.T) {
	_, err := NewEd25519Verifier([]byte("short"))
	if err == nil {
		t.Fatal("short key should fail")
	}
}

func TestStress_VerifyGlobal(t *testing.T) {
	signer, _ := NewEd25519Signer("global-v")
	msg := []byte("global-verify")
	sig, _ := signer.Sign(msg)
	ok, err := Verify(signer.PublicKey(), sig, msg)
	if err != nil || !ok {
		t.Fatal("global verify failed")
	}
}

func TestStress_VerifyBadHex(t *testing.T) {
	_, err := Verify("not-hex", "also-not-hex", []byte("msg"))
	if err == nil {
		t.Fatal("bad hex should fail")
	}
}

func TestStress_Ed25519GetKeyID(t *testing.T) {
	signer, _ := NewEd25519Signer("my-id")
	if signer.GetKeyID() != "my-id" {
		t.Fatalf("expected my-id, got %s", signer.GetKeyID())
	}
}

func TestStress_Ed25519FromKey(t *testing.T) {
	s1, _ := NewEd25519Signer("orig")
	s2 := NewEd25519SignerFromKey(s1.privKey, "derived")
	if s2.PublicKey() != s1.PublicKey() {
		t.Fatal("derived signer should have same pub key")
	}
}

func TestStress_KeyRingEmpty(t *testing.T) {
	ring := NewKeyRing()
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "ALLOW"}
	err := ring.SignDecision(d)
	if err == nil {
		t.Fatal("empty ring should fail signing")
	}
}

func TestStress_KeyRingVerifyMissing(t *testing.T) {
	ring := NewKeyRing()
	_, err := ring.VerifyKey("missing", []byte("msg"), []byte("sig"))
	if err == nil {
		t.Fatal("missing key should fail verify")
	}
}

func TestStress_SigPrefixConstants(t *testing.T) {
	if SigPrefixEd25519 != "ed25519" {
		t.Fatalf("got %s", SigPrefixEd25519)
	}
	if SigPrefixMLDSA65 != "ml-dsa-65" {
		t.Fatalf("got %s", SigPrefixMLDSA65)
	}
}

func TestStress_SigSeparator(t *testing.T) {
	if SigSeparator != ":" {
		t.Fatalf("got %s", SigSeparator)
	}
}

func TestStress_AlgorithmConstants(t *testing.T) {
	if AlgorithmEd25519 != "ed25519" || AlgorithmMLDSA65 != "ml-dsa-65" {
		t.Fatal("algorithm constant mismatch")
	}
}

func TestStress_HSMKeyDir(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	if hsm == nil {
		t.Fatal("HSM should not be nil")
	}
}

func TestStress_VerifierDecision(t *testing.T) {
	signer, _ := NewEd25519Signer("vd-key")
	d := &contracts.DecisionRecord{ID: "d-vd", Verdict: "ALLOW", Reason: "ok"}
	_ = signer.SignDecision(d)
	verifier, _ := NewEd25519Verifier(signer.PublicKeyBytes())
	ok, err := verifier.VerifyDecision(d)
	if err != nil || !ok {
		t.Fatal("verifier decision should pass")
	}
}

func TestStress_VerifierReceipt(t *testing.T) {
	signer, _ := NewEd25519Signer("vr-key")
	r := &contracts.Receipt{ReceiptID: "r-vr", DecisionID: "d1", EffectID: "e1", Status: "OK"}
	_ = signer.SignReceipt(r)
	verifier, _ := NewEd25519Verifier(signer.PublicKeyBytes())
	ok, err := verifier.VerifyReceipt(r)
	if err != nil || !ok {
		t.Fatal("verifier receipt should pass")
	}
}

func TestStress_VerifierIntent(t *testing.T) {
	signer, _ := NewEd25519Signer("vi-key")
	i := &contracts.AuthorizedExecutionIntent{ID: "i-vi", DecisionID: "d1", AllowedTool: "t"}
	_ = signer.SignIntent(i)
	verifier, _ := NewEd25519Verifier(signer.PublicKeyBytes())
	ok, err := verifier.VerifyIntent(i)
	if err != nil || !ok {
		t.Fatal("verifier intent should pass")
	}
}

func TestStress_VerifierMissingSig(t *testing.T) {
	signer, _ := NewEd25519Signer("ms-key")
	verifier, _ := NewEd25519Verifier(signer.PublicKeyBytes())
	_, err := verifier.VerifyDecision(&contracts.DecisionRecord{ID: "d"})
	if err == nil {
		t.Fatal("missing signature should fail")
	}
}
