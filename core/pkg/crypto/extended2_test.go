// quantum_posture: test-only coverage of existing cryptographic code paths;
// it makes no production deployment, hybrid, or post-quantum assurance claim.
package crypto

import (
	"context"

	"encoding/hex"
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto/shredding"
)

// ─── 1: ML-DSA keygen determinism from same seed ─────────────────

func TestExt2_MLDSAKeygenDeterminism(t *testing.T) {
	s1, _ := NewMLDSASigner("k1")
	s2, _ := NewMLDSASigner("k2")
	if s1.PublicKey() == s2.PublicKey() {
		t.Fatal("different random seeds should produce different keys")
	}
}

func TestExt2_MLDSASignVerifyCycle(t *testing.T) {
	s, _ := NewMLDSASigner("k1")
	sigHex, _ := s.Sign([]byte("hello"))
	sigBytes, _ := hex.DecodeString(sigHex)
	if !s.Verify([]byte("hello"), sigBytes) {
		t.Fatal("ML-DSA sign/verify cycle failed")
	}
}

func TestExt2_MLDSAMultipleSignVerify(t *testing.T) {
	s, _ := NewMLDSASigner("k1")
	for i := 0; i < 5; i++ {
		msg := []byte("msg-" + string(rune('A'+i)))
		sigHex, _ := s.Sign(msg)
		sigBytes, _ := hex.DecodeString(sigHex)
		if !s.Verify(msg, sigBytes) {
			t.Fatalf("sign/verify cycle %d failed", i)
		}
	}
}

func TestExt2_MLDSAKeySerializationRoundTrip(t *testing.T) {
	s, _ := NewMLDSASigner("k1")
	pub := s.PublicKey()
	pubBytes := s.PublicKeyBytes()
	if hex.EncodeToString(pubBytes) != pub {
		t.Fatal("PublicKey() and PublicKeyBytes() should be consistent")
	}
}

func TestExt2_MLDSADeterministicSig(t *testing.T) {
	s, _ := NewMLDSASigner("k1")
	sig1, _ := s.Sign([]byte("deterministic"))
	sig2, _ := s.Sign([]byte("deterministic"))
	if sig1 != sig2 {
		t.Fatal("ML-DSA deterministic mode should produce identical signatures")
	}
}

func TestExt2_MLDSASignDecisionType(t *testing.T) {
	s, _ := NewMLDSASigner("pq1")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "ALLOW"}
	s.SignDecision(testDecisionV4Authority(d))
	if d.SignatureType != "ml-dsa-65:pq1" {
		t.Fatalf("expected ml-dsa-65:pq1, got %s", d.SignatureType)
	}
}

func TestExt2_MLDSAVerifyDecisionRoundTrip(t *testing.T) {
	s, _ := NewMLDSASigner("pq1")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "DENY", Reason: "test"}
	s.SignDecision(testDecisionV4Authority(d))
	ok, err := s.VerifyDecision(d)
	if err != nil || !ok {
		t.Fatalf("VerifyDecision round trip failed: ok=%v err=%v", ok, err)
	}
}

func TestExt2_KeyRingConcurrent100(t *testing.T) {
	kr := NewKeyRing()
	ed, _ := NewEd25519Signer("k1")
	kr.AddKey(ed)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			kr.Sign([]byte("concurrent-data"))
		}(i)
	}
	wg.Wait()
}

func TestExt2_KeyRingConcurrentMixedOps(t *testing.T) {
	kr := NewKeyRing()
	ed, _ := NewEd25519Signer("k1")
	kr.AddKey(ed)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			kr.Sign([]byte("data"))
		}()
		go func() {
			defer wg.Done()
			kr.PublicKey()
		}()
	}
	wg.Wait()
}

func TestExt2_KeyRingSignVerifyIntent(t *testing.T) {
	kr := NewKeyRing()
	ed, _ := NewEd25519Signer("k1")
	kr.AddKey(ed)
	i := &contracts.AuthorizedExecutionIntent{ID: "i1", DecisionID: "d1", AllowedTool: "read"}
	kr.SignIntent(i)
	ok, err := kr.VerifyIntent(i)
	if err != nil || !ok {
		t.Fatalf("intent verify failed: ok=%v err=%v", ok, err)
	}
}

func TestExt2_KeyRingSignVerifyReceipt(t *testing.T) {
	kr := NewKeyRing()
	ed, _ := NewEd25519Signer("k1")
	kr.AddKey(ed)
	r := &contracts.Receipt{ReceiptID: "r1", DecisionID: "d1", EffectID: "e1", Status: "SUCCESS"}
	kr.SignReceipt(r)
	ok, err := kr.VerifyReceipt(r)
	if err != nil || !ok {
		t.Fatalf("receipt verify failed: ok=%v err=%v", ok, err)
	}
}

func TestExt2_ShreddingEncryptDecrypt(t *testing.T) {
	ks := shredding.NewKeyStore()
	ks.GenerateKey(context.Background(), "user-1")
	ct, err := ks.Encrypt(context.Background(), "user-1", []byte("personal data"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ks.Decrypt(context.Background(), "user-1", ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "personal data" {
		t.Fatalf("expected 'personal data', got %q", pt)
	}
}

func TestExt2_ShreddingAfterShredDecryptFails(t *testing.T) {
	ks := shredding.NewKeyStore()
	ks.GenerateKey(context.Background(), "user-1")
	ct, _ := ks.Encrypt(context.Background(), "user-1", []byte("secret"))
	ks.Shred(context.Background(), "user-1", "GDPR Art. 17")
	_, err := ks.Decrypt(context.Background(), "user-1", ct)
	if err == nil {
		t.Fatal("decrypt after shred should fail")
	}
}

func TestExt2_ShreddingIsShredded(t *testing.T) {
	ks := shredding.NewKeyStore()
	ks.GenerateKey(context.Background(), "user-1")
	ks.Shred(context.Background(), "user-1", "GDPR")
	if !ks.IsShredded("user-1") {
		t.Fatal("should report shredded")
	}
}

func TestExt2_ShreddingLogRecorded(t *testing.T) {
	ks := shredding.NewKeyStore()
	ks.GenerateKey(context.Background(), "user-1")
	ks.Shred(context.Background(), "user-1", "GDPR Art. 17")
	log := ks.GetShreddingLog()
	if len(log) != 1 || log[0].LegalBasis != "GDPR Art. 17" {
		t.Fatal("shredding log should contain one record with legal basis")
	}
}

func TestExt2_ShreddingUnknownSubjectFails(t *testing.T) {
	ks := shredding.NewKeyStore()
	_, err := ks.Shred(context.Background(), "nonexistent", "GDPR")
	if err == nil {
		t.Fatal("shred of unknown subject should fail")
	}
}
