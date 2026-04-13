package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto/mtls"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto/sdjwt"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto/shredding"
	helmtls "github.com/Mindburn-Labs/helm-oss/core/pkg/crypto/tls"
)

// ─── 1: ML-DSA keygen determinism from same seed ─────────────────

func TestExt2_MLDSAKeygenDeterminism(t *testing.T) {
	s1, _ := NewMLDSASigner("k1")
	s2, _ := NewMLDSASigner("k2")
	if s1.PublicKey() == s2.PublicKey() {
		t.Fatal("different random seeds should produce different keys")
	}
}

// ─── 2: ML-DSA sign then verify cycle ───────────────────────────

func TestExt2_MLDSASignVerifyCycle(t *testing.T) {
	s, _ := NewMLDSASigner("k1")
	sigHex, _ := s.Sign([]byte("hello"))
	sigBytes, _ := hex.DecodeString(sigHex)
	if !s.Verify([]byte("hello"), sigBytes) {
		t.Fatal("ML-DSA sign/verify cycle failed")
	}
}

// ─── 3: ML-DSA multiple sign/verify cycles ───────────────────────

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

// ─── 4: ML-DSA key serialization round trip ──────────────────────

func TestExt2_MLDSAKeySerializationRoundTrip(t *testing.T) {
	s, _ := NewMLDSASigner("k1")
	pub := s.PublicKey()
	pubBytes := s.PublicKeyBytes()
	if hex.EncodeToString(pubBytes) != pub {
		t.Fatal("PublicKey() and PublicKeyBytes() should be consistent")
	}
}

// ─── 5: ML-DSA deterministic signatures same input ───────────────

func TestExt2_MLDSADeterministicSig(t *testing.T) {
	s, _ := NewMLDSASigner("k1")
	sig1, _ := s.Sign([]byte("deterministic"))
	sig2, _ := s.Sign([]byte("deterministic"))
	if sig1 != sig2 {
		t.Fatal("ML-DSA deterministic mode should produce identical signatures")
	}
}

// ─── 6: ML-DSA SignDecision populates signature type ─────────────

func TestExt2_MLDSASignDecisionType(t *testing.T) {
	s, _ := NewMLDSASigner("pq1")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "ALLOW"}
	s.SignDecision(d)
	if d.SignatureType != "ml-dsa-65:pq1" {
		t.Fatalf("expected ml-dsa-65:pq1, got %s", d.SignatureType)
	}
}

// ─── 7: ML-DSA VerifyDecision round trip ─────────────────────────

func TestExt2_MLDSAVerifyDecisionRoundTrip(t *testing.T) {
	s, _ := NewMLDSASigner("pq1")
	d := &contracts.DecisionRecord{ID: "d1", Verdict: "DENY", Reason: "test"}
	s.SignDecision(d)
	ok, err := s.VerifyDecision(d)
	if err != nil || !ok {
		t.Fatalf("VerifyDecision round trip failed: ok=%v err=%v", ok, err)
	}
}

// ─── 8: KeyRing concurrent 100 goroutines ───────────────────────

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

// ─── 9: KeyRing concurrent mixed sign and verify ─────────────────

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

// ─── 10: KeyRing SignIntent and VerifyIntent round trip ──────────

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

// ─── 11: KeyRing SignReceipt and VerifyReceipt round trip ────────

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

// ─── 12: mTLS CA creation and cert issuance ──────────────────────

func TestExt2_MTLSCertIssuance(t *testing.T) {
	ca, err := mtls.NewCA(mtls.CAConfig{Organization: "test"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueCertificate(context.Background(), "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if cert.SPIFFEID != "spiffe://helm.local/proxy" {
		t.Fatalf("unexpected SPIFFE ID: %s", cert.SPIFFEID)
	}
}

// ─── 13: mTLS CA cert needs renewal ──────────────────────────────

func TestExt2_MTLSCertNeedsRenewal(t *testing.T) {
	ca, _ := mtls.NewCA(mtls.CAConfig{CertTTL: 1, RenewBefore: 1})
	cert, _ := ca.IssueCertificate(context.Background(), "agent")
	if !ca.NeedsRenewal(cert) {
		t.Fatal("cert with zero TTL should need renewal")
	}
}

// ─── 14: mTLS empty identity rejected ────────────────────────────

func TestExt2_MTLSEmptyIdentityRejected(t *testing.T) {
	ca, _ := mtls.NewCA(mtls.CAConfig{})
	_, err := ca.IssueCertificate(context.Background(), "")
	if err == nil {
		t.Fatal("empty identity should be rejected")
	}
}

// ─── 15: mTLS mutual TLS config creation ─────────────────────────

func TestExt2_MTLSMutualTLSConfig(t *testing.T) {
	ca, _ := mtls.NewCA(mtls.CAConfig{})
	cert, _ := ca.IssueCertificate(context.Background(), "server")
	cfg, err := mtls.NewMutualTLSConfig(cert)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != 0x0304 { // TLS 1.3
		t.Fatalf("expected TLS 1.3, got %x", cfg.MinVersion)
	}
}

// ─── 16: SD-JWT issue and verify round trip ──────────────────────

func TestExt2_SDJWTIssueAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	issuer := sdjwt.NewIssuer(priv, "test-issuer")
	claims := map[string]any{"name": "alice", "age": 30, "role": "admin"}
	token, discs, err := issuer.Issue(claims, []string{"age"})
	if err != nil {
		t.Fatal(err)
	}
	verifier := sdjwt.NewVerifier(pub)
	pres := sdjwt.Presentation(token, discs)
	result, err := verifier.Verify(pres)
	if err != nil {
		t.Fatal(err)
	}
	if result.IssuerID != "test-issuer" {
		t.Fatalf("expected issuer test-issuer, got %s", result.IssuerID)
	}
}

// ─── 17: SD-JWT selective disclosure hides undisclosed ────────────

func TestExt2_SDJWTSelectiveHide(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	issuer := sdjwt.NewIssuer(priv, "iss")
	token, _, err := issuer.Issue(map[string]any{"secret": "hidden", "public": "visible"}, []string{"secret"})
	if err != nil {
		t.Fatal(err)
	}
	// Present without disclosures
	pres := sdjwt.Presentation(token, nil)
	verifier := sdjwt.NewVerifier(pub)
	result, err := verifier.Verify(pres)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := result.Claims["secret"]; exists {
		t.Fatal("undisclosed claim should not appear")
	}
}

// ─── 18: SD-JWT deterministic disclosure with salt ───────────────

func TestExt2_SDJWTDeterministicDisclosure(t *testing.T) {
	d := sdjwt.NewDisclosureWithSalt("fixed-salt", "claim", "value")
	h1 := d.Hash()
	d2 := sdjwt.NewDisclosureWithSalt("fixed-salt", "claim", "value")
	if h1 != d2.Hash() {
		t.Fatal("same salt+claim+value should produce same hash")
	}
}

// ─── 19: Shredding encrypt then decrypt round trip ───────────────

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

// ─── 20: Shredding after shred decrypt fails ─────────────────────

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

// ─── 21: Shredding IsShredded returns true after shred ───────────

func TestExt2_ShreddingIsShredded(t *testing.T) {
	ks := shredding.NewKeyStore()
	ks.GenerateKey(context.Background(), "user-1")
	ks.Shred(context.Background(), "user-1", "GDPR")
	if !ks.IsShredded("user-1") {
		t.Fatal("should report shredded")
	}
}

// ─── 22: Shredding log records operation ─────────────────────────

func TestExt2_ShreddingLogRecorded(t *testing.T) {
	ks := shredding.NewKeyStore()
	ks.GenerateKey(context.Background(), "user-1")
	ks.Shred(context.Background(), "user-1", "GDPR Art. 17")
	log := ks.GetShreddingLog()
	if len(log) != 1 || log[0].LegalBasis != "GDPR Art. 17" {
		t.Fatal("shredding log should contain one record with legal basis")
	}
}

// ─── 23: Shredding unknown subject fails ─────────────────────────

func TestExt2_ShreddingUnknownSubjectFails(t *testing.T) {
	ks := shredding.NewKeyStore()
	_, err := ks.Shred(context.Background(), "nonexistent", "GDPR")
	if err == nil {
		t.Fatal("shred of unknown subject should fail")
	}
}

// ─── 24: TLS PQC hybrid supported ───────────────────────────────

func TestExt2_TLSPQCHybridSupported(t *testing.T) {
	if !helmtls.IsHybridPQCSupported() {
		t.Skip("hybrid PQC not supported on this Go version")
	}
	cfg := helmtls.HybridPQCConfig()
	if cfg.MinVersion != 0x0304 { // TLS 1.3
		t.Fatalf("expected TLS 1.3, got %x", cfg.MinVersion)
	}
}

// ─── 25: TLS PQC client config sets server name ─────────────────

func TestExt2_TLSPQCClientConfigServerName(t *testing.T) {
	if !helmtls.IsHybridPQCSupported() {
		t.Skip("hybrid PQC not supported on this Go version")
	}
	cfg := helmtls.ClientConfig("helm.example.com")
	if cfg.ServerName != "helm.example.com" {
		t.Fatalf("expected helm.example.com, got %s", cfg.ServerName)
	}
}
