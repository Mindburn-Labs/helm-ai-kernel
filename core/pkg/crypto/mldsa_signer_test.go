package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestMLDSASigner_NewMLDSASigner(t *testing.T) {
	signer, err := NewMLDSASigner("pq-key-1")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}
	if signer.GetKeyID() != "pq-key-1" {
		t.Errorf("expected keyID 'pq-key-1', got %q", signer.GetKeyID())
	}
	if signer.PublicKey() == "" {
		t.Error("public key is empty")
	}
	pubBytes := signer.PublicKeyBytes()
	if len(pubBytes) != mldsa65.PublicKeySize {
		t.Errorf("public key size = %d, want %d", len(pubBytes), mldsa65.PublicKeySize)
	}
}

func TestMLDSASigner_SignVerifyRoundTrip(t *testing.T) {
	signer, err := NewMLDSASigner("pq-key-1")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}

	message := []byte("hello post-quantum world")

	sigHex, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}

	if len(sigBytes) != mldsa65.SignatureSize {
		t.Errorf("signature size = %d, want %d", len(sigBytes), mldsa65.SignatureSize)
	}

	// Verify with signer
	if !signer.Verify(message, sigBytes) {
		t.Error("Verify returned false for valid signature")
	}

	// Verify with standalone verifier
	verifier, err := NewMLDSAVerifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatalf("NewMLDSAVerifier failed: %v", err)
	}
	if !verifier.Verify(message, sigBytes) {
		t.Error("MLDSAVerifier returned false for valid signature")
	}

	// Tampered message must fail
	if signer.Verify([]byte("tampered"), sigBytes) {
		t.Error("Verify accepted tampered message")
	}
}

func TestMLDSASigner_SignDecision(t *testing.T) {
	signer, err := NewMLDSASigner("pq-key-1")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}

	d := &contracts.DecisionRecord{
		ID:                "dec-pq-001",
		Verdict:           "ALLOW",
		Reason:            "policy-match",
		PhenotypeHash:     "sha256:pheno",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      "sha256:effect",
		Timestamp:         time.Now(),
	}

	if err := signer.SignDecision(d); err != nil {
		t.Fatalf("SignDecision failed: %v", err)
	}

	// Verify SignatureType format
	if !strings.HasPrefix(d.SignatureType, SigPrefixMLDSA65+SigSeparator) {
		t.Errorf("SignatureType = %q, want prefix %q", d.SignatureType, SigPrefixMLDSA65+SigSeparator)
	}
	if !strings.HasSuffix(d.SignatureType, "pq-key-1") {
		t.Errorf("SignatureType = %q, want suffix 'pq-key-1'", d.SignatureType)
	}

	// Verify signature
	valid, err := signer.VerifyDecision(d)
	if err != nil {
		t.Fatalf("VerifyDecision failed: %v", err)
	}
	if !valid {
		t.Error("VerifyDecision returned false for valid decision")
	}

	// Tampered decision must fail
	d.Reason = "I changed this"
	valid, _ = signer.VerifyDecision(d)
	if valid {
		t.Error("VerifyDecision accepted tampered decision")
	}
}

func TestMLDSASigner_SignIntent(t *testing.T) {
	signer, err := NewMLDSASigner("pq-key-2")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}

	intent := &contracts.AuthorizedExecutionIntent{
		ID:          "intent-pq-001",
		DecisionID:  "dec-pq-001",
		AllowedTool: "read_file",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	if err := signer.SignIntent(intent); err != nil {
		t.Fatalf("SignIntent failed: %v", err)
	}

	if intent.SignatureType != SigPrefixMLDSA65+SigSeparator+"pq-key-2" {
		t.Errorf("SignatureType = %q, want %q", intent.SignatureType, SigPrefixMLDSA65+SigSeparator+"pq-key-2")
	}

	valid, err := signer.VerifyIntent(intent)
	if err != nil {
		t.Fatalf("VerifyIntent failed: %v", err)
	}
	if !valid {
		t.Error("VerifyIntent returned false for valid intent")
	}

	// Tamper
	intent.AllowedTool = "delete_file"
	valid, _ = signer.VerifyIntent(intent)
	if valid {
		t.Error("VerifyIntent accepted tampered intent")
	}
}

func TestMLDSASigner_SignReceipt(t *testing.T) {
	signer, err := NewMLDSASigner("pq-key-3")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}

	receipt := &contracts.Receipt{
		ReceiptID:    "rcpt-pq-001",
		DecisionID:   "dec-pq-001",
		EffectID:     "eff-pq-001",
		Status:       "EXECUTED",
		OutputHash:   "sha256:out",
		PrevHash:     "sha256:prev",
		LamportClock: 42,
		ArgsHash:     "sha256:args",
		Timestamp:    time.Now(),
	}

	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatalf("SignReceipt failed: %v", err)
	}

	if receipt.Signature == "" {
		t.Error("Signature empty after signing receipt")
	}

	valid, err := signer.VerifyReceipt(receipt)
	if err != nil {
		t.Fatalf("VerifyReceipt failed: %v", err)
	}
	if !valid {
		t.Error("VerifyReceipt returned false for valid receipt")
	}

	// Tamper
	receipt.Status = "FAILED"
	valid, _ = signer.VerifyReceipt(receipt)
	if valid {
		t.Error("VerifyReceipt accepted tampered receipt")
	}
}

func TestMLDSASigner_CrossAlgorithmRejection(t *testing.T) {
	// An Ed25519 signature must not verify under ML-DSA-65, and vice versa.
	ed, err := NewEd25519Signer("ed-key")
	if err != nil {
		t.Fatalf("NewEd25519Signer failed: %v", err)
	}
	pq, err := NewMLDSASigner("pq-key")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}

	message := []byte("cross-algorithm test payload")

	// Sign with Ed25519, attempt verify with ML-DSA-65
	edSigHex, err := ed.Sign(message)
	if err != nil {
		t.Fatalf("Ed25519 Sign failed: %v", err)
	}
	edSigBytes, _ := hex.DecodeString(edSigHex)

	if pq.Verify(message, edSigBytes) {
		t.Error("ML-DSA-65 accepted Ed25519 signature")
	}

	// Sign with ML-DSA-65, attempt verify with Ed25519
	pqSigHex, err := pq.Sign(message)
	if err != nil {
		t.Fatalf("ML-DSA-65 Sign failed: %v", err)
	}
	pqSigBytes, _ := hex.DecodeString(pqSigHex)

	if ed.Verify(message, pqSigBytes) {
		t.Error("Ed25519 accepted ML-DSA-65 signature")
	}
}

func TestMLDSAVerifier_VerifyDecision(t *testing.T) {
	signer, err := NewMLDSASigner("pq-key-v")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}

	d := &contracts.DecisionRecord{
		ID:      "dec-v-001",
		Verdict: "DENY",
		Reason:  "blocked",
	}

	if err := signer.SignDecision(d); err != nil {
		t.Fatalf("SignDecision failed: %v", err)
	}

	// Verify with standalone verifier (only has public key)
	verifier, err := NewMLDSAVerifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatalf("NewMLDSAVerifier failed: %v", err)
	}

	valid, err := verifier.VerifyDecision(d)
	if err != nil {
		t.Fatalf("VerifyDecision failed: %v", err)
	}
	if !valid {
		t.Error("Verifier rejected valid decision")
	}
}

func TestMLDSAVerifier_InvalidPublicKey(t *testing.T) {
	_, err := NewMLDSAVerifier([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Error("expected error for invalid public key size")
	}
}

func TestMLDSAVerifier_PackageLevelVerify(t *testing.T) {
	signer, err := NewMLDSASigner("pq-key-pkg")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}

	message := []byte("package-level verify test")
	sigHex, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	valid, err := VerifyMLDSA65(signer.PublicKey(), sigHex, message)
	if err != nil {
		t.Fatalf("VerifyMLDSA65 failed: %v", err)
	}
	if !valid {
		t.Error("VerifyMLDSA65 returned false for valid signature")
	}

	// Bad public key hex
	_, err = VerifyMLDSA65("not-hex", sigHex, message)
	if err == nil {
		t.Error("expected error for bad public key hex")
	}

	// Bad sig hex
	_, err = VerifyMLDSA65(signer.PublicKey(), "not-hex", message)
	if err == nil {
		t.Error("expected error for bad signature hex")
	}
}

func TestKeyRing_AddKeyMLDSA(t *testing.T) {
	kr := NewKeyRing()

	pq, err := NewMLDSASigner("pq-ring-1")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}

	kr.AddKey(pq)

	// Sign with keyring
	d := &contracts.DecisionRecord{
		ID:      "dec-ring-pq",
		Verdict: "ALLOW",
		Reason:  "keyring-pq-test",
	}

	if err := kr.SignDecision(d); err != nil {
		t.Fatalf("KeyRing.SignDecision failed: %v", err)
	}

	if !strings.HasPrefix(d.SignatureType, SigPrefixMLDSA65+SigSeparator) {
		t.Errorf("SignatureType = %q, want prefix %q", d.SignatureType, SigPrefixMLDSA65+SigSeparator)
	}

	// Verify with keyring
	valid, err := kr.VerifyDecision(d)
	if err != nil {
		t.Fatalf("KeyRing.VerifyDecision failed: %v", err)
	}
	if !valid {
		t.Error("KeyRing.VerifyDecision returned false for valid ML-DSA-65 decision")
	}
}

func TestKeyRing_MixedAlgorithms(t *testing.T) {
	kr := NewKeyRing()

	ed, err := NewEd25519Signer("ed-mixed")
	if err != nil {
		t.Fatalf("NewEd25519Signer failed: %v", err)
	}
	pq, err := NewMLDSASigner("pq-mixed")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}

	kr.AddKey(ed)
	kr.AddKey(pq)

	// Sign a decision with Ed25519 signer directly
	dEd := &contracts.DecisionRecord{
		ID:      "dec-ed",
		Verdict: "ALLOW",
		Reason:  "ed25519-signed",
	}
	if err := ed.SignDecision(dEd); err != nil {
		t.Fatalf("Ed25519 SignDecision failed: %v", err)
	}

	// Verify via keyring (should route to Ed25519 key)
	valid, err := kr.VerifyDecision(dEd)
	if err != nil {
		t.Fatalf("KeyRing.VerifyDecision (ed25519) failed: %v", err)
	}
	if !valid {
		t.Error("KeyRing rejected valid Ed25519 decision")
	}

	// Sign a decision with ML-DSA-65 signer directly
	dPQ := &contracts.DecisionRecord{
		ID:      "dec-pq",
		Verdict: "DENY",
		Reason:  "ml-dsa-65-signed",
	}
	if err := pq.SignDecision(dPQ); err != nil {
		t.Fatalf("ML-DSA-65 SignDecision failed: %v", err)
	}

	// Verify via keyring (should route to ML-DSA-65 key)
	valid, err = kr.VerifyDecision(dPQ)
	if err != nil {
		t.Fatalf("KeyRing.VerifyDecision (ml-dsa-65) failed: %v", err)
	}
	if !valid {
		t.Error("KeyRing rejected valid ML-DSA-65 decision")
	}
}

func TestKeyRing_VerifyKeyMLDSA(t *testing.T) {
	kr := NewKeyRing()
	pq, err := NewMLDSASigner("pq-vk")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}
	kr.AddKey(pq)

	msg := []byte("verify-key test")
	sigHex, err := pq.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	sigBytes, _ := hex.DecodeString(sigHex)

	valid, err := kr.VerifyKey("pq-vk", msg, sigBytes)
	if err != nil {
		t.Fatalf("VerifyKey failed: %v", err)
	}
	if !valid {
		t.Error("VerifyKey returned false for valid ML-DSA-65 signature")
	}
}

func TestMLDSASigner_NewFromKey(t *testing.T) {
	// Generate, extract private key, reconstruct
	signer1, err := NewMLDSASigner("orig")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}

	message := []byte("reconstruct test")
	sigHex, err := signer1.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Create second signer from same private key
	signer2 := NewMLDSASignerFromKey(signer1.privateKey, "clone")
	if signer2.GetKeyID() != "clone" {
		t.Errorf("expected keyID 'clone', got %q", signer2.GetKeyID())
	}

	// Public keys must match
	if signer1.PublicKey() != signer2.PublicKey() {
		t.Error("public keys don't match after reconstruction")
	}

	// Verify original signature with cloned signer
	sigBytes, _ := hex.DecodeString(sigHex)
	if !signer2.Verify(message, sigBytes) {
		t.Error("cloned signer rejected original signature")
	}
}

func TestMLDSASigner_EmptySignatureErrors(t *testing.T) {
	signer, err := NewMLDSASigner("pq-empty")
	if err != nil {
		t.Fatalf("NewMLDSASigner failed: %v", err)
	}

	// VerifyDecision with empty signature
	d := &contracts.DecisionRecord{ID: "dec-1", Verdict: "ALLOW"}
	_, err = signer.VerifyDecision(d)
	if err == nil {
		t.Error("expected error for empty decision signature")
	}

	// VerifyIntent with empty signature
	i := &contracts.AuthorizedExecutionIntent{ID: "int-1", DecisionID: "dec-1"}
	_, err = signer.VerifyIntent(i)
	if err == nil {
		t.Error("expected error for empty intent signature")
	}

	// VerifyReceipt with empty signature
	r := &contracts.Receipt{ReceiptID: "rcpt-1", DecisionID: "dec-1"}
	_, err = signer.VerifyReceipt(r)
	if err == nil {
		t.Error("expected error for empty receipt signature")
	}
}

func TestSoftHSM_GetSignerWithAlgorithm(t *testing.T) {
	dir := t.TempDir()
	hsm, err := NewSoftHSM(dir)
	if err != nil {
		t.Fatalf("NewSoftHSM failed: %v", err)
	}

	// Ed25519 (default)
	edSigner, err := hsm.GetSignerWithAlgorithm("test-ed", AlgorithmEd25519)
	if err != nil {
		t.Fatalf("GetSignerWithAlgorithm(ed25519) failed: %v", err)
	}
	if _, ok := edSigner.(*Ed25519Signer); !ok {
		t.Error("expected *Ed25519Signer")
	}

	// ML-DSA-65
	pqSigner, err := hsm.GetSignerWithAlgorithm("test-pq", AlgorithmMLDSA65)
	if err != nil {
		t.Fatalf("GetSignerWithAlgorithm(ml-dsa-65) failed: %v", err)
	}
	if _, ok := pqSigner.(*MLDSASigner); !ok {
		t.Error("expected *MLDSASigner")
	}

	// Sign and verify round-trip
	d := &contracts.DecisionRecord{
		ID:      "hsm-dec-1",
		Verdict: "ALLOW",
		Reason:  "hsm-test",
	}
	if err := pqSigner.SignDecision(d); err != nil {
		t.Fatalf("SignDecision failed: %v", err)
	}

	pqSigner2 := pqSigner.(*MLDSASigner)
	valid, err := pqSigner2.VerifyDecision(d)
	if err != nil {
		t.Fatalf("VerifyDecision failed: %v", err)
	}
	if !valid {
		t.Error("VerifyDecision returned false for HSM-generated key")
	}

	// Reload from disk
	pqSigner3, err := hsm.GetSignerWithAlgorithm("test-pq", AlgorithmMLDSA65)
	if err != nil {
		t.Fatalf("GetSignerWithAlgorithm reload failed: %v", err)
	}
	if pqSigner3.PublicKey() != pqSigner.PublicKey() {
		t.Error("reloaded key has different public key")
	}

	// Unsupported algorithm
	_, err = hsm.GetSignerWithAlgorithm("test-bad", "rsa-4096")
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestSoftHSM_MLDSAKeyPersistence(t *testing.T) {
	dir := t.TempDir()

	// Create HSM, generate key
	hsm1, err := NewSoftHSM(dir)
	if err != nil {
		t.Fatalf("NewSoftHSM failed: %v", err)
	}
	signer1, err := hsm1.GetSignerWithAlgorithm("persist-pq", AlgorithmMLDSA65)
	if err != nil {
		t.Fatalf("GetSignerWithAlgorithm failed: %v", err)
	}
	pubKey1 := signer1.PublicKey()

	// Create new HSM instance, load same key from disk
	hsm2, err := NewSoftHSM(dir)
	if err != nil {
		t.Fatalf("NewSoftHSM failed: %v", err)
	}
	signer2, err := hsm2.GetSignerWithAlgorithm("persist-pq", AlgorithmMLDSA65)
	if err != nil {
		t.Fatalf("GetSignerWithAlgorithm reload failed: %v", err)
	}

	if signer2.PublicKey() != pubKey1 {
		t.Error("persisted ML-DSA-65 key produced different public key after reload")
	}

	// Cross-verify: sign with first, verify with second
	message := []byte("persistence test")
	sigHex, err := signer1.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	sigBytes, _ := hex.DecodeString(sigHex)

	s2 := signer2.(*MLDSASigner)
	if !s2.Verify(message, sigBytes) {
		t.Error("reloaded signer rejected signature from original signer")
	}
}
