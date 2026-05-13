package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// BenchmarkMLDSA65_KeyGen measures ML-DSA-65 key pair generation.
// Expected: ~1-2ms per op (vs ~30us for Ed25519).
func BenchmarkMLDSA65_KeyGen(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := NewMLDSASigner(fmt.Sprintf("bench-keygen-%d", i))
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMLDSA65_Sign measures ML-DSA-65 signing overhead.
// Expected: ~2-4ms per op (vs ~50us for Ed25519).
func BenchmarkMLDSA65_Sign(b *testing.B) {
	signer, err := NewMLDSASigner("bench-sign")
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("benchmark signing payload for ml-dsa-65 performance measurement")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMLDSA65_Verify measures ML-DSA-65 verification overhead.
// Expected: ~1-2ms per op (vs ~100us for Ed25519).
func BenchmarkMLDSA65_Verify(b *testing.B) {
	signer, err := NewMLDSASigner("bench-verify")
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("benchmark verify payload for ml-dsa-65 performance measurement")
	sigHex, err := signer.Sign(message)
	if err != nil {
		b.Fatal(err)
	}
	sigBytes, _ := hex.DecodeString(sigHex)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !signer.Verify(message, sigBytes) {
			b.Fatal("verification failed")
		}
	}
}

// BenchmarkMLDSA65_SignReceipt measures the full receipt signing path.
func BenchmarkMLDSA65_SignReceipt(b *testing.B) {
	signer, err := NewMLDSASigner("bench-receipt")
	if err != nil {
		b.Fatal(err)
	}

	receipt := &contracts.Receipt{
		ReceiptID:    "rcpt-bench-000",
		DecisionID:   "dec-bench-000",
		EffectID:     "eff-bench-000",
		Status:       "EXECUTED",
		OutputHash:   "sha256:deadbeef",
		PrevHash:     "sha256:00000000",
		LamportClock: 1,
		ArgsHash:     "sha256:aabbccdd",
		Timestamp:    time.Now(),
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		receipt.ReceiptID = fmt.Sprintf("rcpt-bench-%d", i)
		receipt.Signature = ""
		if err := signer.SignReceipt(receipt); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMLDSA65_SignDecision measures decision signing overhead.
func BenchmarkMLDSA65_SignDecision(b *testing.B) {
	signer, err := NewMLDSASigner("bench-decision")
	if err != nil {
		b.Fatal(err)
	}

	decision := &contracts.DecisionRecord{
		Verdict:           "ALLOW",
		Reason:            "policy-match",
		PhenotypeHash:     "sha256:pheno",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      "sha256:effect",
		Timestamp:         time.Now(),
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decision.ID = fmt.Sprintf("dec-bench-%d", i)
		decision.Signature = ""
		if err := signer.SignDecision(decision); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMLDSA65_VerifyReceipt measures receipt verification overhead.
func BenchmarkMLDSA65_VerifyReceipt(b *testing.B) {
	signer, err := NewMLDSASigner("bench-verify-receipt")
	if err != nil {
		b.Fatal(err)
	}

	receipt := &contracts.Receipt{
		ReceiptID:    "rcpt-bench-verify",
		DecisionID:   "dec-bench-verify",
		EffectID:     "eff-bench-verify",
		Status:       "EXECUTED",
		OutputHash:   "sha256:deadbeef",
		PrevHash:     "sha256:00000000",
		LamportClock: 1,
		ArgsHash:     "sha256:aabbccdd",
		Timestamp:    time.Now(),
	}
	if err := signer.SignReceipt(receipt); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		valid, err := signer.VerifyReceipt(receipt)
		if err != nil || !valid {
			b.Fatal("verification failed")
		}
	}
}
