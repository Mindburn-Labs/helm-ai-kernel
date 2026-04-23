package crypto

import (
	"fmt"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// BenchmarkEd25519_SignReceipt measures the cost of Ed25519 receipt signing.
// This is the core cryptographic operation on the HELM hot path.
func BenchmarkEd25519_SignReceipt(b *testing.B) {
	signer, err := NewEd25519Signer("bench-key")
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
		receipt.Signature = "" // Reset for re-sign
		if err := signer.SignReceipt(receipt); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEd25519_VerifyReceipt measures the cost of Ed25519 receipt verification.
func BenchmarkEd25519_VerifyReceipt(b *testing.B) {
	signer, err := NewEd25519Signer("bench-key")
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

// BenchmarkEd25519_SignDecision measures decision signing overhead.
func BenchmarkEd25519_SignDecision(b *testing.B) {
	signer, err := NewEd25519Signer("bench-key")
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
