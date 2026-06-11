package crypto

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func sampleCounterfactual() *contracts.CounterfactualReceipt {
	return &contracts.CounterfactualReceipt{
		ReceiptID:          "cf-receipt-1",
		Enforcement:        contracts.EnforcementCounterfactual,
		WouldHaveVerdict:   contracts.VerdictDeny,
		ReasonCode:         contracts.ReasonApprovalRequired,
		ObserveGrantID:     "og-1",
		BoundaryRecordID:   "mcp-boundary-1",
		BoundaryRecordHash: "sha256:deadbeef",
		PolicyEpoch:        "epoch-42",
		ToolName:           "deploy",
		MCPServerID:        "srv-1",
		ArgsHash:           "sha256:args",
		CreatedAt:          time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC),
	}
}

func TestSignAndVerifyCounterfactualReceipt(t *testing.T) {
	s, err := NewEd25519Signer("k1")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	r := sampleCounterfactual()
	if err := s.SignCounterfactualReceipt(r); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if r.Signature == "" || r.ReceiptHash == "" || r.SignerKeyID == "" {
		t.Fatal("signing must populate signature, receipt hash, and signer key id")
	}
	ok, err := s.VerifyCounterfactualReceipt(r)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("signature should verify")
	}
}

// TestCounterfactualSignatureNotReplayableAsEnforced is the P0 crypto vector: a
// signature minted over a counterfactual receipt must not verify if the receipt
// is coerced to enforced, and a counterfactual receipt with a tampered verdict
// must fail verification.
func TestCounterfactualSignatureNotReplayableAsEnforced(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	r := sampleCounterfactual()
	if err := s.SignCounterfactualReceipt(r); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Coerce the enforcement label: verification must refuse to re-seal it.
	coerced := *r
	coerced.Enforcement = contracts.EnforcementEnforced
	if ok, err := s.VerifyCounterfactualReceipt(&coerced); ok || err == nil {
		t.Fatal("P0 VIOLATION: a counterfactual signature verified after coercion to enforced")
	}

	// Tamper with the would-have verdict: the recomputed hash no longer matches.
	tampered := *r
	tampered.WouldHaveVerdict = contracts.VerdictAllow
	tampered.ReasonCode = ""
	if ok, _ := s.VerifyCounterfactualReceipt(&tampered); ok {
		t.Fatal("tampered would-have verdict must fail verification")
	}
}

func TestSignCounterfactualRejectsNonCounterfactual(t *testing.T) {
	s, _ := NewEd25519Signer("k1")
	r := sampleCounterfactual()
	r.Enforcement = contracts.EnforcementEnforced
	if err := s.SignCounterfactualReceipt(r); err == nil {
		t.Fatal("signing a non-counterfactual receipt via this path must fail")
	}
}
