package zkgov

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────────────
// 100 proofs generated
// ────────────────────────────────────────────────────────────────────────

func TestStress_100ProofsGenerated(t *testing.T) {
	prover := NewProver("node-1")
	for i := 0; i < 100; i++ {
		proof, err := prover.Prove(ProofRequest{
			DecisionID:   fmt.Sprintf("dec-%d", i),
			PolicyHash:   "sha256:policy",
			InputData:    map[string]interface{}{"action": "EXECUTE_TOOL", "index": i},
			Verdict:      "ALLOW",
			DecisionHash: fmt.Sprintf("sha256:dec-%d", i),
		})
		if err != nil {
			t.Fatalf("proof %d failed: %v", i, err)
		}
		if proof.ProofID == "" || proof.ContentHash == "" {
			t.Fatalf("proof %d missing fields", i)
		}
	}
}

func TestStress_100ProofsUniqueIDs(t *testing.T) {
	prover := NewProver("node-1")
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		proof, _ := prover.Prove(ProofRequest{
			DecisionID: fmt.Sprintf("d-%d", i), PolicyHash: "h", Verdict: "ALLOW", DecisionHash: "dh",
		})
		if ids[proof.ProofID] {
			t.Fatalf("duplicate proof ID: %s", proof.ProofID)
		}
		ids[proof.ProofID] = true
	}
}

func TestStress_ConcurrentProofGeneration(t *testing.T) {
	prover := NewProver("node-1")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := prover.Prove(ProofRequest{
				DecisionID: fmt.Sprintf("d-%d", n), PolicyHash: "h", Verdict: "ALLOW", DecisionHash: "dh",
			})
			if err != nil {
				t.Errorf("proof %d: %v", n, err)
			}
		}(i)
	}
	wg.Wait()
}

// ────────────────────────────────────────────────────────────────────────
// Verify each
// ────────────────────────────────────────────────────────────────────────

func TestStress_VerifyEachOf100Proofs(t *testing.T) {
	prover := NewProver("node-1")
	verifier := NewVerifier()
	for i := 0; i < 100; i++ {
		proof, _ := prover.Prove(ProofRequest{
			DecisionID: fmt.Sprintf("d-%d", i), PolicyHash: "h",
			InputData: map[string]interface{}{"k": i}, Verdict: "ALLOW", DecisionHash: "dh",
		})
		result, err := verifier.Verify(VerifyRequest{Proof: *proof})
		if err != nil {
			t.Fatalf("verify %d error: %v", i, err)
		}
		if !result.Valid {
			t.Fatalf("proof %d invalid: %s", i, result.Reason)
		}
	}
}

func TestStress_VerifyWrongAlgorithm(t *testing.T) {
	v := NewVerifier()
	proof := ZKGovernanceProof{Algorithm: "wrong-algo"}
	result, _ := v.Verify(VerifyRequest{Proof: proof})
	if result.Valid {
		t.Fatal("expected invalid for wrong algorithm")
	}
}

func TestStress_VerifyMissingProofID(t *testing.T) {
	v := NewVerifier()
	proof := ZKGovernanceProof{Algorithm: Algorithm}
	result, _ := v.Verify(VerifyRequest{Proof: proof})
	if result.Valid {
		t.Fatal("expected invalid for missing proof_id")
	}
}

func TestStress_VerifyMissingDecisionID(t *testing.T) {
	v := NewVerifier()
	proof := ZKGovernanceProof{Algorithm: Algorithm, ProofID: "p1"}
	result, _ := v.Verify(VerifyRequest{Proof: proof})
	if result.Valid {
		t.Fatal("expected invalid for missing decision_id")
	}
}

func TestStress_VerifyMissingPolicyCommitment(t *testing.T) {
	v := NewVerifier()
	proof := ZKGovernanceProof{Algorithm: Algorithm, ProofID: "p1", DecisionID: "d1"}
	result, _ := v.Verify(VerifyRequest{Proof: proof})
	if result.Valid {
		t.Fatal("expected invalid for missing policy_commitment")
	}
}

func TestStress_VerifyMissingInputCommitment(t *testing.T) {
	v := NewVerifier()
	proof := ZKGovernanceProof{Algorithm: Algorithm, ProofID: "p1", DecisionID: "d1", PolicyCommitment: "pc"}
	result, _ := v.Verify(VerifyRequest{Proof: proof})
	if result.Valid {
		t.Fatal("expected invalid for missing input_commitment")
	}
}

func TestStress_VerifyMissingVerdictCommitment(t *testing.T) {
	v := NewVerifier()
	proof := ZKGovernanceProof{Algorithm: Algorithm, ProofID: "p1", DecisionID: "d1", PolicyCommitment: "pc", InputCommitment: "ic"}
	result, _ := v.Verify(VerifyRequest{Proof: proof})
	if result.Valid {
		t.Fatal("expected invalid for missing verdict_commitment")
	}
}

func TestStress_VerifyMissingChallenge(t *testing.T) {
	v := NewVerifier()
	proof := ZKGovernanceProof{Algorithm: Algorithm, ProofID: "p1", DecisionID: "d1", PolicyCommitment: "pc", InputCommitment: "ic", VerdictCommitment: "vc"}
	result, _ := v.Verify(VerifyRequest{Proof: proof})
	if result.Valid {
		t.Fatal("expected invalid for missing challenge")
	}
}

func TestStress_VerifyMissingResponse(t *testing.T) {
	v := NewVerifier()
	proof := ZKGovernanceProof{Algorithm: Algorithm, ProofID: "p1", DecisionID: "d1", PolicyCommitment: "pc", InputCommitment: "ic", VerdictCommitment: "vc", Challenge: "ch"}
	result, _ := v.Verify(VerifyRequest{Proof: proof})
	if result.Valid {
		t.Fatal("expected invalid for missing response")
	}
}

func TestStress_VerifyMissingResponseCommitment(t *testing.T) {
	v := NewVerifier()
	proof := ZKGovernanceProof{Algorithm: Algorithm, ProofID: "p1", DecisionID: "d1", PolicyCommitment: "pc", InputCommitment: "ic", VerdictCommitment: "vc", Challenge: "ch", Response: "rs"}
	result, _ := v.Verify(VerifyRequest{Proof: proof})
	if result.Valid {
		t.Fatal("expected invalid for missing response_commitment")
	}
}

func TestStress_VerifyTamperedChallenge(t *testing.T) {
	prover := NewProver("n1")
	proof, _ := prover.Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", Verdict: "ALLOW", DecisionHash: "dh"})
	proof.Challenge = "tampered"
	v := NewVerifier()
	result, _ := v.Verify(VerifyRequest{Proof: *proof})
	if result.Valid {
		t.Fatal("expected invalid for tampered challenge")
	}
}

func TestStress_VerifyTamperedContentHash(t *testing.T) {
	prover := NewProver("n1")
	proof, _ := prover.Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", Verdict: "ALLOW", DecisionHash: "dh"})
	proof.ContentHash = "tampered"
	v := NewVerifier()
	result, _ := v.Verify(VerifyRequest{Proof: *proof})
	if result.Valid {
		t.Fatal("expected invalid for tampered content hash")
	}
}

func TestStress_VerifyTamperedResponseCommitment(t *testing.T) {
	prover := NewProver("n1")
	proof, _ := prover.Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", Verdict: "ALLOW", DecisionHash: "dh"})
	proof.ResponseCommitment = "tampered"
	v := NewVerifier()
	result, _ := v.Verify(VerifyRequest{Proof: *proof})
	if result.Valid {
		t.Fatal("expected invalid for tampered response commitment")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Additional prover tests (proofmarket tests in proofmarket/stress_test.go)
// ────────────────────────────────────────────────────────────────────────

func TestStress_ProveWithNilInputData(t *testing.T) {
	prover := NewProver("n1")
	proof, err := prover.Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", Verdict: "v", DecisionHash: "dh", InputData: nil})
	if err != nil || proof == nil {
		t.Fatalf("nil input data should be handled: err=%v", err)
	}
}

func TestStress_ProveWithEmptyInputData(t *testing.T) {
	prover := NewProver("n1")
	proof, err := prover.Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", Verdict: "v", DecisionHash: "dh", InputData: map[string]interface{}{}})
	if err != nil || proof == nil {
		t.Fatalf("empty input data should succeed: err=%v", err)
	}
}

func TestStress_ProveWithComplexInputData(t *testing.T) {
	prover := NewProver("n1")
	proof, err := prover.Prove(ProofRequest{
		DecisionID: "d", PolicyHash: "h", Verdict: "DENY", DecisionHash: "dh",
		InputData: map[string]interface{}{"nested": map[string]interface{}{"deep": "value"}, "list": []interface{}{"a", "b"}},
	})
	if err != nil || proof == nil {
		t.Fatal("complex input data failed")
	}
}

func TestStress_ProofDENYVerdict(t *testing.T) {
	prover := NewProver("n1")
	verifier := NewVerifier()
	proof, _ := prover.Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", Verdict: "DENY", DecisionHash: "dh"})
	result, _ := verifier.Verify(VerifyRequest{Proof: *proof})
	if !result.Valid {
		t.Fatalf("DENY proof invalid: %s", result.Reason)
	}
}

func TestStress_ProofESCALATEVerdict(t *testing.T) {
	prover := NewProver("n1")
	verifier := NewVerifier()
	proof, _ := prover.Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", Verdict: "ESCALATE", DecisionHash: "dh"})
	result, _ := verifier.Verify(VerifyRequest{Proof: *proof})
	if !result.Valid {
		t.Fatalf("ESCALATE proof invalid: %s", result.Reason)
	}
}

// ────────────────────────────────────────────────────────────────────────
// Anchor 50 proofs
// ────────────────────────────────────────────────────────────────────────

func TestStress_Anchor50Proofs(t *testing.T) {
	prover := NewProver("n1")
	anchor := NewAnchor(WithSubmitFunc(func(hash string, data []byte) (string, error) {
		return fmt.Sprintf("entry-%s", hash[:8]), nil
	}))
	for i := 0; i < 50; i++ {
		proof, _ := prover.Prove(ProofRequest{
			DecisionID: fmt.Sprintf("d-%d", i), PolicyHash: "h", Verdict: "ALLOW", DecisionHash: "dh",
		})
		entryID, err := anchor.AnchorToLog(proof)
		if err != nil || entryID == "" {
			t.Fatalf("anchor %d failed: err=%v", i, err)
		}
		if proof.RekorEntryID == "" {
			t.Fatalf("proof %d: RekorEntryID not set", i)
		}
	}
}

func TestStress_AnchorNilProof(t *testing.T) {
	anchor := NewAnchor(WithSubmitFunc(func(h string, d []byte) (string, error) { return "e", nil }))
	_, err := anchor.AnchorToLog(nil)
	if err == nil {
		t.Fatal("expected error for nil proof")
	}
}

func TestStress_AnchorNoLogConfigured(t *testing.T) {
	anchor := NewAnchor()
	proof := &ZKGovernanceProof{ContentHash: "abc"}
	_, err := anchor.AnchorToLog(proof)
	if err == nil {
		t.Fatal("expected error for no log configured")
	}
}

func TestStress_AnchorSubmitFailure(t *testing.T) {
	anchor := NewAnchor(WithSubmitFunc(func(h string, d []byte) (string, error) {
		return "", fmt.Errorf("log down")
	}))
	prover := NewProver("n1")
	proof, _ := prover.Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", Verdict: "ALLOW", DecisionHash: "dh"})
	_, err := anchor.AnchorToLog(proof)
	if err == nil {
		t.Fatal("expected error for submit failure")
	}
}

// ────────────────────────────────────────────────────────────────────────
// ResponseCommitment verified for each
// ────────────────────────────────────────────────────────────────────────

func TestStress_ResponseCommitmentBindsAllCommitments(t *testing.T) {
	prover := NewProver("n1")
	proof, _ := prover.Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", Verdict: "ALLOW", DecisionHash: "dh"})
	expected := computeResponseCommitment(proof.Response, proof.PolicyCommitment, proof.InputCommitment, proof.VerdictCommitment)
	if proof.ResponseCommitment != expected {
		t.Fatal("response commitment does not match recomputed value")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Every validation error
// ────────────────────────────────────────────────────────────────────────

func TestStress_ProveEmptyDecisionID(t *testing.T) {
	_, err := NewProver("n").Prove(ProofRequest{PolicyHash: "h", Verdict: "v", DecisionHash: "d"})
	if err == nil {
		t.Fatal("expected error for empty decision_id")
	}
}

func TestStress_ProveEmptyPolicyHash(t *testing.T) {
	_, err := NewProver("n").Prove(ProofRequest{DecisionID: "d", Verdict: "v", DecisionHash: "dh"})
	if err == nil {
		t.Fatal("expected error for empty policy_hash")
	}
}

func TestStress_ProveEmptyVerdict(t *testing.T) {
	_, err := NewProver("n").Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", DecisionHash: "dh"})
	if err == nil {
		t.Fatal("expected error for empty verdict")
	}
}

func TestStress_ProveEmptyDecisionHash(t *testing.T) {
	_, err := NewProver("n").Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", Verdict: "v"})
	if err == nil {
		t.Fatal("expected error for empty decision_hash")
	}
}

func TestStress_AlgorithmConstant(t *testing.T) {
	if Algorithm != "helm-zkgov-v1" {
		t.Fatalf("unexpected algorithm: %s", Algorithm)
	}
}

func TestStress_ProverWithClock(t *testing.T) {
	fixed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	prover := NewProver("n1").WithClock(func() time.Time { return fixed })
	proof, _ := prover.Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", Verdict: "v", DecisionHash: "dh"})
	if !proof.Timestamp.Equal(fixed) {
		t.Fatal("clock override not applied")
	}
}

func TestStress_VerifierWithClock(t *testing.T) {
	fixed := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	v := NewVerifier().WithClock(func() time.Time { return fixed })
	prover := NewProver("n1")
	proof, _ := prover.Prove(ProofRequest{DecisionID: "d", PolicyHash: "h", Verdict: "v", DecisionHash: "dh"})
	result, _ := v.Verify(VerifyRequest{Proof: *proof})
	if !result.Valid {
		t.Fatalf("valid proof rejected: %s", result.Reason)
	}
	if !result.VerifiedAt.Equal(fixed) {
		t.Fatal("verifier clock not applied")
	}
}

func TestStress_ConcurrentAnchor(t *testing.T) {
	prover := NewProver("n1")
	var mu sync.Mutex
	var entries []string
	anchor := NewAnchor(WithSubmitFunc(func(hash string, data []byte) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		id := fmt.Sprintf("e-%d", len(entries))
		entries = append(entries, id)
		return id, nil
	}))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			proof, _ := prover.Prove(ProofRequest{DecisionID: fmt.Sprintf("d-%d", n), PolicyHash: "h", Verdict: "v", DecisionHash: "dh"})
			_, _ = anchor.AnchorToLog(proof)
		}(i)
	}
	wg.Wait()
	mu.Lock()
	if len(entries) != 20 {
		t.Fatalf("expected 20 anchor entries, got %d", len(entries))
	}
	mu.Unlock()
}

func TestStress_CanonicalizeNilInput(t *testing.T) {
	data, err := canonicalizeInputData(nil)
	if err != nil || string(data) != "{}" {
		t.Fatalf("nil input should produce {}: got %s err=%v", string(data), err)
	}
}
