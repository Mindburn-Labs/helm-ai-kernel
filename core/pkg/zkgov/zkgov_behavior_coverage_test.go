package zkgov

import (
	"strings"
	"testing"
)

func compTestRequest() ProofRequest {
	return ProofRequest{
		DecisionID:   "dec-001",
		PolicyHash:   "abc123",
		InputData:    map[string]interface{}{"action": "read"},
		Verdict:      "ALLOW",
		DecisionHash: "hash-xyz",
	}
}

func TestProverProveReturnsValidProof(t *testing.T) {
	p := NewProver("node-1").WithClock(fixedClock)
	proof, err := p.Prove(compTestRequest())
	if err != nil || proof == nil {
		t.Fatalf("expected valid proof, got err=%v", err)
	}
	if proof.Algorithm != Algorithm {
		t.Fatalf("algorithm=%s, want %s", proof.Algorithm, Algorithm)
	}
}

func TestProverProofIDHasPrefix(t *testing.T) {
	p := NewProver("node-1").WithClock(fixedClock)
	proof, _ := p.Prove(compTestRequest())
	if !strings.HasPrefix(proof.ProofID, "zkp-") {
		t.Fatalf("proof ID should start with zkp-, got %s", proof.ProofID)
	}
}

func TestProverSetsProverID(t *testing.T) {
	p := NewProver("guardian-42").WithClock(fixedClock)
	proof, _ := p.Prove(compTestRequest())
	if proof.ProverID != "guardian-42" {
		t.Fatalf("proverID=%s, want guardian-42", proof.ProverID)
	}
}

func TestProverRequiresDecisionID(t *testing.T) {
	p := NewProver("n")
	req := compTestRequest()
	req.DecisionID = ""
	_, err := p.Prove(req)
	if err == nil || !strings.Contains(err.Error(), "decision_id") {
		t.Fatalf("expected decision_id error, got %v", err)
	}
}

func TestProverRequiresPolicyHash(t *testing.T) {
	p := NewProver("n")
	req := compTestRequest()
	req.PolicyHash = ""
	_, err := p.Prove(req)
	if err == nil || !strings.Contains(err.Error(), "policy_hash") {
		t.Fatalf("expected policy_hash error, got %v", err)
	}
}

func TestProverRequiresVerdict(t *testing.T) {
	p := NewProver("n")
	req := compTestRequest()
	req.Verdict = ""
	_, err := p.Prove(req)
	if err == nil || !strings.Contains(err.Error(), "verdict") {
		t.Fatalf("expected verdict error, got %v", err)
	}
}

func TestProverRequiresDecisionHash(t *testing.T) {
	p := NewProver("n")
	req := compTestRequest()
	req.DecisionHash = ""
	_, err := p.Prove(req)
	if err == nil || !strings.Contains(err.Error(), "decision_hash") {
		t.Fatalf("expected decision_hash error, got %v", err)
	}
}

func TestProverNilInputDataProducesProof(t *testing.T) {
	p := NewProver("n").WithClock(fixedClock)
	req := compTestRequest()
	req.InputData = nil
	proof, err := p.Prove(req)
	if err != nil || proof == nil {
		t.Fatalf("nil input_data should still produce proof, err=%v", err)
	}
}

func TestProverContentHashNonEmpty(t *testing.T) {
	p := NewProver("n").WithClock(fixedClock)
	proof, _ := p.Prove(compTestRequest())
	if proof.ContentHash == "" {
		t.Fatal("content hash should be populated")
	}
}

func TestProverTwoDifferentProofsHaveDifferentIDs(t *testing.T) {
	p := NewProver("n").WithClock(fixedClock)
	p1, _ := p.Prove(compTestRequest())
	p2, _ := p.Prove(compTestRequest())
	if p1.ProofID == p2.ProofID {
		t.Fatal("two proofs should have different IDs")
	}
}

func TestVerifierAcceptsValidProof(t *testing.T) {
	p := NewProver("n").WithClock(fixedClock)
	proof, _ := p.Prove(compTestRequest())
	v := NewVerifier().WithClock(fixedClock)
	result, err := v.Verify(VerifyRequest{Proof: *proof})
	if err != nil || !result.Valid {
		t.Fatalf("valid proof should verify, err=%v, reason=%s", err, result.Reason)
	}
}

func TestVerifierRejectsTamperedChallenge(t *testing.T) {
	p := NewProver("n").WithClock(fixedClock)
	proof, _ := p.Prove(compTestRequest())
	proof.Challenge = "0000000000000000000000000000000000000000000000000000000000000000"
	v := NewVerifier().WithClock(fixedClock)
	result, _ := v.Verify(VerifyRequest{Proof: *proof})
	if result.Valid {
		t.Fatal("tampered challenge should be rejected")
	}
}

func TestVerifierRejectsTamperedContentHash(t *testing.T) {
	p := NewProver("n").WithClock(fixedClock)
	proof, _ := p.Prove(compTestRequest())
	proof.ContentHash = "deadbeef"
	v := NewVerifier().WithClock(fixedClock)
	result, _ := v.Verify(VerifyRequest{Proof: *proof})
	if result.Valid {
		t.Fatal("tampered content hash should be rejected")
	}
}

func TestVerifierRejectsWrongAlgorithm(t *testing.T) {
	p := NewProver("n").WithClock(fixedClock)
	proof, _ := p.Prove(compTestRequest())
	proof.Algorithm = "fake-algo"
	v := NewVerifier().WithClock(fixedClock)
	result, _ := v.Verify(VerifyRequest{Proof: *proof})
	if result.Valid {
		t.Fatal("wrong algorithm should be rejected")
	}
}

func TestVerifierRejectsMissingProofID(t *testing.T) {
	v := NewVerifier()
	result, _ := v.Verify(VerifyRequest{Proof: ZKGovernanceProof{Algorithm: Algorithm}})
	if result.Valid {
		t.Fatal("missing proof_id should fail validation")
	}
}

func TestVerifierRejectsTamperedResponseCommitment(t *testing.T) {
	p := NewProver("n").WithClock(fixedClock)
	proof, _ := p.Prove(compTestRequest())
	proof.ResponseCommitment = "aaaa"
	v := NewVerifier().WithClock(fixedClock)
	result, _ := v.Verify(VerifyRequest{Proof: *proof})
	if result.Valid {
		t.Fatal("tampered response commitment should be rejected")
	}
}

func TestAnchorToLogSuccess(t *testing.T) {
	var gotHash string
	a := NewAnchor(WithSubmitFunc(func(hash string, _ []byte) (string, error) {
		gotHash = hash
		return "entry-123", nil
	}))
	p := NewProver("n").WithClock(fixedClock)
	proof, _ := p.Prove(compTestRequest())
	id, err := a.AnchorToLog(proof)
	if err != nil || id != "entry-123" || gotHash != proof.ContentHash {
		t.Fatalf("anchor failed: id=%s, err=%v", id, err)
	}
	if proof.RekorEntryID != "entry-123" {
		t.Fatalf("rekor entry not set on proof")
	}
}

func TestAnchorToLogNoSinkConfigured(t *testing.T) {
	a := NewAnchor()
	p := NewProver("n").WithClock(fixedClock)
	proof, _ := p.Prove(compTestRequest())
	_, err := a.AnchorToLog(proof)
	if err == nil || !strings.Contains(err.Error(), "no transparency log") {
		t.Fatalf("expected no-log error, got %v", err)
	}
}

func TestAnchorToLogNilProof(t *testing.T) {
	a := NewAnchor()
	_, err := a.AnchorToLog(nil)
	if err == nil {
		t.Fatal("expected error for nil proof")
	}
}

func TestProverTimestampUsesInjectedClock(t *testing.T) {
	p := NewProver("n").WithClock(fixedClock)
	proof, _ := p.Prove(compTestRequest())
	if !proof.Timestamp.Equal(fixedTime) {
		t.Fatalf("expected fixed time, got %v", proof.Timestamp)
	}
}

func TestProverDifferentInputsProduceDifferentCommitments(t *testing.T) {
	p := NewProver("n").WithClock(fixedClock)
	r1 := compTestRequest()
	r1.InputData = map[string]interface{}{"a": "1"}
	r2 := compTestRequest()
	r2.InputData = map[string]interface{}{"b": "2"}
	p1, _ := p.Prove(r1)
	p2, _ := p.Prove(r2)
	if p1.InputCommitment == p2.InputCommitment {
		t.Fatal("different inputs should produce different input commitments")
	}
}

func TestVerifierResultProofIDMatches(t *testing.T) {
	p := NewProver("n").WithClock(fixedClock)
	proof, _ := p.Prove(compTestRequest())
	v := NewVerifier().WithClock(fixedClock)
	result, _ := v.Verify(VerifyRequest{Proof: *proof})
	if result.ProofID != proof.ProofID {
		t.Fatalf("result proof ID mismatch: %s != %s", result.ProofID, proof.ProofID)
	}
}
