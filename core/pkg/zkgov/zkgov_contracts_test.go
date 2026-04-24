package zkgov

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestFinal_AlgorithmConstant(t *testing.T) {
	if Algorithm != "helm-zkgov-v1" {
		t.Fatalf("want helm-zkgov-v1, got %s", Algorithm)
	}
}

func TestFinal_ZKGovernanceProofJSON(t *testing.T) {
	p := ZKGovernanceProof{ProofID: "p1", DecisionID: "d1", Algorithm: Algorithm, PolicyCommitment: "pc", InputCommitment: "ic", VerdictCommitment: "vc"}
	data, _ := json.Marshal(p)
	var p2 ZKGovernanceProof
	json.Unmarshal(data, &p2)
	if p2.ProofID != "p1" || p2.Algorithm != Algorithm {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ProofRequestJSON(t *testing.T) {
	pr := ProofRequest{DecisionID: "d1", PolicyHash: "ph", Verdict: "ALLOW"}
	data, _ := json.Marshal(pr)
	var pr2 ProofRequest
	json.Unmarshal(data, &pr2)
	if pr2.Verdict != "ALLOW" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_VerifyRequestJSON(t *testing.T) {
	vr := VerifyRequest{Proof: ZKGovernanceProof{ProofID: "p1"}, ExpectedVerdict: "DENY"}
	data, _ := json.Marshal(vr)
	var vr2 VerifyRequest
	json.Unmarshal(data, &vr2)
	if vr2.ExpectedVerdict != "DENY" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_VerifyResultJSON(t *testing.T) {
	vr := VerifyResult{Valid: true, ProofID: "p1", VerifiedAt: time.Now()}
	data, _ := json.Marshal(vr)
	var vr2 VerifyResult
	json.Unmarshal(data, &vr2)
	if !vr2.Valid {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ProverNew(t *testing.T) {
	p := NewProver("prover-1")
	if p == nil {
		t.Fatal("prover should not be nil")
	}
}

func TestFinal_ProverProve(t *testing.T) {
	p := NewProver("prover-1")
	req := ProofRequest{DecisionID: "d1", PolicyHash: "ph", InputData: map[string]interface{}{"key": "val"}, Verdict: "ALLOW", DecisionHash: "dh"}
	proof, err := p.Prove(req)
	if err != nil {
		t.Fatal(err)
	}
	if proof.ProofID == "" {
		t.Fatal("proof ID should not be empty")
	}
	if proof.Algorithm != Algorithm {
		t.Fatal("algorithm mismatch")
	}
}

func TestFinal_VerifierNew(t *testing.T) {
	v := NewVerifier()
	if v == nil {
		t.Fatal("verifier should not be nil")
	}
}

func TestFinal_ProveAndVerify(t *testing.T) {
	p := NewProver("prover-1")
	v := NewVerifier()
	req := ProofRequest{DecisionID: "d1", PolicyHash: "ph", InputData: map[string]interface{}{"k": "v"}, Verdict: "ALLOW", DecisionHash: "dh"}
	proof, _ := p.Prove(req)
	result, _ := v.Verify(VerifyRequest{Proof: *proof})
	if !result.Valid {
		t.Fatalf("proof should verify: %s", result.Reason)
	}
}

func TestFinal_ProofContentHashNonEmpty(t *testing.T) {
	p := NewProver("p1")
	req := ProofRequest{DecisionID: "d1", PolicyHash: "ph", InputData: map[string]interface{}{}, Verdict: "DENY", DecisionHash: "dh"}
	proof, _ := p.Prove(req)
	if proof.ContentHash == "" {
		t.Fatal("content hash should not be empty")
	}
}

func TestFinal_ProofDifferentDecisionIDsDifferentProofs(t *testing.T) {
	p := NewProver("p1")
	r1 := ProofRequest{DecisionID: "d1", PolicyHash: "ph", InputData: map[string]interface{}{"k": "v"}, Verdict: "ALLOW", DecisionHash: "dh"}
	r2 := ProofRequest{DecisionID: "d2", PolicyHash: "ph", InputData: map[string]interface{}{"k": "v"}, Verdict: "ALLOW", DecisionHash: "dh"}
	p1, _ := p.Prove(r1)
	p2, _ := p.Prove(r2)
	if p1.DecisionID == p2.DecisionID {
		t.Fatal("different decision IDs should produce different proof bindings")
	}
}

func TestFinal_VerifyInvalidProof(t *testing.T) {
	v := NewVerifier()
	result, _ := v.Verify(VerifyRequest{Proof: ZKGovernanceProof{ProofID: "bad", Challenge: "x", Response: "y"}})
	if result.Valid {
		t.Fatal("invalid proof should not verify")
	}
}

func TestFinal_AnchorNew(t *testing.T) {
	a := NewAnchor()
	if a == nil {
		t.Fatal("anchor should not be nil")
	}
}

func TestFinal_AnchorZeroValue(t *testing.T) {
	a := &Anchor{}
	if a == nil {
		t.Fatal("zero value should not be nil")
	}
}

func TestFinal_ConcurrentProve(t *testing.T) {
	p := NewProver("p1")
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := ProofRequest{DecisionID: "d1", PolicyHash: "ph", InputData: map[string]interface{}{}, Verdict: "ALLOW", DecisionHash: "dh"}
			p.Prove(req)
		}()
	}
	wg.Wait()
}

func TestFinal_ProofTimestamp(t *testing.T) {
	p := NewProver("p1")
	before := time.Now().Add(-time.Second)
	req := ProofRequest{DecisionID: "d1", PolicyHash: "ph", InputData: map[string]interface{}{}, Verdict: "ALLOW", DecisionHash: "dh"}
	proof, _ := p.Prove(req)
	if proof.Timestamp.Before(before) {
		t.Fatal("proof timestamp should be recent")
	}
}

func TestFinal_ProofProverID(t *testing.T) {
	p := NewProver("my-prover")
	req := ProofRequest{DecisionID: "d1", PolicyHash: "ph", InputData: map[string]interface{}{}, Verdict: "ALLOW", DecisionHash: "dh"}
	proof, _ := p.Prove(req)
	if proof.ProverID != "my-prover" {
		t.Fatal("prover ID mismatch")
	}
}

func TestFinal_ProofCommitmentsNonEmpty(t *testing.T) {
	p := NewProver("p1")
	req := ProofRequest{DecisionID: "d1", PolicyHash: "ph", InputData: map[string]interface{}{"a": 1}, Verdict: "DENY", DecisionHash: "dh"}
	proof, _ := p.Prove(req)
	if proof.PolicyCommitment == "" || proof.InputCommitment == "" || proof.VerdictCommitment == "" {
		t.Fatal("commitments should not be empty")
	}
}

func TestFinal_ProofChallengeNonEmpty(t *testing.T) {
	p := NewProver("p1")
	req := ProofRequest{DecisionID: "d1", PolicyHash: "ph", InputData: map[string]interface{}{}, Verdict: "ALLOW", DecisionHash: "dh"}
	proof, _ := p.Prove(req)
	if proof.Challenge == "" {
		t.Fatal("challenge should not be empty")
	}
}

func TestFinal_ProofResponseNonEmpty(t *testing.T) {
	p := NewProver("p1")
	req := ProofRequest{DecisionID: "d1", PolicyHash: "ph", InputData: map[string]interface{}{}, Verdict: "ALLOW", DecisionHash: "dh"}
	proof, _ := p.Prove(req)
	if proof.Response == "" {
		t.Fatal("response should not be empty")
	}
}

func TestFinal_VerifyResultTimestamp(t *testing.T) {
	p := NewProver("p1")
	v := NewVerifier()
	req := ProofRequest{DecisionID: "d1", PolicyHash: "ph", InputData: map[string]interface{}{}, Verdict: "ALLOW", DecisionHash: "dh"}
	proof, _ := p.Prove(req)
	result, _ := v.Verify(VerifyRequest{Proof: *proof})
	if result.VerifiedAt.IsZero() {
		t.Fatal("VerifiedAt should not be zero")
	}
}

func TestFinal_ZKProofDecisionIDBinding(t *testing.T) {
	p := NewProver("p1")
	req := ProofRequest{DecisionID: "decision-xyz", PolicyHash: "ph", InputData: map[string]interface{}{}, Verdict: "ALLOW", DecisionHash: "dh"}
	proof, _ := p.Prove(req)
	if proof.DecisionID != "decision-xyz" {
		t.Fatal("proof should be bound to decision ID")
	}
}
