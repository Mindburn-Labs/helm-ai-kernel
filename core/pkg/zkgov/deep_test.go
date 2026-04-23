package zkgov

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var deepFixedTime = time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)

func deepClock() time.Time { return deepFixedTime }

func deepReq(id int) ProofRequest {
	return ProofRequest{
		DecisionID:   fmt.Sprintf("deep-dec-%d", id),
		PolicyHash:   fmt.Sprintf("deep-policy-%d", id),
		InputData:    map[string]interface{}{"action": "read", "id": id},
		Verdict:      "ALLOW",
		DecisionHash: fmt.Sprintf("deep-hash-%d", id),
	}
}

func TestDeep_DeepProver100DecisionsAllValid(t *testing.T) {
	p := NewProver("node-1").WithClock(deepClock)
	for i := 0; i < 100; i++ {
		proof, err := p.Prove(deepReq(i))
		if err != nil {
			t.Fatalf("decision %d: %v", i, err)
		}
		if proof.ProverID != "node-1" {
			t.Errorf("decision %d: proverID=%q", i, proof.ProverID)
		}
	}
}

func TestDeep_DeepProver100UniqueProofIDs(t *testing.T) {
	p := NewProver("node-2").WithClock(deepClock)
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		proof, err := p.Prove(deepReq(i))
		if err != nil {
			t.Fatalf("decision %d: %v", i, err)
		}
		if seen[proof.ProofID] {
			t.Fatalf("duplicate proof ID: %s", proof.ProofID)
		}
		seen[proof.ProofID] = true
	}
}

func TestDeep_DeepVerifierRejectsTamperedPolicyCommitment(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	proof.PolicyCommitment = "0000000000000000000000000000000000000000000000000000000000000000"
	v := NewVerifier().WithClock(deepClock)
	res, err := v.Verify(VerifyRequest{Proof: *proof})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("should reject tampered PolicyCommitment")
	}
}

func TestDeep_DeepVerifierRejectsTamperedInputCommitment(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	proof.InputCommitment = "aaaa" + proof.InputCommitment[4:]
	v := NewVerifier().WithClock(deepClock)
	res, _ := v.Verify(VerifyRequest{Proof: *proof})
	if res.Valid {
		t.Fatal("should reject tampered InputCommitment")
	}
}

func TestDeep_DeepVerifierRejectsTamperedVerdictCommitment(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	proof.VerdictCommitment = strings.Repeat("b", 64)
	v := NewVerifier().WithClock(deepClock)
	res, _ := v.Verify(VerifyRequest{Proof: *proof})
	if res.Valid {
		t.Fatal("should reject tampered VerdictCommitment")
	}
}

func TestDeep_DeepVerifierRejectsTamperedChallenge(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	proof.Challenge = strings.Repeat("c", 64)
	v := NewVerifier().WithClock(deepClock)
	res, _ := v.Verify(VerifyRequest{Proof: *proof})
	if res.Valid {
		t.Fatal("should reject tampered Challenge")
	}
}

func TestDeep_DeepVerifierRejectsTamperedResponse(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	proof.Response = strings.Repeat("d", 64)
	v := NewVerifier().WithClock(deepClock)
	res, _ := v.Verify(VerifyRequest{Proof: *proof})
	if res.Valid {
		t.Fatal("should reject tampered Response")
	}
}

func TestDeep_DeepProofUniquenessWithSameRequest(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	req := deepReq(42)
	proofs := make(map[string]bool, 10)
	for i := 0; i < 10; i++ {
		proof, err := p.Prove(req)
		if err != nil {
			t.Fatal(err)
		}
		if proofs[proof.Response] {
			t.Fatal("identical response from same request — salt reuse detected")
		}
		proofs[proof.Response] = true
	}
}

func TestDeep_DeepProofSaltCausesDistinctCommitments(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	req := deepReq(7)
	a, _ := p.Prove(req)
	b, _ := p.Prove(req)
	if a.PolicyCommitment == b.PolicyCommitment {
		t.Fatal("same PolicyCommitment — random salt not working")
	}
}

func TestDeep_DeepResponseCommitmentBindsResponse(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	expected := computeResponseCommitment(proof.Response, proof.PolicyCommitment, proof.InputCommitment, proof.VerdictCommitment)
	if proof.ResponseCommitment != expected {
		t.Fatalf("ResponseCommitment mismatch: got %s, want %s", proof.ResponseCommitment, expected)
	}
}

func TestDeep_DeepResponseCommitmentRejectsMismatch(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	proof.Response = strings.Repeat("ff", 32)
	proof.ContentHash, _ = computeContentHash(proof)
	v := NewVerifier().WithClock(deepClock)
	res, _ := v.Verify(VerifyRequest{Proof: *proof})
	if res.Valid {
		t.Fatal("response commitment check should catch mismatched response")
	}
}

func TestDeep_DeepVerifierAcceptsValid(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	v := NewVerifier().WithClock(deepClock)
	res, err := v.Verify(VerifyRequest{Proof: *proof})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("valid proof rejected: %s", res.Reason)
	}
}

func TestDeep_DeepVerifierRejectsUnknownAlgorithm(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	proof.Algorithm = "not-a-real-algo"
	v := NewVerifier().WithClock(deepClock)
	res, _ := v.Verify(VerifyRequest{Proof: *proof})
	if res.Valid {
		t.Fatal("should reject unknown algorithm")
	}
}

func TestDeep_DeepVerifierRejectsEmptyProofID(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	proof.ProofID = ""
	v := NewVerifier().WithClock(deepClock)
	res, _ := v.Verify(VerifyRequest{Proof: *proof})
	if res.Valid {
		t.Fatal("should reject missing ProofID")
	}
}

func TestDeep_DeepVerifierRejectsEmptyContentHash(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	proof.ContentHash = ""
	v := NewVerifier().WithClock(deepClock)
	res, _ := v.Verify(VerifyRequest{Proof: *proof})
	if res.Valid {
		t.Fatal("should reject missing ContentHash")
	}
}

func TestDeep_DeepProverEmptyDecisionID(t *testing.T) {
	p := NewProver("n")
	req := deepReq(1)
	req.DecisionID = ""
	_, err := p.Prove(req)
	if err == nil {
		t.Fatal("should reject empty DecisionID")
	}
}

func TestDeep_DeepProverEmptyPolicyHash(t *testing.T) {
	p := NewProver("n")
	req := deepReq(1)
	req.PolicyHash = ""
	_, err := p.Prove(req)
	if err == nil {
		t.Fatal("should reject empty PolicyHash")
	}
}

func TestDeep_DeepProverEmptyVerdict(t *testing.T) {
	p := NewProver("n")
	req := deepReq(1)
	req.Verdict = ""
	_, err := p.Prove(req)
	if err == nil {
		t.Fatal("should reject empty Verdict")
	}
}

func TestDeep_DeepProverEmptyDecisionHash(t *testing.T) {
	p := NewProver("n")
	req := deepReq(1)
	req.DecisionHash = ""
	_, err := p.Prove(req)
	if err == nil {
		t.Fatal("should reject empty DecisionHash")
	}
}

func TestDeep_DeepProofCommitmentsDeterministicWithSameSalt(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	a, _ := p.proveWithSalt(deepReq(1), salt)
	b, _ := p.proveWithSalt(deepReq(1), salt)
	if a.PolicyCommitment != b.PolicyCommitment || a.Challenge != b.Challenge || a.Response != b.Response {
		t.Fatal("same salt + same request should yield same commitments and response")
	}
}

func TestDeep_DeepProofTimestampFromClock(t *testing.T) {
	ts := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	p := NewProver("n").WithClock(func() time.Time { return ts })
	proof, _ := p.Prove(deepReq(1))
	if !proof.Timestamp.Equal(ts) {
		t.Fatalf("timestamp mismatch: got %v, want %v", proof.Timestamp, ts)
	}
}

func TestDeep_DeepProofAlgorithmField(t *testing.T) {
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	if proof.Algorithm != Algorithm {
		t.Fatalf("algorithm=%q, want %q", proof.Algorithm, Algorithm)
	}
}

func TestDeep_DeepAnchorConcurrentSubmissions(t *testing.T) {
	var mu sync.Mutex
	entries := make(map[string]bool)

	submit := func(proofHash string, _ []byte) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		id := "entry-" + proofHash[:8]
		entries[id] = true
		return id, nil
	}

	anchor := NewAnchor(WithSubmitFunc(submit))
	p := NewProver("n").WithClock(deepClock)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			proof, _ := p.Prove(deepReq(idx))
			_, err := anchor.AnchorToLog(proof)
			if err != nil {
				t.Errorf("anchor %d: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()

	mu.Lock()
	if len(entries) != 20 {
		t.Fatalf("expected 20 unique anchor entries, got %d", len(entries))
	}
	mu.Unlock()
}

func TestDeep_DeepAnchorSetsRekorEntryID(t *testing.T) {
	submit := func(_ string, _ []byte) (string, error) { return "rekor-deep-123", nil }
	anchor := NewAnchor(WithSubmitFunc(submit))
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	id, _ := anchor.AnchorToLog(proof)
	if id != "rekor-deep-123" || proof.RekorEntryID != "rekor-deep-123" {
		t.Fatalf("RekorEntryID not set correctly: %q", proof.RekorEntryID)
	}
}

func TestDeep_DeepAnchorNilProof(t *testing.T) {
	anchor := NewAnchor(WithSubmitFunc(func(string, []byte) (string, error) { return "", nil }))
	_, err := anchor.AnchorToLog(nil)
	if err == nil {
		t.Fatal("should reject nil proof")
	}
}

func TestDeep_DeepAnchorNoSubmitFunc(t *testing.T) {
	anchor := NewAnchor()
	p := NewProver("n").WithClock(deepClock)
	proof, _ := p.Prove(deepReq(1))
	_, err := anchor.AnchorToLog(proof)
	if err == nil || !strings.Contains(err.Error(), "no transparency log") {
		t.Fatalf("expected no-log error, got: %v", err)
	}
}
