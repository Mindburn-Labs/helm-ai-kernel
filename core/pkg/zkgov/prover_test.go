package zkgov

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// fixedTime is a deterministic clock for testing.
var fixedTime = time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedTime }

// sampleRequest returns a realistic ProofRequest matching Guardian decision data.
func sampleRequest() ProofRequest {
	return ProofRequest{
		DecisionID: "dec-abc123",
		PolicyHash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		InputData: map[string]interface{}{
			"action":    "tool.execute",
			"resource":  "github.create_issue",
			"principal": "agent-007",
			"context": map[string]interface{}{
				"session_id": "sess-xyz",
				"trust_tier": "standard",
			},
		},
		Verdict:      "ALLOW",
		DecisionHash: "sha256:deadbeefcafe1234567890abcdef1234567890abcdef1234567890abcdef1234",
	}
}

func TestProver_Prove(t *testing.T) {
	prover := NewProver("node-alpha").WithClock(fixedClock)

	proof, err := prover.Prove(sampleRequest())
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Verify proof structure.
	if proof.ProofID == "" {
		t.Error("ProofID must not be empty")
	}
	if !strings.HasPrefix(proof.ProofID, "zkp-") {
		t.Errorf("ProofID should start with 'zkp-', got %q", proof.ProofID)
	}
	if proof.DecisionID != "dec-abc123" {
		t.Errorf("DecisionID mismatch: got %q", proof.DecisionID)
	}
	if proof.PolicyCommitment == "" {
		t.Error("PolicyCommitment must not be empty")
	}
	if proof.InputCommitment == "" {
		t.Error("InputCommitment must not be empty")
	}
	if proof.VerdictCommitment == "" {
		t.Error("VerdictCommitment must not be empty")
	}
	if proof.Challenge == "" {
		t.Error("Challenge must not be empty")
	}
	if proof.Response == "" {
		t.Error("Response must not be empty")
	}
	if proof.ProverID != "node-alpha" {
		t.Errorf("ProverID mismatch: got %q", proof.ProverID)
	}
	if proof.Algorithm != Algorithm {
		t.Errorf("Algorithm mismatch: got %q, want %q", proof.Algorithm, Algorithm)
	}
	if proof.ContentHash == "" {
		t.Error("ContentHash must not be empty")
	}
	if !proof.Timestamp.Equal(fixedTime) {
		t.Errorf("Timestamp mismatch: got %v, want %v", proof.Timestamp, fixedTime)
	}

	// All hex-encoded fields should be valid hex and 64 chars (SHA-256 = 32 bytes).
	for _, field := range []struct {
		name  string
		value string
	}{
		{"PolicyCommitment", proof.PolicyCommitment},
		{"InputCommitment", proof.InputCommitment},
		{"VerdictCommitment", proof.VerdictCommitment},
		{"Challenge", proof.Challenge},
		{"Response", proof.Response},
		{"ContentHash", proof.ContentHash},
	} {
		if len(field.value) != 64 {
			t.Errorf("%s should be 64 hex chars (32 bytes), got %d", field.name, len(field.value))
		}
		if _, err := hex.DecodeString(field.value); err != nil {
			t.Errorf("%s is not valid hex: %v", field.name, err)
		}
	}
}

func TestProver_ProofIsBlind(t *testing.T) {
	prover := NewProver("node-alpha").WithClock(fixedClock)
	req := sampleRequest()

	proof, err := prover.Prove(req)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// The policy hash must NOT appear anywhere in the proof's public fields.
	proofStr := proof.PolicyCommitment + proof.InputCommitment + proof.VerdictCommitment +
		proof.Challenge + proof.Response + proof.ContentHash

	if strings.Contains(proofStr, req.PolicyHash) {
		t.Error("Policy hash appears in proof — zero-knowledge violated")
	}

	// The input data's raw values must not appear in commitments.
	if strings.Contains(proofStr, "agent-007") {
		t.Error("Raw input data appears in proof — zero-knowledge violated")
	}
	if strings.Contains(proofStr, "tool.execute") {
		t.Error("Raw action appears in proof — zero-knowledge violated")
	}

	// The verdict must not appear in raw form.
	if strings.Contains(proof.PolicyCommitment, "ALLOW") {
		t.Error("Verdict appears in policy commitment")
	}
}

func TestProver_DifferentInputsDifferentProofs(t *testing.T) {
	prover := NewProver("node-alpha").WithClock(fixedClock)

	req1 := sampleRequest()
	req2 := sampleRequest()
	req2.InputData["action"] = "tool.delete" // Different action.

	proof1, err := prover.Prove(req1)
	if err != nil {
		t.Fatalf("Prove(req1) failed: %v", err)
	}

	proof2, err := prover.Prove(req2)
	if err != nil {
		t.Fatalf("Prove(req2) failed: %v", err)
	}

	// Same policy, different inputs → different input commitments.
	if proof1.InputCommitment == proof2.InputCommitment {
		t.Error("Different inputs should produce different InputCommitments")
	}

	// Policy commitment should also differ because the salt is different.
	// (Each call to Prove generates a fresh salt.)
	if proof1.PolicyCommitment == proof2.PolicyCommitment {
		t.Error("Even same policy hash should produce different commitments (different salt)")
	}

	// Challenges must differ (since commitments differ).
	if proof1.Challenge == proof2.Challenge {
		t.Error("Different commitments should produce different challenges")
	}
}

func TestProver_Deterministic(t *testing.T) {
	prover := NewProver("node-alpha").WithClock(fixedClock)
	req := sampleRequest()

	// With the same salt, the proof should be deterministic (except ProofID).
	salt, err := hex.DecodeString("0102030405060708091011121314151617181920212223242526272829303132")
	if err != nil {
		t.Fatalf("salt decode failed: %v", err)
	}

	proof1, err := prover.proveWithSalt(req, salt)
	if err != nil {
		t.Fatalf("proveWithSalt(1) failed: %v", err)
	}

	proof2, err := prover.proveWithSalt(req, salt)
	if err != nil {
		t.Fatalf("proveWithSalt(2) failed: %v", err)
	}

	// All commitment fields must match.
	if proof1.PolicyCommitment != proof2.PolicyCommitment {
		t.Error("PolicyCommitment differs for same salt")
	}
	if proof1.InputCommitment != proof2.InputCommitment {
		t.Error("InputCommitment differs for same salt")
	}
	if proof1.VerdictCommitment != proof2.VerdictCommitment {
		t.Error("VerdictCommitment differs for same salt")
	}
	if proof1.Challenge != proof2.Challenge {
		t.Error("Challenge differs for same salt")
	}
	if proof1.Response != proof2.Response {
		t.Error("Response differs for same salt")
	}

	// ProofIDs should differ (they are random).
	if proof1.ProofID == proof2.ProofID {
		t.Error("ProofIDs should be unique even with same salt")
	}
}

func TestVerifier_ValidProof(t *testing.T) {
	prover := NewProver("node-alpha").WithClock(fixedClock)
	verifier := NewVerifier().WithClock(fixedClock)

	proof, err := prover.Prove(sampleRequest())
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	result, err := verifier.Verify(VerifyRequest{Proof: *proof})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !result.Valid {
		t.Errorf("Valid proof should verify: reason=%q", result.Reason)
	}
	if result.ProofID != proof.ProofID {
		t.Errorf("ProofID mismatch: got %q, want %q", result.ProofID, proof.ProofID)
	}
}

func TestVerifier_TamperedCommitment(t *testing.T) {
	prover := NewProver("node-alpha").WithClock(fixedClock)
	verifier := NewVerifier().WithClock(fixedClock)

	proof, err := prover.Prove(sampleRequest())
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Tamper with the policy commitment.
	tampered := *proof
	tampered.PolicyCommitment = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	result, err := verifier.Verify(VerifyRequest{Proof: tampered})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if result.Valid {
		t.Error("Tampered commitment should fail verification")
	}
	if !strings.Contains(result.Reason, "challenge verification failed") {
		t.Errorf("Unexpected failure reason: %q", result.Reason)
	}
}

func TestVerifier_WrongChallenge(t *testing.T) {
	prover := NewProver("node-alpha").WithClock(fixedClock)
	verifier := NewVerifier().WithClock(fixedClock)

	proof, err := prover.Prove(sampleRequest())
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Tamper with the challenge directly.
	tampered := *proof
	tampered.Challenge = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	result, err := verifier.Verify(VerifyRequest{Proof: tampered})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if result.Valid {
		t.Error("Wrong challenge should fail verification")
	}
	if !strings.Contains(result.Reason, "challenge verification failed") {
		t.Errorf("Unexpected failure reason: %q", result.Reason)
	}
}

func TestVerifier_ContentHashIntegrity(t *testing.T) {
	prover := NewProver("node-alpha").WithClock(fixedClock)
	verifier := NewVerifier().WithClock(fixedClock)

	proof, err := prover.Prove(sampleRequest())
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Tamper with the response but keep the challenge valid.
	// This tests that the response commitment check catches response tampering.
	tampered := *proof
	tampered.Response = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	// ResponseCommitment was computed from the original response, so it will mismatch.

	result, err := verifier.Verify(VerifyRequest{Proof: tampered})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if result.Valid {
		t.Error("Tampered response should fail response commitment check")
	}
	if !strings.Contains(result.Reason, "response commitment mismatch") {
		t.Errorf("Expected response commitment failure, got: %q", result.Reason)
	}
}

func TestProver_EmptyDecision(t *testing.T) {
	prover := NewProver("node-alpha").WithClock(fixedClock)

	// Empty decision ID should fail.
	_, err := prover.Prove(ProofRequest{})
	if err == nil {
		t.Fatal("Expected error for empty ProofRequest")
	}
	if !strings.Contains(err.Error(), "decision_id is required") {
		t.Errorf("Unexpected error: %v", err)
	}

	// Empty policy hash should fail.
	_, err = prover.Prove(ProofRequest{DecisionID: "dec-1"})
	if err == nil {
		t.Fatal("Expected error for empty policy hash")
	}
	if !strings.Contains(err.Error(), "policy_hash is required") {
		t.Errorf("Unexpected error: %v", err)
	}

	// Empty verdict should fail.
	_, err = prover.Prove(ProofRequest{DecisionID: "dec-1", PolicyHash: "hash"})
	if err == nil {
		t.Fatal("Expected error for empty verdict")
	}
	if !strings.Contains(err.Error(), "verdict is required") {
		t.Errorf("Unexpected error: %v", err)
	}

	// Empty decision hash should fail.
	_, err = prover.Prove(ProofRequest{DecisionID: "dec-1", PolicyHash: "hash", Verdict: "ALLOW"})
	if err == nil {
		t.Fatal("Expected error for empty decision hash")
	}
	if !strings.Contains(err.Error(), "decision_hash is required") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	// Full prove → verify cycle with realistic Guardian decision data.
	prover := NewProver("guardian-node-east-1").WithClock(fixedClock)
	verifier := NewVerifier().WithClock(fixedClock)

	req := ProofRequest{
		DecisionID: "dec-7f3a2b1c4d5e6f7890abcdef12345678",
		PolicyHash: "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		InputData: map[string]interface{}{
			"action":    "tool.execute",
			"resource":  "slack.send_message",
			"principal": "agent-marketing-bot",
			"context": map[string]interface{}{
				"session_id":      "sess-9f8e7d6c5b4a",
				"trust_tier":      "elevated",
				"budget_id":       "budget-q2-marketing",
				"credential_hash": "sha256:cafe",
				"delegation": map[string]interface{}{
					"delegator":  "user-alice",
					"scope":      "slack.*",
					"expires_at": "2026-04-13T00:00:00Z",
				},
			},
		},
		Verdict:      "ALLOW",
		DecisionHash: "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	}

	// Prove.
	proof, err := prover.Prove(req)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Verify.
	result, err := verifier.Verify(VerifyRequest{Proof: *proof})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !result.Valid {
		t.Errorf("Round-trip proof should verify: reason=%q", result.Reason)
	}

	// Verify with a DENY request to make sure different verdicts also work.
	reqDeny := req
	reqDeny.Verdict = "DENY"
	reqDeny.DecisionHash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	proofDeny, err := prover.Prove(reqDeny)
	if err != nil {
		t.Fatalf("Prove(DENY) failed: %v", err)
	}

	resultDeny, err := verifier.Verify(VerifyRequest{Proof: *proofDeny})
	if err != nil {
		t.Fatalf("Verify(DENY) returned error: %v", err)
	}
	if !resultDeny.Valid {
		t.Errorf("DENY proof should verify: reason=%q", resultDeny.Reason)
	}

	// ALLOW and DENY proofs must have different verdict commitments.
	if proof.VerdictCommitment == proofDeny.VerdictCommitment {
		t.Error("ALLOW and DENY should have different VerdictCommitments")
	}
}

func TestVerifier_UnsupportedAlgorithm(t *testing.T) {
	prover := NewProver("node-alpha").WithClock(fixedClock)
	verifier := NewVerifier().WithClock(fixedClock)

	proof, err := prover.Prove(sampleRequest())
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	tampered := *proof
	tampered.Algorithm = "unknown-v2"

	result, err := verifier.Verify(VerifyRequest{Proof: tampered})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Valid {
		t.Error("Unknown algorithm should fail verification")
	}
	if !strings.Contains(result.Reason, "unsupported algorithm") {
		t.Errorf("Unexpected failure reason: %q", result.Reason)
	}
}

func TestVerifier_MissingFields(t *testing.T) {
	verifier := NewVerifier().WithClock(fixedClock)

	// A proof with no fields should fail validation.
	result, err := verifier.Verify(VerifyRequest{Proof: ZKGovernanceProof{Algorithm: Algorithm}})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Valid {
		t.Error("Empty proof should fail verification")
	}
}

func TestProver_NilInputData(t *testing.T) {
	prover := NewProver("node-alpha").WithClock(fixedClock)
	verifier := NewVerifier().WithClock(fixedClock)

	req := ProofRequest{
		DecisionID:   "dec-nil-input",
		PolicyHash:   "sha256:empty",
		InputData:    nil, // Nil input data should produce a valid proof.
		Verdict:      "DENY",
		DecisionHash: "sha256:abc",
	}

	proof, err := prover.Prove(req)
	if err != nil {
		t.Fatalf("Prove with nil input failed: %v", err)
	}

	result, err := verifier.Verify(VerifyRequest{Proof: *proof})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !result.Valid {
		t.Errorf("Nil-input proof should verify: reason=%q", result.Reason)
	}
}

func TestAnchor_AnchorToLog(t *testing.T) {
	prover := NewProver("node-alpha").WithClock(fixedClock)

	proof, err := prover.Prove(sampleRequest())
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Test with a mock submit function.
	var capturedHash string
	var capturedBytes []byte
	anchor := NewAnchor(WithSubmitFunc(func(proofHash string, proofBytes []byte) (string, error) {
		capturedHash = proofHash
		capturedBytes = proofBytes
		return "rekor-entry-12345", nil
	}))

	entryID, err := anchor.AnchorToLog(proof)
	if err != nil {
		t.Fatalf("AnchorToLog failed: %v", err)
	}

	if entryID != "rekor-entry-12345" {
		t.Errorf("Expected entry ID 'rekor-entry-12345', got %q", entryID)
	}
	if proof.RekorEntryID != "rekor-entry-12345" {
		t.Errorf("Proof's RekorEntryID should be set, got %q", proof.RekorEntryID)
	}
	if capturedHash != proof.ContentHash {
		t.Errorf("Submit received wrong hash: got %q, want %q", capturedHash, proof.ContentHash)
	}
	if len(capturedBytes) == 0 {
		t.Error("Submit received empty proof bytes")
	}
}

func TestAnchor_NoLogConfigured(t *testing.T) {
	anchor := NewAnchor() // No submit function.
	prover := NewProver("node-alpha").WithClock(fixedClock)

	proof, err := prover.Prove(sampleRequest())
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	_, err = anchor.AnchorToLog(proof)
	if err == nil {
		t.Fatal("Expected error when no log is configured")
	}
	if !strings.Contains(err.Error(), "no transparency log configured") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestAnchor_NilProof(t *testing.T) {
	anchor := NewAnchor()

	_, err := anchor.AnchorToLog(nil)
	if err == nil {
		t.Fatal("Expected error for nil proof")
	}
	if !strings.Contains(err.Error(), "nil proof") {
		t.Errorf("Unexpected error: %v", err)
	}
}
