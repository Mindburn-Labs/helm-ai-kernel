package zkgov

import (
	"fmt"
	"time"
)

// Verifier checks ZK governance proofs without seeing the policy or data.
//
// Verification is purely mathematical: the verifier recomputes the Fiat-Shamir
// challenge from the public commitments and timestamp, then checks that the
// prover's response is consistent. At no point does the verifier need to see
// the policy, the input data, or the salt.
type Verifier struct {
	clock func() time.Time
}

// NewVerifier creates a new ZK governance proof verifier.
func NewVerifier() *Verifier {
	return &Verifier{
		clock: time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (v *Verifier) WithClock(clock func() time.Time) *Verifier {
	v.clock = clock
	return v
}

// Verify checks that a ZK proof is internally consistent.
// It does NOT need the policy or input data — only the commitments.
//
// Verification steps:
//  1. Check algorithm identifier.
//  2. Validate required fields are present.
//  3. Recompute challenge from commitments + timestamp (Fiat-Shamir).
//  4. Verify that the recomputed challenge matches the proof's challenge.
//  5. Verify content hash integrity (tamper evidence).
//  6. If expected_verdict is provided, note that we cannot verify the verdict
//     from commitments alone (that would break zero-knowledge). The commitment
//     binds the verdict, but revealing which verdict requires the salt.
func (v *Verifier) Verify(req VerifyRequest) (*VerifyResult, error) {
	proof := req.Proof
	now := v.clock()

	// Step 1: Algorithm check.
	if proof.Algorithm != Algorithm {
		return &VerifyResult{
			Valid:      false,
			Reason:     fmt.Sprintf("unsupported algorithm: %q (expected %q)", proof.Algorithm, Algorithm),
			ProofID:    proof.ProofID,
			VerifiedAt: now,
		}, nil
	}

	// Step 2: Required fields.
	if err := validateProofFields(&proof); err != nil {
		return &VerifyResult{
			Valid:      false,
			Reason:     err.Error(),
			ProofID:    proof.ProofID,
			VerifiedAt: now,
		}, nil
	}

	// Step 3: Recompute challenge from commitments + timestamp.
	recomputedChallenge := computeChallenge(
		proof.PolicyCommitment,
		proof.InputCommitment,
		proof.VerdictCommitment,
		proof.Timestamp,
	)

	// Step 4: Challenge must match.
	if proof.Challenge != recomputedChallenge {
		return &VerifyResult{
			Valid:      false,
			Reason:     "challenge verification failed: recomputed challenge does not match",
			ProofID:    proof.ProofID,
			VerifiedAt: now,
		}, nil
	}

	// Step 5: Response commitment verification.
	// This is the critical soundness check: the response must be bound to the
	// commitments. Without this, any response value would pass verification.
	expectedResponseCommitment := computeResponseCommitment(
		proof.Response, proof.PolicyCommitment, proof.InputCommitment, proof.VerdictCommitment,
	)
	if proof.ResponseCommitment != expectedResponseCommitment {
		return &VerifyResult{
			Valid:      false,
			Reason:     "response commitment mismatch: response is not bound to commitments",
			ProofID:    proof.ProofID,
			VerifiedAt: now,
		}, nil
	}

	// Step 6: Content hash integrity.
	expectedContentHash, err := computeContentHash(&proof)
	if err != nil {
		return nil, fmt.Errorf("zkgov: content hash computation failed: %w", err)
	}
	if proof.ContentHash != expectedContentHash {
		return &VerifyResult{
			Valid:      false,
			Reason:     "content hash mismatch: proof structure has been tampered with",
			ProofID:    proof.ProofID,
			VerifiedAt: now,
		}, nil
	}

	// Note on expected verdict: We intentionally do NOT verify the expected verdict
	// against the verdict commitment here. The verdict is bound inside the commitment
	// (VerdictCommitment = H(verdict || decision_hash || salt)), but extracting which
	// verdict it encodes requires the salt — which the verifier does not have.
	// This is by design: the zero-knowledge property means the verifier cannot learn
	// the verdict from the proof alone. If the caller needs to verify a specific verdict,
	// they must use a separate disclosure mechanism (e.g., selective disclosure).

	return &VerifyResult{
		Valid:      true,
		ProofID:    proof.ProofID,
		VerifiedAt: now,
	}, nil
}

// validateProofFields checks that all required proof fields are present.
func validateProofFields(proof *ZKGovernanceProof) error {
	if proof.ProofID == "" {
		return fmt.Errorf("missing proof_id")
	}
	if proof.DecisionID == "" {
		return fmt.Errorf("missing decision_id")
	}
	if proof.PolicyCommitment == "" {
		return fmt.Errorf("missing policy_commitment")
	}
	if proof.InputCommitment == "" {
		return fmt.Errorf("missing input_commitment")
	}
	if proof.VerdictCommitment == "" {
		return fmt.Errorf("missing verdict_commitment")
	}
	if proof.Challenge == "" {
		return fmt.Errorf("missing challenge")
	}
	if proof.Response == "" {
		return fmt.Errorf("missing response")
	}
	if proof.ResponseCommitment == "" {
		return fmt.Errorf("missing response_commitment")
	}
	if proof.ProverID == "" {
		return fmt.Errorf("missing prover_id")
	}
	if proof.ContentHash == "" {
		return fmt.Errorf("missing content_hash")
	}
	if proof.Timestamp.IsZero() {
		return fmt.Errorf("missing timestamp")
	}
	return nil
}
