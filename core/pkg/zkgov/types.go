// Package zkgov implements Zero-Knowledge Governance Proofs for HELM.
//
// ZK governance proofs allow HELM to prove that a governance decision was
// correctly evaluated WITHOUT revealing the policy rules or the governed data.
// This uses a commitment-based Sigma-protocol style proof:
//
//  1. Commit: Hash the policy + input data into commitments (hidden)
//  2. Prove: Generate a proof that the Guardian evaluation was correct given the commitments
//  3. Verify: Third party can verify the proof using only the commitments (not the policy or data)
//
// The proof is non-interactive (Fiat-Shamir heuristic), binding (tied to a specific
// decision), and sound (cannot be forged without knowledge of the secret witness).
//
// All serialization uses JCS (RFC 8785) canonicalization for cross-platform determinism.
package zkgov

import "time"

// Algorithm is the proof algorithm identifier.
const Algorithm = "helm-zkgov-v1"

// ZKGovernanceProof proves that a governance decision was correctly evaluated
// without revealing the policy rules or the governed data.
//
// The commitments are public (verifier sees these). The policy, input data,
// and salt remain secret to the prover.
type ZKGovernanceProof struct {
	// ProofID is a unique identifier for this proof.
	ProofID string `json:"proof_id"`

	// DecisionID links this proof to the Guardian DecisionRecord it covers.
	DecisionID string `json:"decision_id"`

	// PolicyCommitment is H(policy_hash || salt). Hides the policy.
	PolicyCommitment string `json:"policy_commitment"`

	// InputCommitment is H(canonical(input_data) || salt). Hides the input.
	InputCommitment string `json:"input_commitment"`

	// VerdictCommitment is H(verdict || decision_hash || salt). Binds the verdict.
	VerdictCommitment string `json:"verdict_commitment"`

	// Challenge is the Fiat-Shamir challenge derived from the commitments.
	// challenge = SHA256(PolicyCommitment || InputCommitment || VerdictCommitment || timestamp_bytes)
	Challenge string `json:"challenge"`

	// Response is the prover's response to the challenge.
	// response = HMAC-SHA256(salt, challenge)
	// This proves knowledge of the salt without revealing it.
	Response string `json:"response"`

	// ResponseCommitment binds the response to the commitments so the verifier
	// can check that the response was derived from the same witness as the commitments.
	// ResponseCommitment = SHA256(response || PolicyCommitment || InputCommitment || VerdictCommitment)
	// The verifier recomputes this from the proof fields and rejects if it doesn't match.
	ResponseCommitment string `json:"response_commitment"`

	// ProverID identifies the HELM node that generated this proof.
	ProverID string `json:"prover_id"`

	// Timestamp is when the proof was generated.
	Timestamp time.Time `json:"timestamp"`

	// Algorithm identifies the proof scheme. Always "helm-zkgov-v1".
	Algorithm string `json:"algorithm"`

	// ContentHash is SHA256 of the canonical proof body (excluding ContentHash itself).
	// Provides tamper evidence over the entire proof structure.
	ContentHash string `json:"content_hash"`

	// RekorEntryID is the transparency log entry ID, if the proof was anchored.
	RekorEntryID string `json:"rekor_entry_id,omitempty"`
}

// ProofRequest describes a governance decision to prove.
// The prover needs all fields to generate the proof; the verifier never sees this.
type ProofRequest struct {
	// DecisionID is the Guardian DecisionRecord ID.
	DecisionID string `json:"decision_id"`

	// PolicyHash is the content-addressed hash of the evaluated policy.
	PolicyHash string `json:"policy_hash"`

	// InputData is the governed data that was evaluated (action, resource, context, etc.).
	InputData map[string]interface{} `json:"input_data"`

	// Verdict is the Guardian verdict: "ALLOW", "DENY", or "ESCALATE".
	Verdict string `json:"verdict"`

	// DecisionHash is the SHA-256 of the canonical DecisionRecord.
	DecisionHash string `json:"decision_hash"`
}

// VerifyRequest is what a verifier receives. It contains no secrets.
type VerifyRequest struct {
	// Proof is the ZK governance proof to verify.
	Proof ZKGovernanceProof `json:"proof"`

	// ExpectedVerdict optionally specifies the verdict to verify against.
	// If non-empty, the verifier checks that the proof's verdict commitment
	// is consistent with this verdict.
	ExpectedVerdict string `json:"expected_verdict,omitempty"`
}

// VerifyResult is the output of ZK proof verification.
type VerifyResult struct {
	// Valid is true if the proof passed all verification checks.
	Valid bool `json:"valid"`

	// Reason explains why verification failed (empty on success).
	Reason string `json:"reason,omitempty"`

	// ProofID is the identifier of the verified proof.
	ProofID string `json:"proof_id"`

	// VerifiedAt is when the verification was performed.
	VerifiedAt time.Time `json:"verified_at"`
}
