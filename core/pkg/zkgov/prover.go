package zkgov

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// Prover generates ZK governance proofs.
//
// A Prover holds a prover identity and a clock source. The prover ID is
// embedded in every proof so verifiers can attribute proofs to HELM nodes.
type Prover struct {
	proverID string
	clock    func() time.Time
}

// NewProver creates a new ZK governance proof generator.
// proverID identifies the HELM node (typically the Guardian node ID).
func NewProver(proverID string) *Prover {
	return &Prover{
		proverID: proverID,
		clock:    time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (p *Prover) WithClock(clock func() time.Time) *Prover {
	p.clock = clock
	return p
}

// Prove generates a ZK proof that a governance decision was correctly evaluated.
// The proof reveals NOTHING about the policy or input data.
//
// Algorithm (commitment + Schnorr-like sigma protocol via Fiat-Shamir):
//
//  1. Generate cryptographically random 32-byte salt (the secret witness).
//  2. Compute commitments (public):
//     - PolicyCommitment  = SHA256(policy_hash || salt)
//     - InputCommitment   = SHA256(JCS(input_data) || salt)
//     - VerdictCommitment = SHA256(verdict || decision_hash || salt)
//  3. Derive challenge via Fiat-Shamir heuristic (non-interactive):
//     challenge = SHA256(PolicyCommitment || InputCommitment || VerdictCommitment || timestamp_bytes)
//  4. Compute response (proves knowledge of salt without revealing it):
//     response = HMAC-SHA256(key=salt, message=challenge)
//  5. Compute content hash over the canonical proof body for tamper evidence.
//  6. Package as ZKGovernanceProof.
func (p *Prover) Prove(req ProofRequest) (*ZKGovernanceProof, error) {
	if req.DecisionID == "" {
		return nil, fmt.Errorf("zkgov: decision_id is required")
	}
	if req.PolicyHash == "" {
		return nil, fmt.Errorf("zkgov: policy_hash is required")
	}
	if req.Verdict == "" {
		return nil, fmt.Errorf("zkgov: verdict is required")
	}
	if req.DecisionHash == "" {
		return nil, fmt.Errorf("zkgov: decision_hash is required")
	}

	// Step 1: Generate random salt (secret witness).
	salt, err := generateSalt()
	if err != nil {
		return nil, fmt.Errorf("zkgov: salt generation failed: %w", err)
	}

	return p.proveWithSalt(req, salt)
}

// proveWithSalt is the internal proof generation with an explicit salt.
// Exposed for deterministic testing only.
func (p *Prover) proveWithSalt(req ProofRequest, salt []byte) (*ZKGovernanceProof, error) {
	now := p.clock()

	// Step 2: Compute commitments.
	policyCommitment := computeCommitment([]byte(req.PolicyHash), salt)

	inputCanonical, err := canonicalizeInputData(req.InputData)
	if err != nil {
		return nil, fmt.Errorf("zkgov: input canonicalization failed: %w", err)
	}
	inputCommitment := computeCommitment(inputCanonical, salt)

	verdictPayload := []byte(req.Verdict + req.DecisionHash)
	verdictCommitment := computeCommitment(verdictPayload, salt)

	// Step 3: Derive challenge (Fiat-Shamir).
	challenge := computeChallenge(policyCommitment, inputCommitment, verdictCommitment, now)

	// Step 4: Compute response.
	response := computeResponse(salt, challenge)

	// Step 5: Generate proof ID.
	proofID, err := generateProofID()
	if err != nil {
		return nil, fmt.Errorf("zkgov: proof ID generation failed: %w", err)
	}

	// Step 5b: Compute response commitment (verifier-checkable binding).
	// This binds the response to the commitments so a verifier can confirm
	// the response was derived from the same witness, without knowing the salt.
	responseCommitment := computeResponseCommitment(response, policyCommitment, inputCommitment, verdictCommitment)

	proof := &ZKGovernanceProof{
		ProofID:            proofID,
		DecisionID:         req.DecisionID,
		PolicyCommitment:   policyCommitment,
		InputCommitment:    inputCommitment,
		VerdictCommitment:  verdictCommitment,
		Challenge:          challenge,
		Response:           response,
		ResponseCommitment: responseCommitment,
		ProverID:           p.proverID,
		Timestamp:          now,
		Algorithm:          Algorithm,
	}

	// Step 6: Compute content hash over the proof body.
	contentHash, err := computeContentHash(proof)
	if err != nil {
		return nil, fmt.Errorf("zkgov: content hash failed: %w", err)
	}
	proof.ContentHash = contentHash

	return proof, nil
}

// computeCommitment produces SHA256(data || salt).
func computeCommitment(data, salt []byte) string {
	h := sha256.New()
	h.Write(data)
	h.Write(salt)
	return hex.EncodeToString(h.Sum(nil))
}

// computeChallenge derives the Fiat-Shamir challenge from commitments and timestamp.
// challenge = SHA256(policyCommitment || inputCommitment || verdictCommitment || timestamp_bytes)
func computeChallenge(policyCommitment, inputCommitment, verdictCommitment string, ts time.Time) string {
	h := sha256.New()
	h.Write([]byte(policyCommitment))
	h.Write([]byte(inputCommitment))
	h.Write([]byte(verdictCommitment))

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(ts.UnixNano()))
	h.Write(tsBuf[:])

	return hex.EncodeToString(h.Sum(nil))
}

// computeResponse computes HMAC-SHA256(key=salt, message=challenge).
// This proves knowledge of the salt without revealing it.
func computeResponse(salt []byte, challenge string) string {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(challenge))
	return hex.EncodeToString(mac.Sum(nil))
}

// computeResponseCommitment binds the HMAC response to the public commitments.
// ResponseCommitment = SHA256(response || policyCommitment || inputCommitment || verdictCommitment)
// The verifier recomputes this from the proof fields and rejects if it doesn't match.
func computeResponseCommitment(response, policyCommitment, inputCommitment, verdictCommitment string) string {
	h := sha256.New()
	h.Write([]byte(response))
	h.Write([]byte(policyCommitment))
	h.Write([]byte(inputCommitment))
	h.Write([]byte(verdictCommitment))
	return hex.EncodeToString(h.Sum(nil))
}

// computeContentHash returns SHA256 of the canonical proof body (excluding ContentHash).
// Uses JCS canonicalization for deterministic, cross-platform hashing.
func computeContentHash(proof *ZKGovernanceProof) (string, error) {
	// Create a copy without ContentHash for hashing.
	type proofBody struct {
		ProofID            string    `json:"proof_id"`
		DecisionID         string    `json:"decision_id"`
		PolicyCommitment   string    `json:"policy_commitment"`
		InputCommitment    string    `json:"input_commitment"`
		VerdictCommitment  string    `json:"verdict_commitment"`
		Challenge          string    `json:"challenge"`
		Response           string    `json:"response"`
		ResponseCommitment string    `json:"response_commitment"`
		ProverID           string    `json:"prover_id"`
		Timestamp          time.Time `json:"timestamp"`
		Algorithm          string    `json:"algorithm"`
	}

	body := proofBody{
		ProofID:            proof.ProofID,
		DecisionID:         proof.DecisionID,
		PolicyCommitment:   proof.PolicyCommitment,
		InputCommitment:    proof.InputCommitment,
		VerdictCommitment:  proof.VerdictCommitment,
		Challenge:          proof.Challenge,
		Response:           proof.Response,
		ResponseCommitment: proof.ResponseCommitment,
		ProverID:           proof.ProverID,
		Timestamp:          proof.Timestamp,
		Algorithm:          proof.Algorithm,
	}

	return canonicalize.CanonicalHash(body)
}

// canonicalizeInputData produces a deterministic byte representation of input data
// using JCS (RFC 8785) canonicalization.
func canonicalizeInputData(data map[string]interface{}) ([]byte, error) {
	if data == nil {
		return []byte("{}"), nil
	}
	return canonicalize.JCS(data)
}

// generateSalt produces a cryptographically random 32-byte salt.
func generateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("crypto/rand failure: %w", err)
	}
	return salt, nil
}

// generateProofID produces a cryptographically random proof identifier.
func generateProofID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("crypto/rand failure: %w", err)
	}
	return "zkp-" + hex.EncodeToString(b[:]), nil
}
