package gdpr17

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// CircuitVersion is the identifier recorded in proof public signals.
// Every circuit revision MUST bump this and maintain a test-vector table
// against the prior version so regression can be detected mechanically.
const CircuitVersion = "gdpr17-v1-scaffold"

// ErrNotImplemented is returned by every function in this package until the
// real gnark circuit lands in Q3 2026.
var ErrNotImplemented = errors.New(
	"gdpr17: scaffold only — real circuit lands Q3 2026 after external review; " +
		"see docs/decisions/0003-zk-cryptographic-reviewer.md",
)

// Prover builds zero-knowledge proofs that a session's trace satisfies GDPR
// Article 17 with respect to a subject and an erasure event.
type Prover interface {
	// Prove produces a ComplianceProof against private inputs.
	// Returns ErrNotImplemented until the real circuit lands.
	Prove(ctx context.Context, priv PrivateInputs, pub PublicInputs) (Proof, error)
}

// Verifier validates ComplianceProofs against public signals.
type Verifier interface {
	// Verify validates a proof's soundness. Returns nil if valid; a descriptive
	// error otherwise. Returns ErrNotImplemented until the real circuit lands.
	Verify(ctx context.Context, proof Proof, pub PublicInputs) error
}

// PrivateInputs are held by the prover and NEVER appear in the proof.
type PrivateInputs struct {
	// Trace is the session's full ProofGraph node sequence.
	// Canonicalized form (JSON-LD or similar) enforces deterministic hashing
	// inside the circuit.
	Trace []byte

	// SubjectID is the raw personal identifier whose erasure is being proved.
	SubjectID []byte

	// Secrets are per-record nonces used to re-derive personal-data hashes
	// within the circuit.
	Secrets [][]byte
}

// PublicInputs accompany the proof and are visible to the verifier.
// The verifier's acceptance is a claim about these public signals: that the
// private inputs exist such that the circuit's invariant holds.
type PublicInputs struct {
	// PolicyHash is SHA-256 of the active P1 policy bundle at ErasureTime.
	PolicyHash [32]byte

	// ErasureTime is the timestamp of the erasure event (UTC).
	ErasureTime time.Time

	// SubjectCommit is a Pedersen commitment to SubjectID (private).
	// Committing rather than revealing allows multiple proofs over different
	// sessions to be cross-referenced without leaking the identifier.
	SubjectCommit [32]byte

	// CircuitVersion pins the circuit that produced the proof. Verifier checks
	// this matches the CircuitVersion constant — any mismatch is rejected.
	CircuitVersion string
}

// Proof is the zero-knowledge proof artifact.
// Opaque to consumers; structure depends on the underlying SNARK scheme
// (Groth16 vs PLONK vs Halo2) chosen during real implementation.
type Proof struct {
	// Bytes is the serialized proof.
	Bytes []byte

	// Scheme records which SNARK system produced the proof
	// ("groth16-bn254" | "plonk-bn254" | "halo2-bls12-381").
	Scheme string

	// ProverVersion is the gnark (or other) library version used.
	ProverVersion string

	// ProvedAt is when the proof was generated.
	ProvedAt time.Time
}

// ScaffoldProver returns a Prover that panics / errors on every call.
// Intended use: downstream code (CLI, dashboard) types against the Prover
// interface today, and swaps the implementation to a real gnark-backed
// prover when available.
func ScaffoldProver() Prover {
	return &scaffoldProver{}
}

// ScaffoldVerifier returns a Verifier that always errors with
// ErrNotImplemented. Same rationale as ScaffoldProver.
func ScaffoldVerifier() Verifier {
	return &scaffoldVerifier{}
}

type scaffoldProver struct{}

func (s *scaffoldProver) Prove(ctx context.Context, priv PrivateInputs, pub PublicInputs) (Proof, error) {
	return Proof{}, fmt.Errorf("gdpr17.Prove: %w", ErrNotImplemented)
}

type scaffoldVerifier struct{}

func (s *scaffoldVerifier) Verify(ctx context.Context, proof Proof, pub PublicInputs) error {
	return fmt.Errorf("gdpr17.Verify: %w", ErrNotImplemented)
}
