// Package a2a — trust_propagation.go
// Transitive trust score propagation across vouch chains.
//
// Trust propagates through vouch relationships with exponential decay per hop.
// Given agents A → B → C, A's propagated trust in C is:
//
//	max(directScore(C), max over paths(score * decay^hops))
//
// Invariants:
//   - Cycle detection via visited-set prevents infinite loops.
//   - MaxHops bounds the BFS depth (default 3).
//   - Agents below MinScore are not propagated through (default 400 = NEUTRAL).
//   - Direct score always participates as a candidate (never decayed).

package a2a

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// ── Configuration ─────────────────────────────────────────────────

// PropagationConfig controls trust propagation parameters.
type PropagationConfig struct {
	DecayPerHop float64 // fraction retained per hop (default 0.7 = 30% decay)
	MaxHops     int     // maximum chain depth (default 3)
	MinScore    int     // minimum score to propagate through (default 400 = NEUTRAL)
}

// ── Trust Path ────────────────────────────────────────────────────

// TrustPath represents one chain of vouching relationships between two agents.
type TrustPath struct {
	Hops        []string `json:"hops"`         // agent IDs in path
	HopScores   []int    `json:"hop_scores"`   // trust score at each hop
	FinalScore  int      `json:"final_score"`  // decayed end score
	DecayFactor float64  `json:"decay_factor"` // cumulative decay applied
}

// ── Propagator ────────────────────────────────────────────────────

// TrustPropagator computes transitive trust scores through vouch chains.
type TrustPropagator struct {
	scorer  *trust.BehavioralTrustScorer
	voucher *VouchingEngine
	config  PropagationConfig
}

// bfsState tracks the BFS frontier.
type bfsState struct {
	agent  string
	path   []string
	scores []int
	depth  int
}
