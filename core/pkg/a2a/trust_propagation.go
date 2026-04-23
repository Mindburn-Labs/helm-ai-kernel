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
	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
)

// ── Configuration ─────────────────────────────────────────────────

// PropagationConfig controls trust propagation parameters.
type PropagationConfig struct {
	DecayPerHop float64 // fraction retained per hop (default 0.7 = 30% decay)
	MaxHops     int     // maximum chain depth (default 3)
	MinScore    int     // minimum score to propagate through (default 400 = NEUTRAL)
}

// DefaultPropagationConfig returns production defaults.
func DefaultPropagationConfig() PropagationConfig {
	return PropagationConfig{
		DecayPerHop: 0.7,
		MaxHops:     3,
		MinScore:    400,
	}
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

// NewTrustPropagator creates a trust propagator.
// If no config is provided, DefaultPropagationConfig() is used.
func NewTrustPropagator(
	scorer *trust.BehavioralTrustScorer,
	voucher *VouchingEngine,
	config ...PropagationConfig,
) *TrustPropagator {
	cfg := DefaultPropagationConfig()
	if len(config) > 0 {
		cfg = config[0]
	}
	return &TrustPropagator{
		scorer:  scorer,
		voucher: voucher,
		config:  cfg,
	}
}

// PropagatedScore computes the effective trust score that fromAgent has for toAgent.
//
// Algorithm:
//  1. Get direct trust score of toAgent from the scorer.
//  2. BFS from fromAgent through vouch chains to toAgent (max depth = MaxHops).
//  3. For each path, compute decayed score: endpointScore * decay^hops.
//  4. Return max of: direct score, max propagated score.
//
// Returns the effective score, all discovered trust paths, and any error.
func (p *TrustPropagator) PropagatedScore(fromAgent, toAgent string) (int, []TrustPath, error) {
	// Direct score is always a baseline.
	directScore := p.scorer.GetScore(toAgent).Score

	if fromAgent == toAgent {
		return directScore, nil, nil
	}

	// BFS to find all vouch paths from fromAgent to toAgent.
	paths := p.findPaths(fromAgent, toAgent)

	bestScore := directScore
	for i := range paths {
		if paths[i].FinalScore > bestScore {
			bestScore = paths[i].FinalScore
		}
	}

	return bestScore, paths, nil
}

// bfsState tracks the BFS frontier.
type bfsState struct {
	agent  string
	path   []string
	scores []int
	depth  int
}

// findPaths performs BFS from source to target through active vouch chains.
func (p *TrustPropagator) findPaths(source, target string) []TrustPath {
	var paths []TrustPath

	// BFS frontier.
	queue := []bfsState{{
		agent:  source,
		path:   []string{source},
		scores: []int{p.scorer.GetScore(source).Score},
		depth:  0,
	}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.depth >= p.config.MaxHops {
			continue
		}

		// Find all agents that current.agent vouches for.
		vouches := p.voucher.ActiveVouches(current.agent)
		for _, vouch := range vouches {
			vouchee := vouch.Vouchee

			// Cycle detection: skip if already in path.
			if p.inPath(current.path, vouchee) {
				continue
			}

			// MinScore filter: skip agents below threshold.
			voucheeScore := p.scorer.GetScore(vouchee).Score
			if voucheeScore < p.config.MinScore {
				continue
			}

			newPath := make([]string, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = vouchee

			newScores := make([]int, len(current.scores)+1)
			copy(newScores, current.scores)
			newScores[len(current.scores)] = voucheeScore

			if vouchee == target {
				// Found a path to target. Compute decayed score.
				hops := current.depth + 1
				decayFactor := 1.0
				for h := 0; h < hops; h++ {
					decayFactor *= p.config.DecayPerHop
				}
				finalScore := int(float64(voucheeScore) * decayFactor)

				paths = append(paths, TrustPath{
					Hops:        newPath,
					HopScores:   newScores,
					FinalScore:  finalScore,
					DecayFactor: decayFactor,
				})
			} else {
				// Continue BFS.
				queue = append(queue, bfsState{
					agent:  vouchee,
					path:   newPath,
					scores: newScores,
					depth:  current.depth + 1,
				})
			}
		}
	}

	return paths
}

// inPath checks whether an agent is already in the visited path (cycle detection).
func (p *TrustPropagator) inPath(path []string, agent string) bool {
	for _, a := range path {
		if a == agent {
			return true
		}
	}
	return false
}
