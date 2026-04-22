// Package kernel provides deterministic state reduction.
// Per Section 2.2 - Deterministic Reducer Specification
package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
)

// ConflictPolicy defines how conflicts are resolved.
type ConflictPolicy string

const (
	// ConflictPolicyVerifierWins - the verifier's value takes precedence
	ConflictPolicyVerifierWins ConflictPolicy = "verifier_wins"
	// ConflictPolicyFirstSuccess - first successful write wins
	ConflictPolicyFirstSuccess ConflictPolicy = "first_success"
	// ConflictPolicyQuorum - requires quorum agreement
	ConflictPolicyQuorum ConflictPolicy = "quorum"
	// ConflictPolicyLastWriteWins - last write wins (by sequence number)
	ConflictPolicyLastWriteWins ConflictPolicy = "last_write_wins"
)

// ReducerInput represents an input to the reducer.
type ReducerInput struct {
	SequenceNumber uint64                 `json:"sequence_number"`
	Key            string                 `json:"key"`
	Value          interface{}            `json:"value"`
	SortKey        string                 `json:"sort_key"` // Stable sort key for determinism
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// ReducerOutput represents the reduced state.
type ReducerOutput struct {
	StateHash string                 `json:"state_hash"`
	State     map[string]interface{} `json:"state"`
	Applied   []uint64               `json:"applied"`   // Sequence numbers applied
	Conflicts []ReducerConflict      `json:"conflicts"` // Conflicts encountered
}

// ReducerConflict records a conflict during reduction.
type ReducerConflict struct {
	Key          string      `json:"key"`
	WinnerSeq    uint64      `json:"winner_seq"`
	LoserSeq     uint64      `json:"loser_seq"`
	WinnerValue  interface{} `json:"winner_value"`
	LoserValue   interface{} `json:"loser_value"`
	ResolutionBy string      `json:"resolution_by"` // Which policy resolved it
}

// Reducer provides deterministic state reduction.
// Per Section 2.2 - Deterministic Reducer Specification
type Reducer interface {
	// Reduce applies inputs to produce deterministic output.
	Reduce(ctx context.Context, inputs []ReducerInput) (*ReducerOutput, error)

	// Policy returns the current conflict policy.
	Policy() ConflictPolicy
}

// DeterministicReducer implements the reducer with stable sorting.
type DeterministicReducer struct {
	mu       sync.Mutex
	policy   ConflictPolicy
	stateMap map[string]interface{}
}

// NewDeterministicReducer creates a new deterministic reducer.
func NewDeterministicReducer(policy ConflictPolicy) *DeterministicReducer {
	return &DeterministicReducer{
		policy:   policy,
		stateMap: make(map[string]interface{}),
	}
}

// Policy returns the current conflict policy.
func (r *DeterministicReducer) Policy() ConflictPolicy {
	return r.policy
}

// Reduce applies inputs in deterministic order.
// INVARIANT: Same inputs MUST produce same output regardless of input order.
func (r *DeterministicReducer) Reduce(ctx context.Context, inputs []ReducerInput) (*ReducerOutput, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 1. Sort inputs by stable sort key for determinism
	sortedInputs := make([]ReducerInput, len(inputs))
	copy(sortedInputs, inputs)
	sort.Slice(sortedInputs, func(i, j int) bool {
		// Primary sort: by sort_key
		if sortedInputs[i].SortKey != sortedInputs[j].SortKey {
			return sortedInputs[i].SortKey < sortedInputs[j].SortKey
		}
		// Tie-breaker: by sequence number
		return sortedInputs[i].SequenceNumber < sortedInputs[j].SequenceNumber
	})

	// 2. Apply inputs and track conflicts
	applied := make([]uint64, 0, len(sortedInputs))
	conflicts := make([]ReducerConflict, 0)
	keyOwner := make(map[string]uint64) // key -> sequence number of current owner

	for _, input := range sortedInputs {
		existingSeq, exists := keyOwner[input.Key]

		if !exists {
			// No conflict - apply directly
			r.stateMap[input.Key] = input.Value
			keyOwner[input.Key] = input.SequenceNumber
			applied = append(applied, input.SequenceNumber)
			continue
		}

		// Conflict detected - resolve based on policy
		var winner, loser uint64
		var winnerValue, loserValue interface{}

		switch r.policy {
		case ConflictPolicyFirstSuccess:
			// First write wins - existing owner keeps it
			winner = existingSeq
			loser = input.SequenceNumber
			winnerValue = r.stateMap[input.Key]
			loserValue = input.Value

		case ConflictPolicyLastWriteWins:
			// Last write wins - new input wins
			winner = input.SequenceNumber
			loser = existingSeq
			winnerValue = input.Value
			loserValue = r.stateMap[input.Key]
			r.stateMap[input.Key] = input.Value
			keyOwner[input.Key] = input.SequenceNumber
			applied = append(applied, input.SequenceNumber)

		case ConflictPolicyVerifierWins:
			// Verifier wins - treat higher sequence as verifier
			if input.SequenceNumber > existingSeq {
				winner = input.SequenceNumber
				loser = existingSeq
				winnerValue = input.Value
				loserValue = r.stateMap[input.Key]
				r.stateMap[input.Key] = input.Value
				keyOwner[input.Key] = input.SequenceNumber
				applied = append(applied, input.SequenceNumber)
			} else {
				winner = existingSeq
				loser = input.SequenceNumber
				winnerValue = r.stateMap[input.Key]
				loserValue = input.Value
			}

		default:
			// Default to first-success
			winner = existingSeq
			loser = input.SequenceNumber
			winnerValue = r.stateMap[input.Key]
			loserValue = input.Value
		}

		conflicts = append(conflicts, ReducerConflict{
			Key:          input.Key,
			WinnerSeq:    winner,
			LoserSeq:     loser,
			WinnerValue:  winnerValue,
			LoserValue:   loserValue,
			ResolutionBy: string(r.policy),
		})
	}

	// 3. Compute state hash
	stateHash, err := r.computeStateHash()
	if err != nil {
		return nil, fmt.Errorf("failed to compute state hash: %w", err)
	}

	// 4. Build output
	stateCopy := make(map[string]interface{})
	for k, v := range r.stateMap {
		stateCopy[k] = v
	}

	return &ReducerOutput{
		StateHash: stateHash,
		State:     stateCopy,
		Applied:   applied,
		Conflicts: conflicts,
	}, nil
}

// computeStateHash computes a deterministic hash of the state.
func (r *DeterministicReducer) computeStateHash() (string, error) {
	// Get sorted keys for determinism
	keys := make([]string, 0, len(r.stateMap))
	for k := range r.stateMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build canonical representation
	canonical := ""
	for _, k := range keys {
		canonical += fmt.Sprintf("%s:%v;", k, r.stateMap[k])
	}

	hash := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

// TestReducerConfluence verifies that different orderings produce the same result.
// This is used for Section 9.4 - Module Lifecycle Confluence Tests.
func TestReducerConfluence(reducer Reducer, inputs []ReducerInput, permutations int) (bool, error) {
	ctx := context.Background()

	// Get reference output from original order
	refOutput, err := reducer.Reduce(ctx, inputs)
	if err != nil {
		return false, err
	}

	// Test with shuffled orderings
	for i := 0; i < permutations; i++ {
		shuffled := make([]ReducerInput, len(inputs))
		copy(shuffled, inputs)

		// Shuffle using deterministic permutation based on iteration
		for j := len(shuffled) - 1; j > 0; j-- {
			k := (i + j) % (j + 1)
			shuffled[j], shuffled[k] = shuffled[k], shuffled[j]
		}

		testReducer := NewDeterministicReducer(reducer.Policy())
		testOutput, err := testReducer.Reduce(ctx, shuffled)
		if err != nil {
			return false, err
		}

		// Verify same state hash regardless of input order
		if testOutput.StateHash != refOutput.StateHash {
			return false, fmt.Errorf("confluence failed: ordering %d produced hash %s, expected %s",
				i, testOutput.StateHash, refOutput.StateHash)
		}
	}

	return true, nil
}
