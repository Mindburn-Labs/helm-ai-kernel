package consensus

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

// QuorumChecker validates quorum requirements for BFT consensus.
type QuorumChecker struct {
	validators *ValidatorSet
}

// NewQuorumChecker creates a QuorumChecker for the given validator set.
func NewQuorumChecker(validators *ValidatorSet) *QuorumChecker {
	return &QuorumChecker{validators: validators}
}

// ComputeQuorum returns the minimum number of validators needed for consensus.
// For BFT: quorum = 2f+1 where n = 3f+1 (n validators, f max Byzantine).
// f = floor((n-1)/3), quorum = n - f.
func (q *QuorumChecker) ComputeQuorum() int {
	n := len(q.validators.Validators)
	if n == 0 {
		return 0
	}
	f := (n - 1) / 3
	return n - f
}

// IsQuorumMet checks if the given votes form a valid quorum.
// Only votes that Accept are counted toward quorum.
func (q *QuorumChecker) IsQuorumMet(votes []*Vote) bool {
	acceptCount := 0
	seen := make(map[string]bool)
	for _, v := range votes {
		if !v.Accept {
			continue
		}
		// Each validator may only contribute one vote.
		if seen[v.ValidatorID] {
			continue
		}
		// Only count votes from known validators.
		if _, ok := q.validators.Validators[v.ValidatorID]; !ok {
			continue
		}
		seen[v.ValidatorID] = true
		acceptCount++
	}
	return acceptCount >= q.ComputeQuorum()
}

// VerifyVotes checks that all votes are from valid validators with correct signatures.
func (q *QuorumChecker) VerifyVotes(votes []*Vote) error {
	for _, v := range votes {
		info, ok := q.validators.Validators[v.ValidatorID]
		if !ok {
			return fmt.Errorf("consensus: unknown validator %s", v.ValidatorID)
		}

		sigData := canonicalVoteBytes(v)
		valid, err := crypto.Verify(info.PublicKey, v.Signature, sigData)
		if err != nil {
			return fmt.Errorf("consensus: signature verification error for validator %s: %w", v.ValidatorID, err)
		}
		if !valid {
			return fmt.Errorf("consensus: invalid signature from validator %s", v.ValidatorID)
		}
	}
	return nil
}
