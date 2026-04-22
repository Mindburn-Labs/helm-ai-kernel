package consensus

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

func TestQuorumChecker_ComputeQuorum(t *testing.T) {
	tests := []struct {
		name       string
		validators int
		wantQuorum int
	}{
		{name: "1 validator", validators: 1, wantQuorum: 1},
		{name: "2 validators", validators: 2, wantQuorum: 2},
		{name: "3 validators", validators: 3, wantQuorum: 3},
		{name: "4 validators (f=1)", validators: 4, wantQuorum: 3},
		{name: "5 validators", validators: 5, wantQuorum: 4},
		{name: "6 validators", validators: 6, wantQuorum: 5},
		{name: "7 validators (f=2)", validators: 7, wantQuorum: 5},
		{name: "10 validators (f=3)", validators: 10, wantQuorum: 7},
		{name: "13 validators (f=4)", validators: 13, wantQuorum: 9},
		{name: "0 validators", validators: 0, wantQuorum: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := makeValidatorSet(t, tt.validators)
			checker := NewQuorumChecker(vs)
			got := checker.ComputeQuorum()
			if got != tt.wantQuorum {
				t.Errorf("ComputeQuorum() = %d, want %d", got, tt.wantQuorum)
			}
		})
	}
}

func TestQuorumChecker_IsQuorumMet(t *testing.T) {
	// 4 validators, quorum = 3.
	vs, signers := testCluster(t, 4)
	checker := NewQuorumChecker(vs)

	// 3 accepting votes -> quorum met.
	votes := make([]*Vote, 3)
	for i := range 3 {
		id := "validator-" + itoa(i)
		v := &Vote{
			VoteID:      "vote-" + itoa(i),
			ValidatorID: id,
			ProposalID:  "proposal-test",
			Round:       1,
			Phase:       StatePreVote,
			Accept:      true,
		}
		sigData := canonicalVoteBytes(v)
		sig, err := signers[id].Sign(sigData)
		if err != nil {
			t.Fatalf("signing vote: %v", err)
		}
		v.Signature = sig
		votes[i] = v
	}

	if !checker.IsQuorumMet(votes) {
		t.Error("expected quorum to be met with 3 of 4 validators")
	}
}

func TestQuorumChecker_BelowQuorum(t *testing.T) {
	// 4 validators, quorum = 3. Only 2 votes -> below quorum.
	vs, signers := testCluster(t, 4)
	checker := NewQuorumChecker(vs)

	votes := make([]*Vote, 2)
	for i := range 2 {
		id := "validator-" + itoa(i)
		v := &Vote{
			VoteID:      "vote-" + itoa(i),
			ValidatorID: id,
			ProposalID:  "proposal-test",
			Round:       1,
			Phase:       StatePreVote,
			Accept:      true,
		}
		sigData := canonicalVoteBytes(v)
		sig, err := signers[id].Sign(sigData)
		if err != nil {
			t.Fatalf("signing vote: %v", err)
		}
		v.Signature = sig
		votes[i] = v
	}

	if checker.IsQuorumMet(votes) {
		t.Error("quorum should not be met with 2 of 4 validators (need 3)")
	}
}

func TestQuorumChecker_RejectVotesNotAccepted(t *testing.T) {
	// 4 validators, quorum = 3. 3 votes but one has Accept=false.
	vs, signers := testCluster(t, 4)
	checker := NewQuorumChecker(vs)

	votes := make([]*Vote, 3)
	for i := range 3 {
		id := "validator-" + itoa(i)
		v := &Vote{
			VoteID:      "vote-" + itoa(i),
			ValidatorID: id,
			ProposalID:  "proposal-test",
			Round:       1,
			Phase:       StatePreVote,
			Accept:      i != 2, // Third vote rejects.
		}
		sigData := canonicalVoteBytes(v)
		sig, err := signers[id].Sign(sigData)
		if err != nil {
			t.Fatalf("signing vote: %v", err)
		}
		v.Signature = sig
		votes[i] = v
	}

	if checker.IsQuorumMet(votes) {
		t.Error("quorum should not be met when one of three votes rejects (need 3 accepts)")
	}
}

func TestQuorumChecker_DuplicateVotesIgnored(t *testing.T) {
	// 4 validators, quorum = 3. Same validator votes 3 times -> still only 1 unique.
	vs, signers := testCluster(t, 4)
	checker := NewQuorumChecker(vs)

	id := "validator-0"
	votes := make([]*Vote, 3)
	for i := range 3 {
		v := &Vote{
			VoteID:      "vote-dup-" + itoa(i),
			ValidatorID: id,
			ProposalID:  "proposal-test",
			Round:       1,
			Phase:       StatePreVote,
			Accept:      true,
		}
		sigData := canonicalVoteBytes(v)
		sig, err := signers[id].Sign(sigData)
		if err != nil {
			t.Fatalf("signing vote: %v", err)
		}
		v.Signature = sig
		votes[i] = v
	}

	if checker.IsQuorumMet(votes) {
		t.Error("duplicate votes from the same validator should not count as quorum")
	}
}

func TestQuorumChecker_VerifyVotes(t *testing.T) {
	vs, signers := testCluster(t, 4)
	checker := NewQuorumChecker(vs)

	// Valid votes.
	validVotes := make([]*Vote, 2)
	for i := range 2 {
		id := "validator-" + itoa(i)
		v := &Vote{
			VoteID:      "vote-verify-" + itoa(i),
			ValidatorID: id,
			ProposalID:  "proposal-verify",
			Round:       1,
			Phase:       StatePreVote,
			Accept:      true,
		}
		sigData := canonicalVoteBytes(v)
		sig, err := signers[id].Sign(sigData)
		if err != nil {
			t.Fatalf("signing vote: %v", err)
		}
		v.Signature = sig
		validVotes[i] = v
	}

	if err := checker.VerifyVotes(validVotes); err != nil {
		t.Errorf("VerifyVotes with valid votes: %v", err)
	}

	// Vote from unknown validator.
	unknownVote := &Vote{
		VoteID:      "vote-unknown",
		ValidatorID: "validator-unknown",
		ProposalID:  "proposal-verify",
		Round:       1,
		Phase:       StatePreVote,
		Accept:      true,
		Signature:   "anything",
	}
	if err := checker.VerifyVotes([]*Vote{unknownVote}); err == nil {
		t.Error("expected error for vote from unknown validator")
	}

	// Vote with wrong signature.
	wrongSigVote := &Vote{
		VoteID:      "vote-wrong-sig",
		ValidatorID: "validator-0",
		ProposalID:  "proposal-verify",
		Round:       1,
		Phase:       StatePreVote,
		Accept:      true,
	}
	// Sign with validator-1's key but claim to be validator-0.
	sigData := canonicalVoteBytes(wrongSigVote)
	sig, err := signers["validator-1"].Sign(sigData)
	if err != nil {
		t.Fatalf("signing with wrong key: %v", err)
	}
	wrongSigVote.Signature = sig

	if err := checker.VerifyVotes([]*Vote{wrongSigVote}); err == nil {
		t.Error("expected error for vote signed with wrong key")
	}
}

func TestQuorumChecker_UnknownValidatorVotesIgnored(t *testing.T) {
	// 4 validators. 2 legit + 1 unknown = should not meet quorum.
	vs, signers := testCluster(t, 4)
	checker := NewQuorumChecker(vs)

	outsider, err := crypto.NewEd25519Signer("outsider")
	if err != nil {
		t.Fatalf("creating outsider: %v", err)
	}

	votes := make([]*Vote, 3)
	for i := range 2 {
		id := "validator-" + itoa(i)
		v := &Vote{
			VoteID:      "vote-" + itoa(i),
			ValidatorID: id,
			ProposalID:  "proposal-test",
			Round:       1,
			Phase:       StatePreVote,
			Accept:      true,
		}
		sigData := canonicalVoteBytes(v)
		sig, err := signers[id].Sign(sigData)
		if err != nil {
			t.Fatalf("signing vote: %v", err)
		}
		v.Signature = sig
		votes[i] = v
	}

	// Outsider vote.
	outsiderVote := &Vote{
		VoteID:      "vote-outsider",
		ValidatorID: "outsider",
		ProposalID:  "proposal-test",
		Round:       1,
		Phase:       StatePreVote,
		Accept:      true,
	}
	sigData := canonicalVoteBytes(outsiderVote)
	sig, err := outsider.Sign(sigData)
	if err != nil {
		t.Fatalf("signing outsider vote: %v", err)
	}
	outsiderVote.Signature = sig
	votes[2] = outsiderVote

	if checker.IsQuorumMet(votes) {
		t.Error("outsider votes should not count toward quorum")
	}
}

// makeValidatorSet creates a ValidatorSet with n dummy validators (no real keys).
func makeValidatorSet(t *testing.T, n int) *ValidatorSet {
	t.Helper()
	validators := make(map[string]ValidatorInfo, n)
	for i := range n {
		id := "v" + itoa(i)
		validators[id] = ValidatorInfo{
			ValidatorID: id,
			PublicKey:   "pubkey-" + itoa(i),
			Weight:      1,
		}
	}
	return &ValidatorSet{Validators: validators}
}
