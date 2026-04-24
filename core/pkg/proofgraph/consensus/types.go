// Package consensus implements Byzantine-fault-tolerant consensus for ProofGraph
// node batches. It uses a HotStuff-inspired two-phase voting protocol
// (PRE_VOTE -> PRE_COMMIT -> COMMIT) to agree on which batches of content-addressed
// ProofGraph nodes should be committed. Since ProofGraph nodes are append-only and
// content-addressed, consensus reduces to agreeing on batch membership rather than
// mutable state transitions.
package consensus

import "time"

// ConsensusState tracks the BFT consensus protocol state.
type ConsensusState string

const (
	StateIdle      ConsensusState = "IDLE"
	StatePropose   ConsensusState = "PROPOSE"
	StatePreVote   ConsensusState = "PRE_VOTE"
	StatePreCommit ConsensusState = "PRE_COMMIT"
	StateCommit    ConsensusState = "COMMIT"
)

// Proposal is a batch of ProofGraph nodes proposed for consensus.
type Proposal struct {
	ProposalID string    `json:"proposal_id"`
	ProposerID string    `json:"proposer_id"`
	Round      uint64    `json:"round"`
	NodeHashes []string  `json:"node_hashes"` // nodes being proposed
	MerkleRoot string    `json:"merkle_root"` // root of proposed nodes
	Signature  string    `json:"signature"`
	Timestamp  time.Time `json:"timestamp"`
}

// Vote represents a validator's vote on a proposal.
type Vote struct {
	VoteID      string         `json:"vote_id"`
	ValidatorID string         `json:"validator_id"`
	ProposalID  string         `json:"proposal_id"`
	Round       uint64         `json:"round"`
	Phase       ConsensusState `json:"phase"` // PRE_VOTE or PRE_COMMIT
	Accept      bool           `json:"accept"`
	Signature   string         `json:"signature"`
	Timestamp   time.Time      `json:"timestamp"`
}

// CommitCertificate proves that a quorum agreed on a proposal.
type CommitCertificate struct {
	ProposalID  string `json:"proposal_id"`
	Round       uint64 `json:"round"`
	MerkleRoot  string `json:"merkle_root"`
	Votes       []Vote `json:"votes"`
	QuorumSize  int    `json:"quorum_size"`
	ContentHash string `json:"content_hash"`
}

// ValidatorSet defines the set of consensus participants.
type ValidatorSet struct {
	Validators map[string]ValidatorInfo `json:"validators"` // validatorID -> info
	Quorum     int                      `json:"quorum"`     // 2f+1 where f = max Byzantine
}

// ValidatorInfo describes a single consensus participant.
type ValidatorInfo struct {
	ValidatorID string `json:"validator_id"`
	PublicKey   string `json:"public_key"`
	Weight      int    `json:"weight"` // voting power
}
