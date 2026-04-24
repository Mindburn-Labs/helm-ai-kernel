package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

// Engine implements a HotStuff-inspired BFT consensus protocol.
// Since ProofGraph nodes are content-addressed and append-only, consensus
// decides "which batch of nodes to commit" rather than mutable state.
//
// Protocol flow:
//  1. Proposer calls Propose() to create a signed Proposal for a batch of node hashes.
//  2. Validators receive the proposal via ReceiveProposal() and return a PRE_VOTE.
//  3. Votes are collected via ReceiveVote(). Once a quorum of PRE_VOTE accepts is reached,
//     the engine transitions to PRE_COMMIT and validators produce PRE_COMMIT votes.
//  4. Once a quorum of PRE_COMMIT accepts is reached, a CommitCertificate is issued.
type Engine struct {
	nodeID       string
	validators   *ValidatorSet
	state        ConsensusState
	round        uint64
	proposals    map[string]*Proposal          // proposalID -> proposal
	votes        map[string]map[string]*Vote   // proposalID -> validatorID -> vote (per phase)
	preCommits   map[string]map[string]*Vote   // proposalID -> validatorID -> precommit vote
	certificates map[uint64]*CommitCertificate // round -> certificate
	signer       crypto.Signer
	clock        func() time.Time
	mu           sync.Mutex
}

// NewEngine creates a new BFT consensus engine.
func NewEngine(nodeID string, validators *ValidatorSet, signer crypto.Signer) *Engine {
	return &Engine{
		nodeID:       nodeID,
		validators:   validators,
		state:        StateIdle,
		round:        0,
		proposals:    make(map[string]*Proposal),
		votes:        make(map[string]map[string]*Vote),
		preCommits:   make(map[string]map[string]*Vote),
		certificates: make(map[uint64]*CommitCertificate),
		signer:       signer,
		clock:        time.Now,
	}
}

// WithClock overrides the timestamp source (useful for testing).
func (e *Engine) WithClock(clock func() time.Time) *Engine {
	e.clock = clock
	return e
}

// Propose creates a new proposal for a batch of ProofGraph nodes.
// The proposer must be a member of the validator set.
func (e *Engine) Propose(nodeHashes []string) (*Proposal, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.validators.Validators[e.nodeID]; !ok {
		return nil, fmt.Errorf("consensus: proposer %s is not a validator", e.nodeID)
	}

	e.round++
	merkleRoot := computeMerkleRoot(nodeHashes)
	proposalID := computeProposalID(e.nodeID, e.round, merkleRoot)

	p := &Proposal{
		ProposalID: proposalID,
		ProposerID: e.nodeID,
		Round:      e.round,
		NodeHashes: nodeHashes,
		MerkleRoot: merkleRoot,
		Timestamp:  e.clock(),
	}

	sigData, err := canonicalProposalBytes(p)
	if err != nil {
		return nil, fmt.Errorf("consensus: proposal canonicalization failed: %w", err)
	}
	sig, err := e.signer.Sign(sigData)
	if err != nil {
		return nil, fmt.Errorf("consensus: signing proposal failed: %w", err)
	}
	p.Signature = sig

	e.proposals[proposalID] = p
	e.state = StatePropose

	return p, nil
}

// ReceiveProposal handles an incoming proposal from another validator.
// If the proposal is valid, a PRE_VOTE Accept=true is returned.
func (e *Engine) ReceiveProposal(proposal *Proposal) (*Vote, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Verify proposer is a validator.
	proposerInfo, ok := e.validators.Validators[proposal.ProposerID]
	if !ok {
		return nil, fmt.Errorf("consensus: unknown proposer %s", proposal.ProposerID)
	}

	// Verify proposal signature.
	sigData, err := canonicalProposalBytes(proposal)
	if err != nil {
		return nil, fmt.Errorf("consensus: proposal canonicalization failed: %w", err)
	}
	valid, err := crypto.Verify(proposerInfo.PublicKey, proposal.Signature, sigData)
	if err != nil {
		return nil, fmt.Errorf("consensus: proposal signature verification error: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("consensus: invalid proposal signature from %s", proposal.ProposerID)
	}

	// Verify merkle root matches.
	expectedRoot := computeMerkleRoot(proposal.NodeHashes)
	if proposal.MerkleRoot != expectedRoot {
		return nil, fmt.Errorf("consensus: merkle root mismatch: got %s, want %s", proposal.MerkleRoot, expectedRoot)
	}

	// Store proposal and update round.
	e.proposals[proposal.ProposalID] = proposal
	if proposal.Round > e.round {
		e.round = proposal.Round
	}
	e.state = StatePreVote

	// Create a PRE_VOTE Accept=true.
	vote, err := e.createVote(proposal.ProposalID, proposal.Round, StatePreVote, true)
	if err != nil {
		return nil, err
	}

	// Store our own vote.
	e.storeVote(vote)

	return vote, nil
}

// ReceiveVote handles an incoming vote from a validator.
// Returns a CommitCertificate if quorum is reached at PRE_COMMIT phase,
// or nil if more votes are needed.
func (e *Engine) ReceiveVote(vote *Vote) (*CommitCertificate, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Verify voter is a validator.
	voterInfo, ok := e.validators.Validators[vote.ValidatorID]
	if !ok {
		return nil, fmt.Errorf("consensus: unknown validator %s", vote.ValidatorID)
	}

	// Verify vote signature.
	sigData := canonicalVoteBytes(vote)
	valid, err := crypto.Verify(voterInfo.PublicKey, vote.Signature, sigData)
	if err != nil {
		return nil, fmt.Errorf("consensus: vote signature verification error: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("consensus: invalid vote signature from %s", vote.ValidatorID)
	}

	// Validate vote phase against current engine state.
	// PRE_VOTE is only accepted when the engine is in PROPOSE or PRE_VOTE state.
	// PRE_COMMIT is only accepted when the engine is in PRE_VOTE state (first quorum reached).
	switch vote.Phase {
	case StatePreVote:
		if e.state != StatePropose && e.state != StatePreVote {
			return nil, fmt.Errorf("consensus: cannot accept PRE_VOTE in state %s", e.state)
		}
	case StatePreCommit:
		if e.state != StatePreCommit {
			return nil, fmt.Errorf("consensus: cannot accept PRE_COMMIT in state %s", e.state)
		}
	default:
		return nil, fmt.Errorf("consensus: unexpected vote phase %s", vote.Phase)
	}

	// Store the vote.
	e.storeVote(vote)

	checker := NewQuorumChecker(e.validators)

	switch vote.Phase {
	case StatePreVote:
		// Check if we have quorum for PRE_VOTE.
		if e.hasQuorumLocked(vote.ProposalID, StatePreVote, checker) {
			e.state = StatePreCommit
			// No automatic PRE_COMMIT vote generation here; the caller
			// (or protocol driver) should create PRE_COMMIT votes after
			// observing PRE_VOTE quorum.
			return nil, nil
		}
		return nil, nil

	case StatePreCommit:
		// Check if we have quorum for PRE_COMMIT.
		if e.hasQuorumLocked(vote.ProposalID, StatePreCommit, checker) {
			e.state = StateCommit

			proposal, ok := e.proposals[vote.ProposalID]
			if !ok {
				return nil, fmt.Errorf("consensus: proposal %s not found", vote.ProposalID)
			}

			cert := e.buildCertificate(proposal, checker)
			e.certificates[proposal.Round] = cert
			return cert, nil
		}
		return nil, nil

	default:
		return nil, fmt.Errorf("consensus: unexpected vote phase %s", vote.Phase)
	}
}

// HasQuorum checks if enough votes have been collected for a proposal at a given phase.
func (e *Engine) HasQuorum(proposalID string, phase ConsensusState) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	checker := NewQuorumChecker(e.validators)
	return e.hasQuorumLocked(proposalID, phase, checker)
}

// GetCertificate returns the commit certificate for a round.
func (e *Engine) GetCertificate(round uint64) (*CommitCertificate, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cert, ok := e.certificates[round]
	return cert, ok
}

// CurrentRound returns the current consensus round.
func (e *Engine) CurrentRound() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.round
}

// --- internal helpers ---

func (e *Engine) createVote(proposalID string, round uint64, phase ConsensusState, accept bool) (*Vote, error) {
	voteID := computeVoteID(e.nodeID, proposalID, phase)

	v := &Vote{
		VoteID:      voteID,
		ValidatorID: e.nodeID,
		ProposalID:  proposalID,
		Round:       round,
		Phase:       phase,
		Accept:      accept,
		Timestamp:   e.clock(),
	}

	sigData := canonicalVoteBytes(v)
	sig, err := e.signer.Sign(sigData)
	if err != nil {
		return nil, fmt.Errorf("consensus: signing vote failed: %w", err)
	}
	v.Signature = sig

	return v, nil
}

func (e *Engine) storeVote(v *Vote) {
	switch v.Phase {
	case StatePreVote:
		if e.votes[v.ProposalID] == nil {
			e.votes[v.ProposalID] = make(map[string]*Vote)
		}
		e.votes[v.ProposalID][v.ValidatorID] = v
	case StatePreCommit:
		if e.preCommits[v.ProposalID] == nil {
			e.preCommits[v.ProposalID] = make(map[string]*Vote)
		}
		e.preCommits[v.ProposalID][v.ValidatorID] = v
	}
}

func (e *Engine) hasQuorumLocked(proposalID string, phase ConsensusState, checker *QuorumChecker) bool {
	var voteMap map[string]*Vote
	switch phase {
	case StatePreVote:
		voteMap = e.votes[proposalID]
	case StatePreCommit:
		voteMap = e.preCommits[proposalID]
	default:
		return false
	}
	if voteMap == nil {
		return false
	}
	votes := make([]*Vote, 0, len(voteMap))
	for _, v := range voteMap {
		votes = append(votes, v)
	}
	return checker.IsQuorumMet(votes)
}

func (e *Engine) buildCertificate(proposal *Proposal, checker *QuorumChecker) *CommitCertificate {
	preCommitVotes := e.preCommits[proposal.ProposalID]
	allVotes := make([]Vote, 0, len(preCommitVotes))
	for _, v := range preCommitVotes {
		if v.Accept {
			allVotes = append(allVotes, *v)
		}
	}

	contentHash, _ := canonicalize.CanonicalHash(proposal)

	return &CommitCertificate{
		ProposalID:  proposal.ProposalID,
		Round:       proposal.Round,
		MerkleRoot:  proposal.MerkleRoot,
		Votes:       allVotes,
		QuorumSize:  checker.ComputeQuorum(),
		ContentHash: contentHash,
	}
}

// computeMerkleRoot computes a simple Merkle root over sorted node hashes.
// For an empty set, returns the hash of the empty string.
func computeMerkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		h := sha256.Sum256(nil)
		return hex.EncodeToString(h[:])
	}

	// Sort for determinism.
	sorted := make([]string, len(hashes))
	copy(sorted, hashes)
	sort.Strings(sorted)

	// Iterative Merkle tree: hash pairs bottom-up.
	level := make([][]byte, len(sorted))
	for i, s := range sorted {
		decoded, err := hex.DecodeString(s)
		if err != nil {
			// Treat as raw bytes if not hex.
			h := sha256.Sum256([]byte(s))
			level[i] = h[:]
		} else {
			level[i] = decoded
		}
	}

	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				combined := append(level[i], level[i+1]...)
				h := sha256.Sum256(combined)
				next = append(next, h[:])
			} else {
				// Odd element: promote.
				next = append(next, level[i])
			}
		}
		level = next
	}

	return hex.EncodeToString(level[0])
}

// computeProposalID deterministically derives a proposal ID from proposer, round, and merkle root.
func computeProposalID(proposerID string, round uint64, merkleRoot string) string {
	data := fmt.Sprintf("proposal:%s:%d:%s", proposerID, round, merkleRoot)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// computeVoteID deterministically derives a vote ID from validator, proposal, and phase.
func computeVoteID(validatorID string, proposalID string, phase ConsensusState) string {
	data := fmt.Sprintf("vote:%s:%s:%s", validatorID, proposalID, phase)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// canonicalProposalBytes returns the JCS-canonical bytes of a proposal for signing.
// Excludes the Signature field to avoid circular dependency.
func canonicalProposalBytes(p *Proposal) ([]byte, error) {
	type proposalSignable struct {
		ProposalID string   `json:"proposal_id"`
		ProposerID string   `json:"proposer_id"`
		Round      uint64   `json:"round"`
		NodeHashes []string `json:"node_hashes"`
		MerkleRoot string   `json:"merkle_root"`
	}
	signable := proposalSignable{
		ProposalID: p.ProposalID,
		ProposerID: p.ProposerID,
		Round:      p.Round,
		NodeHashes: p.NodeHashes,
		MerkleRoot: p.MerkleRoot,
	}
	return canonicalize.JCS(signable)
}

// canonicalVoteBytes returns the deterministic bytes of a vote for signing.
// Excludes the Signature field to avoid circular dependency.
func canonicalVoteBytes(v *Vote) []byte {
	// Deterministic string format for vote signing.
	data := fmt.Sprintf("vote:%s:%s:%s:%d:%s:%t",
		v.VoteID, v.ValidatorID, v.ProposalID, v.Round, v.Phase, v.Accept)
	return []byte(data)
}
