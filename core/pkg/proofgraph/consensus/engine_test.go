package consensus

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// testCluster creates a validator set with n validators and their signers.
func testCluster(t *testing.T, n int) (*ValidatorSet, map[string]*crypto.Ed25519Signer) {
	t.Helper()
	signers := make(map[string]*crypto.Ed25519Signer, n)
	validators := make(map[string]ValidatorInfo, n)

	for i := range n {
		id := "validator-" + itoa(i)
		signer, err := crypto.NewEd25519Signer(id)
		if err != nil {
			t.Fatalf("creating signer %d: %v", i, err)
		}
		signers[id] = signer
		validators[id] = ValidatorInfo{
			ValidatorID: id,
			PublicKey:   signer.PublicKey(),
			Weight:      1,
		}
	}

	vs := &ValidatorSet{Validators: validators}
	// Quorum will be computed dynamically by QuorumChecker.
	return vs, signers
}

func fixedClock() func() time.Time {
	t := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func TestEngine_Propose(t *testing.T) {
	vs, signers := testCluster(t, 4)
	proposerID := "validator-0"
	engine := NewEngine(proposerID, vs, signers[proposerID]).WithClock(fixedClock())

	nodeHashes := []string{
		"aaaa000000000000000000000000000000000000000000000000000000000001",
		"bbbb000000000000000000000000000000000000000000000000000000000002",
	}

	proposal, err := engine.Propose(nodeHashes)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}

	if proposal.ProposerID != proposerID {
		t.Errorf("ProposerID = %s, want %s", proposal.ProposerID, proposerID)
	}
	if proposal.Round != 1 {
		t.Errorf("Round = %d, want 1", proposal.Round)
	}
	if len(proposal.NodeHashes) != 2 {
		t.Errorf("NodeHashes len = %d, want 2", len(proposal.NodeHashes))
	}
	if proposal.MerkleRoot == "" {
		t.Error("MerkleRoot should not be empty")
	}
	if proposal.Signature == "" {
		t.Error("Signature should not be empty")
	}
	if proposal.ProposalID == "" {
		t.Error("ProposalID should not be empty")
	}

	// Verify the signature is valid against the proposer's public key.
	sigData, err := canonicalProposalBytes(proposal)
	if err != nil {
		t.Fatalf("canonicalProposalBytes: %v", err)
	}
	valid, err := crypto.Verify(vs.Validators[proposerID].PublicKey, proposal.Signature, sigData)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Error("proposal signature verification failed")
	}
}

func TestEngine_ReceiveProposal(t *testing.T) {
	vs, signers := testCluster(t, 4)

	// Proposer creates a proposal.
	proposerID := "validator-0"
	proposerEngine := NewEngine(proposerID, vs, signers[proposerID]).WithClock(fixedClock())

	nodeHashes := []string{
		"cccc000000000000000000000000000000000000000000000000000000000003",
	}
	proposal, err := proposerEngine.Propose(nodeHashes)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}

	// Another validator receives the proposal.
	voterID := "validator-1"
	voterEngine := NewEngine(voterID, vs, signers[voterID]).WithClock(fixedClock())

	vote, err := voterEngine.ReceiveProposal(proposal)
	if err != nil {
		t.Fatalf("ReceiveProposal: %v", err)
	}

	if vote.ValidatorID != voterID {
		t.Errorf("ValidatorID = %s, want %s", vote.ValidatorID, voterID)
	}
	if vote.ProposalID != proposal.ProposalID {
		t.Errorf("ProposalID = %s, want %s", vote.ProposalID, proposal.ProposalID)
	}
	if vote.Phase != StatePreVote {
		t.Errorf("Phase = %s, want %s", vote.Phase, StatePreVote)
	}
	if !vote.Accept {
		t.Error("Accept should be true")
	}
	if vote.Signature == "" {
		t.Error("Vote signature should not be empty")
	}
}

func TestEngine_QuorumReached(t *testing.T) {
	// 4 validators, quorum = 3 (can tolerate 1 Byzantine).
	vs, signers := testCluster(t, 4)

	proposerID := "validator-0"
	proposerEngine := NewEngine(proposerID, vs, signers[proposerID]).WithClock(fixedClock())

	nodeHashes := []string{
		"dddd000000000000000000000000000000000000000000000000000000000004",
		"eeee000000000000000000000000000000000000000000000000000000000005",
	}
	proposal, err := proposerEngine.Propose(nodeHashes)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}

	// Collect PRE_VOTE from 3 validators (0, 1, 2). Validator 3 is Byzantine/silent.
	var preVotes []*Vote

	// Proposer votes for its own proposal.
	proposerVote, err := proposerEngine.ReceiveProposal(proposal)
	if err != nil {
		t.Fatalf("proposer ReceiveProposal: %v", err)
	}
	preVotes = append(preVotes, proposerVote)

	for i := 1; i <= 2; i++ {
		id := "validator-" + itoa(i)
		eng := NewEngine(id, vs, signers[id]).WithClock(fixedClock())
		vote, err := eng.ReceiveProposal(proposal)
		if err != nil {
			t.Fatalf("ReceiveProposal validator-%d: %v", i, err)
		}
		preVotes = append(preVotes, vote)
	}

	// Feed PRE_VOTE votes into the proposer engine. 3 votes should reach quorum.
	for _, v := range preVotes {
		_, err := proposerEngine.ReceiveVote(v)
		if err != nil {
			t.Fatalf("ReceiveVote PRE_VOTE: %v", err)
		}
	}

	if !proposerEngine.HasQuorum(proposal.ProposalID, StatePreVote) {
		t.Fatal("expected PRE_VOTE quorum to be met with 3 of 4 validators")
	}

	// Now create PRE_COMMIT votes from the same 3 validators.
	var preCommitVotes []*Vote
	for i := 0; i <= 2; i++ {
		id := "validator-" + itoa(i)
		// Manually create a PRE_COMMIT vote.
		voteID := computeVoteID(id, proposal.ProposalID, StatePreCommit)
		v := &Vote{
			VoteID:      voteID,
			ValidatorID: id,
			ProposalID:  proposal.ProposalID,
			Round:       proposal.Round,
			Phase:       StatePreCommit,
			Accept:      true,
			Timestamp:   fixedClock()(),
		}
		sigData := canonicalVoteBytes(v)
		sig, err := signers[id].Sign(sigData)
		if err != nil {
			t.Fatalf("signing precommit: %v", err)
		}
		v.Signature = sig
		preCommitVotes = append(preCommitVotes, v)
	}

	// Feed PRE_COMMIT votes. The last one should produce a certificate.
	var cert *CommitCertificate
	for _, v := range preCommitVotes {
		c, err := proposerEngine.ReceiveVote(v)
		if err != nil {
			t.Fatalf("ReceiveVote PRE_COMMIT: %v", err)
		}
		if c != nil {
			cert = c
		}
	}

	if cert == nil {
		t.Fatal("expected CommitCertificate after PRE_COMMIT quorum")
	}
	if cert.ProposalID != proposal.ProposalID {
		t.Errorf("cert.ProposalID = %s, want %s", cert.ProposalID, proposal.ProposalID)
	}
	if cert.Round != proposal.Round {
		t.Errorf("cert.Round = %d, want %d", cert.Round, proposal.Round)
	}
	if cert.MerkleRoot != proposal.MerkleRoot {
		t.Errorf("cert.MerkleRoot = %s, want %s", cert.MerkleRoot, proposal.MerkleRoot)
	}
	if cert.QuorumSize != 3 {
		t.Errorf("cert.QuorumSize = %d, want 3", cert.QuorumSize)
	}
	if len(cert.Votes) < 3 {
		t.Errorf("cert.Votes = %d, want >= 3", len(cert.Votes))
	}
	if cert.ContentHash == "" {
		t.Error("cert.ContentHash should not be empty")
	}

	// Verify certificate is retrievable.
	stored, ok := proposerEngine.GetCertificate(proposal.Round)
	if !ok {
		t.Fatal("GetCertificate returned false")
	}
	if stored.ProposalID != cert.ProposalID {
		t.Error("stored certificate does not match")
	}
}

func TestEngine_QuorumNotReached(t *testing.T) {
	// 4 validators, quorum = 3. Only 1 vote should not be enough.
	vs, signers := testCluster(t, 4)

	proposerID := "validator-0"
	proposerEngine := NewEngine(proposerID, vs, signers[proposerID]).WithClock(fixedClock())

	nodeHashes := []string{
		"ffff000000000000000000000000000000000000000000000000000000000006",
	}
	proposal, err := proposerEngine.Propose(nodeHashes)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}

	// Only validator-1 votes.
	voterID := "validator-1"
	voterEngine := NewEngine(voterID, vs, signers[voterID]).WithClock(fixedClock())
	vote, err := voterEngine.ReceiveProposal(proposal)
	if err != nil {
		t.Fatalf("ReceiveProposal: %v", err)
	}

	cert, err := proposerEngine.ReceiveVote(vote)
	if err != nil {
		t.Fatalf("ReceiveVote: %v", err)
	}
	if cert != nil {
		t.Error("expected no certificate with only 1 vote")
	}

	if proposerEngine.HasQuorum(proposal.ProposalID, StatePreVote) {
		t.Error("quorum should not be met with 1 of 4 validators")
	}
}

func TestEngine_ByzantineRejection(t *testing.T) {
	vs, signers := testCluster(t, 4)

	proposerID := "validator-0"
	proposerEngine := NewEngine(proposerID, vs, signers[proposerID]).WithClock(fixedClock())

	nodeHashes := []string{
		"1111000000000000000000000000000000000000000000000000000000000007",
	}
	proposal, err := proposerEngine.Propose(nodeHashes)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}

	// Create a vote with an invalid signature (Byzantine behavior).
	byzantineVote := &Vote{
		VoteID:      "fake-vote-id",
		ValidatorID: "validator-1",
		ProposalID:  proposal.ProposalID,
		Round:       proposal.Round,
		Phase:       StatePreVote,
		Accept:      true,
		Signature:   "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		Timestamp:   fixedClock()(),
	}

	_, err = proposerEngine.ReceiveVote(byzantineVote)
	if err == nil {
		t.Fatal("expected error for vote with invalid signature")
	}

	// Also test a vote from an unknown validator.
	unknownVote := &Vote{
		VoteID:      "unknown-vote-id",
		ValidatorID: "validator-999",
		ProposalID:  proposal.ProposalID,
		Round:       proposal.Round,
		Phase:       StatePreVote,
		Accept:      true,
		Signature:   "anything",
		Timestamp:   fixedClock()(),
	}

	_, err = proposerEngine.ReceiveVote(unknownVote)
	if err == nil {
		t.Fatal("expected error for vote from unknown validator")
	}

	// Test proposal with invalid signature.
	badProposal := &Proposal{
		ProposalID: "bad-proposal",
		ProposerID: "validator-0",
		Round:      99,
		NodeHashes: []string{"abc"},
		MerkleRoot: computeMerkleRoot([]string{"abc"}),
		Signature:  "badsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsigbadsig",
		Timestamp:  fixedClock()(),
	}

	voterEngine := NewEngine("validator-2", vs, signers["validator-2"]).WithClock(fixedClock())
	_, err = voterEngine.ReceiveProposal(badProposal)
	if err == nil {
		t.Fatal("expected error for proposal with invalid signature")
	}
}

func TestEngine_RoundAdvancement(t *testing.T) {
	vs, signers := testCluster(t, 4)
	proposerID := "validator-0"
	engine := NewEngine(proposerID, vs, signers[proposerID]).WithClock(fixedClock())

	if engine.CurrentRound() != 0 {
		t.Errorf("initial round = %d, want 0", engine.CurrentRound())
	}

	// First proposal advances to round 1.
	_, err := engine.Propose([]string{"hash1"})
	if err != nil {
		t.Fatalf("Propose 1: %v", err)
	}
	if engine.CurrentRound() != 1 {
		t.Errorf("round after first propose = %d, want 1", engine.CurrentRound())
	}

	// Second proposal advances to round 2.
	_, err = engine.Propose([]string{"hash2"})
	if err != nil {
		t.Fatalf("Propose 2: %v", err)
	}
	if engine.CurrentRound() != 2 {
		t.Errorf("round after second propose = %d, want 2", engine.CurrentRound())
	}

	// Third proposal advances to round 3.
	_, err = engine.Propose([]string{"hash3"})
	if err != nil {
		t.Fatalf("Propose 3: %v", err)
	}
	if engine.CurrentRound() != 3 {
		t.Errorf("round after third propose = %d, want 3", engine.CurrentRound())
	}
}

func TestEngine_NonValidatorCannotPropose(t *testing.T) {
	vs, _ := testCluster(t, 4)

	// Create a signer that is NOT in the validator set.
	outsider, err := crypto.NewEd25519Signer("outsider")
	if err != nil {
		t.Fatalf("creating outsider signer: %v", err)
	}
	engine := NewEngine("outsider", vs, outsider).WithClock(fixedClock())

	_, err = engine.Propose([]string{"hash1"})
	if err == nil {
		t.Fatal("expected error when non-validator proposes")
	}
}

func TestEngine_OutOfOrderVoteRejected(t *testing.T) {
	vs, signers := testCluster(t, 4)

	proposerID := "validator-0"
	proposerEngine := NewEngine(proposerID, vs, signers[proposerID]).WithClock(fixedClock())

	// Create a proposal — engine moves to PROPOSE state.
	nodeHashes := []string{
		"aabb000000000000000000000000000000000000000000000000000000000099",
	}
	proposal, err := proposerEngine.Propose(nodeHashes)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}

	// Try to submit a PRE_COMMIT vote while the engine is still in PROPOSE state.
	// This should be rejected because PRE_COMMIT is only valid in PRE_COMMIT state.
	voterID := "validator-1"
	voteID := computeVoteID(voterID, proposal.ProposalID, StatePreCommit)
	preCommitVote := &Vote{
		VoteID:      voteID,
		ValidatorID: voterID,
		ProposalID:  proposal.ProposalID,
		Round:       proposal.Round,
		Phase:       StatePreCommit,
		Accept:      true,
		Timestamp:   fixedClock()(),
	}
	sigData := canonicalVoteBytes(preCommitVote)
	sig, err := signers[voterID].Sign(sigData)
	if err != nil {
		t.Fatalf("signing precommit: %v", err)
	}
	preCommitVote.Signature = sig

	_, err = proposerEngine.ReceiveVote(preCommitVote)
	if err == nil {
		t.Fatal("expected error when submitting PRE_COMMIT vote in PROPOSE state")
	}
}

// itoa is a simple int-to-string for generating test IDs.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
