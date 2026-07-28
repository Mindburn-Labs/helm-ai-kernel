package receipts

// Chain assigns causal linkage to the receipts produced within one launch.
//
// Every receipt used to be created by NewReceipt with a hardcoded
// LamportClock of 1 and no PrevHash at all, so a launch emitted six receipts
// that each claimed to be the genesis of their own chain and none of which
// referenced another. An EvidencePack built from them asserted no chain of
// custody, which is materially weaker than the product's claim (F-21).
//
// Chain is not safe for concurrent use: a causal chain is inherently ordered,
// and receipts within a launch are produced sequentially.
type Chain struct {
	sessionID string
	prevHash  string
	lamport   uint64
}

// NewChain starts a fresh causal chain. The first receipt it produces is the
// genesis: empty PrevHash, LamportClock 1.
// NewChain starts a chain under an explicit session key. Receipts belonging
// to different operations must use different session keys, or the verifier
// reads their separate genesis receipts as a fork of one chain.
func NewChain(sessionID string) *Chain { return &Chain{sessionID: sessionID} }

// Next builds the following receipt in the chain, linking it to the previous
// one and advancing the logical clock.
func (c *Chain) Next(receiptType, launchID, verdict string, subject map[string]any) Receipt {
	c.lamport++
	r := newLinkedReceipt(receiptType, launchID, verdict, subject, c.prevHash, c.lamport, c.sessionID)
	c.prevHash = r.Hash
	return r
}

// Head returns the hash of the most recent receipt, or "" before the first.
func (c *Chain) Head() string { return c.prevHash }
