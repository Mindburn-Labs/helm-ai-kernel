package receipts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type Receipt = contracts.Receipt

type LaunchReceipt struct {
	LaunchID string `json:"launch_id"`
	Verdict  string `json:"verdict"`
	PlanHash string `json:"plan_hash"`
}

// NewReceipt builds an unchained receipt: genesis clock, no predecessor.
//
// Prefer Chain.Next for anything that emits more than one receipt — a set of
// unchained receipts asserts no chain of custody (F-21).
func NewReceipt(receiptType, launchID, verdict string, subject map[string]any) Receipt {
	return newLinkedReceipt(receiptType, launchID, verdict, subject, "", 1, launchID)
}

func newLinkedReceipt(receiptType, launchID, verdict string, subject map[string]any, prevHash string, lamport uint64, sessionID string) Receipt {
	r := Receipt{
		Type:         receiptType,
		LaunchID:     launchID,
		DecisionID:   receiptType + ":" + launchID,
		Verdict:      verdict,
		Status:       verdict,
		Subject:      subject,
		CreatedAt:    time.Now().UTC(),
		PrevHash:     prevHash,
		LamportClock: lamport,
		// ExecutorID is the session key the verifier groups causal chains by.
		// Without it every receipt in a pack lands in one implicit group, so a
		// launch chain and a separate teardown genesis would read as a forked
		// chain rather than as the two distinct chains they are.
		ExecutorID: sessionID,
	}
	r.DecisionHash = Hash(map[string]any{"type": receiptType, "launch_id": launchID, "verdict": verdict, "subject": subject})
	r.Hash = Hash(r)
	r.ReceiptID = receiptType + ":" + r.Hash
	return r
}

func Hash(v any) string {
	data, _ := json.Marshal(v)
	return HashBytes(data)
}

func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
