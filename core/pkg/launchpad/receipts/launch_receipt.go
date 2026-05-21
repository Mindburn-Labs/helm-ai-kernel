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

func NewReceipt(receiptType, launchID, verdict string, subject map[string]any) Receipt {
	r := Receipt{
		Type:         receiptType,
		LaunchID:     launchID,
		DecisionID:   receiptType + ":" + launchID,
		Verdict:      verdict,
		Status:       verdict,
		Subject:      subject,
		CreatedAt:    time.Now().UTC(),
		LamportClock: 1,
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
