package governance

import (
	"context"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// Corroborator ingests Receipts and validates them against an external Source of Truth
// (e.g. Ledger, Transparency Log, or Witness Group).
type Corroborator struct {
	id     string
	ledger LedgerClient
}

type LedgerClient interface {
	VerifyReceipt(ctx context.Context, receiptID, merkleRoot string) (bool, error)
}

func NewCorroborator(id string, ledger LedgerClient) *Corroborator {
	return &Corroborator{
		id:     id,
		ledger: ledger,
	}
}

// Corroborate checks the receipt and returns a status.
func (c *Corroborator) Corroborate(ctx context.Context, receipt *contracts.Receipt) (*CorroboratedReceipt, error) {
	// 1. Structural Validation
	if receipt.ReceiptID == "" || receipt.MerkleRoot == "" {
		return nil, fmt.Errorf("invalid receipt structure")
	}

	// 2. External Verification (Ledger)
	valid, err := c.ledger.VerifyReceipt(ctx, receipt.ReceiptID, receipt.MerkleRoot)
	if err != nil {
		return &CorroboratedReceipt{
			ReceiptID:      receipt.ReceiptID,
			CorroboratorID: c.id,
			Status:         "PENDING", // Retry later
			Timestamp:      time.Now(),
		}, nil
	}

	status := "VERIFIED"
	if !valid {
		status = "DISPUTED"
	}

	return &CorroboratedReceipt{
		ReceiptID:      receipt.ReceiptID,
		CorroboratorID: c.id,
		Status:         status,
		Timestamp:      time.Now(),
	}, nil
}

type CorroboratedReceipt struct {
	ReceiptID      string    `json:"receipt_id"`
	CorroboratorID string    `json:"corroborator_id"`
	Status         string    `json:"status"`
	Timestamp      time.Time `json:"timestamp"`
}
