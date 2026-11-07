package governance

import (
	"context"
	"time"
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

type CorroboratedReceipt struct {
	ReceiptID      string    `json:"receipt_id"`
	CorroboratorID string    `json:"corroborator_id"`
	Status         string    `json:"status"`
	Timestamp      time.Time `json:"timestamp"`
}
