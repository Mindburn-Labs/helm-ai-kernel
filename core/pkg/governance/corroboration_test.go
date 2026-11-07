package governance

import (
	"context"
)

// MockLedger
type mockLedger struct {
	valid bool
	err   error
}

func (m *mockLedger) VerifyReceipt(ctx context.Context, receiptID, merkleRoot string) (bool, error) {
	return m.valid, m.err
}
