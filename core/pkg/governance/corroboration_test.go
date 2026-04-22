package governance

import (
	"context"
	"errors"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// MockLedger
type mockLedger struct {
	valid bool
	err   error
}

func (m *mockLedger) VerifyReceipt(ctx context.Context, receiptID, merkleRoot string) (bool, error) {
	return m.valid, m.err
}

func TestCorroborator_Corroborate_I18(t *testing.T) {
	tests := []struct {
		name           string
		receipt        *contracts.Receipt
		ledger         LedgerClient
		expectedStatus string
	}{
		{
			name: "Valid Receipt",
			receipt: &contracts.Receipt{
				ReceiptID:  "rcpt-1",
				MerkleRoot: "root-1",
			},
			ledger:         &mockLedger{valid: true},
			expectedStatus: "VERIFIED",
		},
		{
			name: "Invalid Receipt (Ledger Logic)",
			receipt: &contracts.Receipt{
				ReceiptID:  "rcpt-2",
				MerkleRoot: "bad-root",
			},
			ledger:         &mockLedger{valid: false},
			expectedStatus: "DISPUTED",
		},
		{
			name: "Ledger Err (Pending)",
			receipt: &contracts.Receipt{
				ReceiptID:  "rcpt-3",
				MerkleRoot: "root-3",
			},
			ledger:         &mockLedger{err: errors.New("timeout")},
			expectedStatus: "PENDING",
		},
		{
			name: "Invalid Structure",
			receipt: &contracts.Receipt{
				ReceiptID: "", // Missing ID
			},
			ledger:         &mockLedger{},
			expectedStatus: "ERROR", // Test logic handles error manually
		},
	}

	c := NewCorroborator("witness-1", nil) // ledger set in loop

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c.ledger = tt.ledger
			res, err := c.Corroborate(context.Background(), tt.receipt)

			if tt.expectedStatus == "ERROR" {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if res.Status != tt.expectedStatus {
				t.Errorf("expected status %s, got %s", tt.expectedStatus, res.Status)
			}
		})
	}
}
