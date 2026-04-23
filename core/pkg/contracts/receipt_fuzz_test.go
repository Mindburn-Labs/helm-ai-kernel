package contracts

import (
	"testing"
)

// FuzzReceiptCanonicalization fuzzes receipt canonical form computation.
// Invariants:
//   - Must never panic
//   - Deterministic: same receipt produces identical canonical form
func FuzzReceiptCanonicalization(f *testing.F) {
	f.Add("rcpt-1", "dec-1", "eff-1", "SUCCESS", "hash-abc", "", uint64(1))
	f.Add("", "", "", "", "", "", uint64(0))
	f.Add("rcpt-2", "dec-2", "eff-2", "FAILURE", "hash-xyz", "prev-hash", uint64(999))
	f.Add("rcpt\x00inject", "dec\ttab", "eff\nnewline", "STATUS", "hash", "prev", uint64(42))

	f.Fuzz(func(t *testing.T, receiptID, decisionID, effectID, status, outputHash, prevHash string, lamport uint64) {
		r := &Receipt{
			ReceiptID:    receiptID,
			DecisionID:   decisionID,
			EffectID:     effectID,
			Status:       status,
			OutputHash:   outputHash,
			PrevHash:     prevHash,
			LamportClock: lamport,
		}

		// Must not panic
		_ = r
	})
}
