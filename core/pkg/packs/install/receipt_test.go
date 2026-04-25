package install

import (
	"strings"
	"testing"
	"time"
)

// TestReceipt_DeterministicHash confirms repeated issueReceipt calls with
// identical inputs produce identical ContentHash values.
func TestReceipt_DeterministicHash(t *testing.T) {
	installedAt := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)

	r1, err := issueReceipt("demo-pack", "Demo", "0.1.0", "sha256:abc", ActionInstall, "operator-local", installedAt, "")
	if err != nil {
		t.Fatalf("issueReceipt #1: %v", err)
	}
	r2, err := issueReceipt("demo-pack", "Demo", "0.1.0", "sha256:abc", ActionInstall, "operator-local", installedAt, "")
	if err != nil {
		t.Fatalf("issueReceipt #2: %v", err)
	}

	if r1.ContentHash != r2.ContentHash {
		t.Fatalf("ContentHash not deterministic: %q vs %q", r1.ContentHash, r2.ContentHash)
	}
	if !strings.HasPrefix(r1.ContentHash, "sha256:") || len(r1.ContentHash) != len("sha256:")+64 {
		t.Fatalf("ContentHash format: %q", r1.ContentHash)
	}
}

// TestReceipt_Chain verifies PrevReceiptID threads the chain and changes
// the ContentHash.
func TestReceipt_Chain(t *testing.T) {
	installedAt := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)

	first, err := issueReceipt("demo-pack", "Demo", "0.1.0", "sha256:abc", ActionInstall, "operator-local", installedAt, "")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := issueReceipt("demo-pack", "Demo", "0.2.0", "sha256:def", ActionUpgrade, "operator-local", installedAt.Add(time.Hour), first.ReceiptID)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if second.PrevReceiptID != first.ReceiptID {
		t.Fatalf("PrevReceiptID not threaded: got %q, want %q", second.PrevReceiptID, first.ReceiptID)
	}
	if first.ContentHash == second.ContentHash {
		t.Fatalf("chain receipts share ContentHash; chain is broken")
	}
	if first.ReceiptID == second.ReceiptID {
		t.Fatalf("sequential receipts share ReceiptID: %q", first.ReceiptID)
	}
}

// TestReceipt_ActionChangesHash confirms different actions yield different
// ContentHash values even when all other fields match.
func TestReceipt_ActionChangesHash(t *testing.T) {
	installedAt := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)

	install, err := issueReceipt("demo", "Demo", "0.1.0", "sha256:abc", ActionInstall, "op", installedAt, "")
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	rollback, err := issueReceipt("demo", "Demo", "0.1.0", "sha256:abc", ActionRollback, "op", installedAt, "")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if install.ContentHash == rollback.ContentHash {
		t.Fatalf("install and rollback receipts should hash differently")
	}
}

// TestReceipt_MissingFields rejects invalid inputs.
func TestReceipt_MissingFields(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name                                     string
		packID, packVersion, action, installedBy string
	}{
		{"missing pack_id", "", "0.1.0", ActionInstall, "op"},
		{"missing version", "demo", "", ActionInstall, "op"},
		{"missing action", "demo", "0.1.0", "", "op"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := issueReceipt(tc.packID, "Demo", tc.packVersion, "sha256:abc", tc.action, tc.installedBy, now, ""); err == nil {
				t.Fatalf("%s: want error", tc.name)
			}
		})
	}
}
