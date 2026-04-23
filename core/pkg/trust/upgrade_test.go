package trust

import (
	"testing"
)

func TestUpgradeRecordFull(t *testing.T) {
	r := NewUpgradeRegistry()
	receipt, err := r.RecordUpgrade("my-pack", "1.0", "2.0", "admin", CompatFull, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Compatibility != CompatFull {
		t.Fatal("expected FULL compat")
	}
	if !receipt.Reversible {
		t.Fatal("expected reversible")
	}
	if receipt.RollbackVersion != "1.0" {
		t.Fatal("expected rollback to 1.0")
	}
}

func TestUpgradeBreakingRequiresSchema(t *testing.T) {
	r := NewUpgradeRegistry()
	_, err := r.RecordUpgrade("pkg", "1.0", "2.0", "admin", CompatBreaking, false, false, false)
	if err == nil {
		t.Fatal("expected error: breaking upgrade without schema check")
	}
}

func TestUpgradeBreakingWithSchema(t *testing.T) {
	r := NewUpgradeRegistry()
	receipt, err := r.RecordUpgrade("pkg", "1.0", "2.0", "admin", CompatBreaking, true, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Compatibility != CompatBreaking {
		t.Fatal("expected BREAKING")
	}
}

func TestUpgradeHistory(t *testing.T) {
	r := NewUpgradeRegistry()
	r.RecordUpgrade("pkg", "1.0", "2.0", "admin", CompatFull, true, true, true)
	r.RecordUpgrade("pkg", "2.0", "3.0", "admin", CompatBackward, true, true, true)

	history := r.GetHistory("pkg")
	if len(history) != 2 {
		t.Fatalf("expected 2 upgrades, got %d", len(history))
	}
}

func TestUpgradeGetReceipt(t *testing.T) {
	r := NewUpgradeRegistry()
	up, _ := r.RecordUpgrade("pkg", "1.0", "2.0", "admin", CompatFull, true, true, true)

	got, err := r.Get(up.ReceiptID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ToVersion != "2.0" {
		t.Fatal("version mismatch")
	}
}
