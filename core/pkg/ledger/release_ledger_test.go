package ledger

import (
	"testing"
)

func TestReleaseLedgerAppend(t *testing.T) {
	l := NewReleaseLedger()
	r, err := l.RecordRelease(ReleaseRecord{Version: "1.0.0", TestEvidenceHash: "sha256:test1", SupplyChainHash: "sha256:sc1"})
	if err != nil {
		t.Fatal(err)
	}
	if r.ContentHash == "" {
		t.Fatal("expected content hash")
	}
	if l.Length() != 1 {
		t.Fatalf("expected 1, got %d", l.Length())
	}
}

func TestReleaseLedgerChaining(t *testing.T) {
	l := NewReleaseLedger()
	r1, _ := l.RecordRelease(ReleaseRecord{Version: "1.0.0", TestEvidenceHash: "sha256:t1", SupplyChainHash: "sha256:s1"})
	r2, _ := l.RecordRelease(ReleaseRecord{Version: "2.0.0", TestEvidenceHash: "sha256:t2", SupplyChainHash: "sha256:s2"})

	if r2.PrevReleaseHash != r1.ContentHash {
		t.Fatal("release 2 should chain to release 1")
	}
}

func TestReleaseLedgerVerify(t *testing.T) {
	l := NewReleaseLedger()
	l.RecordRelease(ReleaseRecord{Version: "1.0.0", TestEvidenceHash: "sha256:t1", SupplyChainHash: "sha256:s1"})
	l.RecordRelease(ReleaseRecord{Version: "2.0.0", TestEvidenceHash: "sha256:t2", SupplyChainHash: "sha256:s2"})

	ok, _ := l.Verify()
	if !ok {
		t.Fatal("expected valid chain")
	}
}

func TestReleaseLedgerGetRelease(t *testing.T) {
	l := NewReleaseLedger()
	l.RecordRelease(ReleaseRecord{Version: "1.0.0", TestEvidenceHash: "sha256:t1", SupplyChainHash: "sha256:s1"})

	r, err := l.GetRelease(0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "1.0.0" {
		t.Fatal("version mismatch")
	}
}

func TestReleaseLedgerWithDR(t *testing.T) {
	l := NewReleaseLedger()
	r, _ := l.RecordRelease(ReleaseRecord{
		Version:          "1.0.0",
		TestEvidenceHash: "sha256:t1",
		SupplyChainHash:  "sha256:s1",
		DRDrillReceiptID: "dr-1",
		RedTeamSuiteID:   "rt-suite-1",
	})

	if r.DRDrillReceiptID != "dr-1" {
		t.Fatal("expected DR drill receipt")
	}
	if r.RedTeamSuiteID != "rt-suite-1" {
		t.Fatal("expected red team suite")
	}
}
