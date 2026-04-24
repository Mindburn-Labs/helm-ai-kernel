package ledger

import (
	"fmt"
	"testing"
	"time"
)

var ledgerClock = func() time.Time { return time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC) }

// --- Ledger 500 Entries ---

func TestStress_Ledger_500Entries(t *testing.T) {
	l := NewLedger(LedgerTypeRelease).WithClock(ledgerClock)
	for i := 0; i < 500; i++ {
		_, err := l.Append("release", "author", map[string]interface{}{"version": fmt.Sprintf("v%d", i)})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if l.Length() != 500 {
		t.Fatalf("expected 500 entries, got %d", l.Length())
	}
}

func TestStress_Ledger_ChainVerification500(t *testing.T) {
	l := NewLedger(LedgerTypePolicy).WithClock(ledgerClock)
	for i := 0; i < 500; i++ {
		l.Append("policy_change", "admin", map[string]interface{}{"rule": i})
	}
	ok, msg := l.Verify()
	if !ok {
		t.Fatalf("chain verification failed: %s", msg)
	}
}

func TestStress_Ledger_HeadAdvances(t *testing.T) {
	l := NewLedger(LedgerTypeRun).WithClock(ledgerClock)
	head1 := l.Head()
	l.Append("run_start", "agent", map[string]interface{}{})
	head2 := l.Head()
	if head1 == head2 {
		t.Fatal("head should advance after append")
	}
}

func TestStress_Ledger_GenesisHead(t *testing.T) {
	l := NewLedger(LedgerTypeEvidence)
	if l.Head() != "genesis" {
		t.Fatal("expected genesis head")
	}
}

func TestStress_Ledger_GetEntry(t *testing.T) {
	l := NewLedger(LedgerTypeRelease).WithClock(ledgerClock)
	l.Append("release", "author", map[string]interface{}{"ver": "1"})
	entry, err := l.Get(1)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Sequence != 1 {
		t.Fatalf("expected seq 1, got %d", entry.Sequence)
	}
}

func TestStress_Ledger_GetOutOfRange(t *testing.T) {
	l := NewLedger(LedgerTypeRelease)
	_, err := l.Get(0)
	if err == nil {
		t.Fatal("expected error for seq 0")
	}
	_, err = l.Get(999)
	if err == nil {
		t.Fatal("expected error for seq out of range")
	}
}

func TestStress_Ledger_Type(t *testing.T) {
	l := NewLedger(LedgerTypePolicy)
	if l.Type() != LedgerTypePolicy {
		t.Fatalf("expected POLICY, got %s", l.Type())
	}
}

func TestStress_Ledger_EmptyVerify(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	ok, _ := l.Verify()
	if !ok {
		t.Fatal("empty ledger should verify")
	}
}

func TestStress_Ledger_ContentHashDeterminism(t *testing.T) {
	l := NewLedger(LedgerTypeRelease).WithClock(ledgerClock)
	l.Append("release", "a", map[string]interface{}{"v": "1"})
	e1, _ := l.Get(1)
	l2 := NewLedger(LedgerTypeRelease).WithClock(ledgerClock)
	l2.Append("release", "a", map[string]interface{}{"v": "1"})
	e2, _ := l2.Get(1)
	if e1.ContentHash != e2.ContentHash {
		t.Fatal("content hash should be deterministic")
	}
}

// --- Typed Ledger 100 Entries ---

func TestStress_TypedLedger_100Entries(t *testing.T) {
	tl := NewTypedLedger(LedgerPolicy).WithClock(ledgerClock)
	for i := 0; i < 100; i++ {
		tl.Append("policy_change", fmt.Sprintf(`{"rule":%d}`, i))
	}
	if tl.Length() != 100 {
		t.Fatalf("expected 100 entries, got %d", tl.Length())
	}
}

func TestStress_TypedLedger_ChainVerify(t *testing.T) {
	tl := NewTypedLedger(LedgerRun).WithClock(ledgerClock)
	for i := 0; i < 100; i++ {
		tl.Append("run", fmt.Sprintf(`{"id":%d}`, i))
	}
	ok, err := tl.Verify()
	if !ok {
		t.Fatalf("typed chain verification failed: %v", err)
	}
}

func TestStress_TypedLedger_HeadAdvances(t *testing.T) {
	tl := NewTypedLedger(LedgerEvidence).WithClock(ledgerClock)
	h1 := tl.Head()
	tl.Append("evidence", "data")
	h2 := tl.Head()
	if h1 == h2 {
		t.Fatal("head should advance")
	}
}

func TestStress_TypedLedger_Get(t *testing.T) {
	tl := NewTypedLedger(LedgerPolicy).WithClock(ledgerClock)
	tl.Append("policy", "data")
	e, err := tl.Get(1)
	if err != nil {
		t.Fatal(err)
	}
	if e.Sequence != 1 {
		t.Fatalf("expected seq 1, got %d", e.Sequence)
	}
}

func TestStress_TypedLedger_GetOutOfRange(t *testing.T) {
	tl := NewTypedLedger(LedgerPolicy)
	_, err := tl.Get(0)
	if err == nil {
		t.Fatal("expected error for seq 0")
	}
}

func TestStress_TypedLedger_Type(t *testing.T) {
	tl := NewTypedLedger(LedgerEvidence)
	if tl.Type() != LedgerEvidence {
		t.Fatalf("expected EVIDENCE, got %s", tl.Type())
	}
}

// --- Release Ledger 50 Releases ---

func TestStress_ReleaseLedger_50Releases(t *testing.T) {
	rl := NewReleaseLedger().WithClock(ledgerClock)
	for i := 0; i < 50; i++ {
		_, err := rl.RecordRelease(ReleaseRecord{
			Version:          fmt.Sprintf("v1.%d.0", i),
			PolicyVersion:    "p1",
			TestEvidenceHash: fmt.Sprintf("test-hash-%d", i),
			SupplyChainHash:  fmt.Sprintf("sc-hash-%d", i),
		})
		if err != nil {
			t.Fatalf("release %d: %v", i, err)
		}
	}
	if rl.Length() != 50 {
		t.Fatalf("expected 50 releases, got %d", rl.Length())
	}
}

func TestStress_ReleaseLedger_ChainVerify(t *testing.T) {
	rl := NewReleaseLedger().WithClock(ledgerClock)
	for i := 0; i < 50; i++ {
		rl.RecordRelease(ReleaseRecord{Version: fmt.Sprintf("v%d", i), TestEvidenceHash: "t", SupplyChainHash: "s"})
	}
	ok, msg := rl.Verify()
	if !ok {
		t.Fatalf("release chain verification failed: %s", msg)
	}
}

func TestStress_ReleaseLedger_GetRelease(t *testing.T) {
	rl := NewReleaseLedger().WithClock(ledgerClock)
	rl.RecordRelease(ReleaseRecord{Version: "v1.0.0", TestEvidenceHash: "t", SupplyChainHash: "s"})
	r, err := rl.GetRelease(0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "v1.0.0" {
		t.Fatalf("expected v1.0.0, got %s", r.Version)
	}
}

func TestStress_ReleaseLedger_GetOutOfRange(t *testing.T) {
	rl := NewReleaseLedger()
	_, err := rl.GetRelease(-1)
	if err == nil {
		t.Fatal("expected error for negative index")
	}
	_, err = rl.GetRelease(999)
	if err == nil {
		t.Fatal("expected error for out-of-range index")
	}
}

func TestStress_ReleaseLedger_AutoID(t *testing.T) {
	rl := NewReleaseLedger().WithClock(ledgerClock)
	rec, _ := rl.RecordRelease(ReleaseRecord{Version: "v1", TestEvidenceHash: "t", SupplyChainHash: "s"})
	if rec.ReleaseID == "" {
		t.Fatal("expected auto-generated release ID")
	}
}

func TestStress_Ledger_AllTypes(t *testing.T) {
	types := []LedgerType{LedgerTypeRelease, LedgerTypePolicy, LedgerTypeRun, LedgerTypeEvidence}
	for _, lt := range types {
		l := NewLedger(lt).WithClock(ledgerClock)
		l.Append("entry", "author", map[string]interface{}{})
		if l.Type() != lt {
			t.Fatalf("expected type %s, got %s", lt, l.Type())
		}
	}
}

func TestStress_Ledger_ContentHashDiffersPerEntry(t *testing.T) {
	l := NewLedger(LedgerTypeRelease).WithClock(ledgerClock)
	l.Append("release", "a", map[string]interface{}{"v": "1"})
	l.Append("release", "a", map[string]interface{}{"v": "2"})
	e1, _ := l.Get(1)
	e2, _ := l.Get(2)
	if e1.ContentHash == e2.ContentHash {
		t.Fatal("different entries should have different hashes")
	}
}

func TestStress_TypedLedger_GenesisHead(t *testing.T) {
	tl := NewTypedLedger(LedgerPolicy)
	if tl.Head() != "genesis" {
		t.Fatal("expected genesis head for empty typed ledger")
	}
}

func TestStress_ReleaseLedger_PrevReleaseHash(t *testing.T) {
	rl := NewReleaseLedger().WithClock(ledgerClock)
	r1, _ := rl.RecordRelease(ReleaseRecord{Version: "v1", TestEvidenceHash: "t", SupplyChainHash: "s"})
	r2, _ := rl.RecordRelease(ReleaseRecord{Version: "v2", TestEvidenceHash: "t", SupplyChainHash: "s"})
	if r2.PrevReleaseHash != r1.ContentHash {
		t.Fatal("second release should chain to first")
	}
}

func TestStress_ReleaseLedger_ContentHashDeterminism(t *testing.T) {
	rl1 := NewReleaseLedger().WithClock(ledgerClock)
	r1, _ := rl1.RecordRelease(ReleaseRecord{ReleaseID: "r1", Version: "v1", TestEvidenceHash: "t", SupplyChainHash: "s"})
	rl2 := NewReleaseLedger().WithClock(ledgerClock)
	r2, _ := rl2.RecordRelease(ReleaseRecord{ReleaseID: "r1", Version: "v1", TestEvidenceHash: "t", SupplyChainHash: "s"})
	if r1.ContentHash != r2.ContentHash {
		t.Fatal("identical releases should have identical content hashes")
	}
}
