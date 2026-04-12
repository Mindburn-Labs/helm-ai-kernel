package ledger

import (
	"testing"
	"time"
)

func TestLedgerNewHasGenesisHead(t *testing.T) {
	l := NewLedger(LedgerTypeRelease)
	if l.Length() != 0 || l.Head() != "genesis" || l.Type() != LedgerTypeRelease {
		t.Fatal("new ledger should be empty with genesis head and correct type")
	}
}

func TestLedgerAppendReturnsSequence(t *testing.T) {
	l := NewLedger(LedgerTypePolicy)
	seq, err := l.Append("policy_change", "admin", map[string]interface{}{"rule": "deny-all"})
	if err != nil || seq != 1 {
		t.Fatalf("expected seq 1, got %d, err=%v", seq, err)
	}
	if l.Length() != 1 || l.Head() == "genesis" {
		t.Fatal("head should advance after append")
	}
}

func TestLedgerGetReturnsEntry(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	l.Append("run_start", "engine", nil)
	entry, err := l.Get(1)
	if err != nil || entry.EntryType != "run_start" {
		t.Fatalf("get seq 1 failed: %v", err)
	}
}

func TestLedgerGetZeroAndBeyondFail(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	if _, err := l.Get(0); err == nil {
		t.Fatal("expected error for seq 0")
	}
	if _, err := l.Get(99); err == nil {
		t.Fatal("expected error for nonexistent seq")
	}
}

func TestLedgerVerifyMultiEntryChain(t *testing.T) {
	l := NewLedger(LedgerTypeEvidence)
	l.Append("commit", "agent", map[string]interface{}{"hash": "abc"})
	l.Append("commit", "agent", map[string]interface{}{"hash": "def"})
	ok, msg := l.Verify()
	if !ok {
		t.Fatalf("chain should verify: %s", msg)
	}
}

func TestLedgerClockOverride(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := NewLedger(LedgerTypePolicy).WithClock(func() time.Time { return fixed })
	l.Append("test", "author", nil)
	entry, _ := l.Get(1)
	if !entry.Timestamp.Equal(fixed) {
		t.Fatalf("expected fixed time, got %v", entry.Timestamp)
	}
}

func TestLedgerPrevHashLinksEntries(t *testing.T) {
	l := NewLedger(LedgerTypeRelease)
	l.Append("v1", "ci", nil)
	e1, _ := l.Get(1)
	l.Append("v2", "ci", nil)
	e2, _ := l.Get(2)
	if e2.PrevHash != e1.ContentHash {
		t.Fatal("entry 2 prev_hash should equal entry 1 content_hash")
	}
}

func TestLedgerAuthorPreserved(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	l.Append("deploy", "ci-bot", nil)
	e, _ := l.Get(1)
	if e.Author != "ci-bot" {
		t.Fatalf("expected author ci-bot, got %s", e.Author)
	}
}

// --- TypedLedger Comprehensive Tests ---

func TestTypedLedgerAppendSetsFields(t *testing.T) {
	tl := NewTypedLedger(LedgerPolicy)
	entry := tl.Append("policy_change", `{"action":"deny"}`)
	if entry.Sequence != 1 || entry.LedgerType != LedgerPolicy || entry.Payload != `{"action":"deny"}` {
		t.Fatal("typed ledger append did not set fields correctly")
	}
}

func TestTypedLedgerVerifyMultiEntry(t *testing.T) {
	tl := NewTypedLedger(LedgerRun)
	tl.Append("run_start", "data1")
	tl.Append("run_end", "data2")
	tl.Append("run_cleanup", "data3")
	ok, err := tl.Verify()
	if !ok || err != nil {
		t.Fatalf("typed ledger verify failed: %v", err)
	}
}

func TestTypedLedgerGetBeyondLengthFails(t *testing.T) {
	tl := NewTypedLedger(LedgerEvidence)
	if _, err := tl.Get(1); err == nil {
		t.Fatal("expected error for out of range")
	}
}

func TestTypedLedgerHeadChangesOnAppend(t *testing.T) {
	tl := NewTypedLedger(LedgerPolicy)
	h1 := tl.Head()
	tl.Append("change", "payload")
	h2 := tl.Head()
	if h1 == h2 {
		t.Fatal("head should change after append")
	}
}

func TestTypedLedgerWithClockOverride(t *testing.T) {
	fixed := time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC)
	tl := NewTypedLedger(LedgerRun).WithClock(func() time.Time { return fixed })
	tl.Append("start", "p")
	e, _ := tl.Get(1)
	if !e.Timestamp.Equal(fixed) {
		t.Fatalf("expected fixed time, got %v", e.Timestamp)
	}
}

// --- ReleaseLedger Comprehensive Tests ---

func TestReleaseLedgerRecordSetsHash(t *testing.T) {
	rl := NewReleaseLedger()
	rec, err := rl.RecordRelease(ReleaseRecord{Version: "0.1.0", TestEvidenceHash: "h1", SupplyChainHash: "s1"})
	if err != nil || rec.ContentHash == "" || rl.Length() != 1 {
		t.Fatalf("record release failed: %v", err)
	}
}

func TestReleaseLedgerAutoAssignsID(t *testing.T) {
	rl := NewReleaseLedger()
	rec, _ := rl.RecordRelease(ReleaseRecord{Version: "0.1.0"})
	if rec.ReleaseID == "" {
		t.Fatal("release ID should be auto-assigned")
	}
}

func TestReleaseLedgerGetReleaseByIndex(t *testing.T) {
	rl := NewReleaseLedger()
	rl.RecordRelease(ReleaseRecord{Version: "0.1.0"})
	got, err := rl.GetRelease(0)
	if err != nil || got.Version != "0.1.0" {
		t.Fatalf("get release failed: %v", err)
	}
}

func TestReleaseLedgerGetNegativeIndexFails(t *testing.T) {
	rl := NewReleaseLedger()
	rl.RecordRelease(ReleaseRecord{Version: "0.1.0"})
	if _, err := rl.GetRelease(-1); err == nil {
		t.Fatal("expected error for negative index")
	}
}

func TestReleaseLedgerVerifyChain(t *testing.T) {
	rl := NewReleaseLedger()
	rl.RecordRelease(ReleaseRecord{Version: "0.1.0", TestEvidenceHash: "t1", SupplyChainHash: "s1"})
	rl.RecordRelease(ReleaseRecord{Version: "0.2.0", TestEvidenceHash: "t2", SupplyChainHash: "s2"})
	ok, msg := rl.Verify()
	if !ok {
		t.Fatalf("release chain should verify: %s", msg)
	}
}
