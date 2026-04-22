package ledger

import (
	"testing"
	"time"
)

func TestTypedLedgerAppend(t *testing.T) {
	l := NewTypedLedger(LedgerPolicy).WithClock(func() time.Time { return time.Unix(0, 0).UTC() })
	entry := l.Append("policy_change", `{"id":"p1","action":"update"}`)
	if entry.Sequence != 1 {
		t.Fatalf("expected seq 1, got %d", entry.Sequence)
	}
	if entry.PrevHash != "genesis" {
		t.Fatal("first entry prev hash should be genesis")
	}
	if l.Head() == "" {
		t.Fatal("expected non-empty head hash")
	}
}

func TestTypedLedgerHashChain(t *testing.T) {
	l := NewTypedLedger(LedgerRun)
	e1 := l.Append("run_start", "payload1")
	e2 := l.Append("run_end", "payload2")

	if e2.PrevHash != e1.ContentHash {
		t.Fatal("hash chain broken: e2.PrevHash != e1.ContentHash")
	}
}

func TestTypedLedgerVerify(t *testing.T) {
	l := NewTypedLedger(LedgerEvidence)
	l.Append("commit", "ev1")
	l.Append("commit", "ev2")
	l.Append("commit", "ev3")

	ok, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected valid chain")
	}
}

func TestTypedLedgerGet(t *testing.T) {
	l := NewTypedLedger(LedgerPolicy)
	l.Append("change", "p1")

	e, err := l.Get(1)
	if err != nil {
		t.Fatal(err)
	}
	if e.Payload != "p1" {
		t.Fatal("payload mismatch")
	}
}

func TestTypedLedgerGetOutOfRange(t *testing.T) {
	l := NewTypedLedger(LedgerPolicy)
	_, err := l.Get(1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTypedLedgerLength(t *testing.T) {
	l := NewTypedLedger(LedgerRun)
	l.Append("a", "1")
	l.Append("b", "2")

	if l.Length() != 2 {
		t.Fatalf("expected 2, got %d", l.Length())
	}
}

func TestTypedLedgerType(t *testing.T) {
	l := NewTypedLedger(LedgerEvidence)
	if l.Type() != LedgerEvidence {
		t.Fatal("wrong type")
	}
}
