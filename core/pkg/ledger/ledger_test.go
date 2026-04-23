package ledger

import (
	"testing"
)

func TestLedgerAppend(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	seq, err := l.Append("action", "system", map[string]interface{}{"event": "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Fatalf("expected seq 1, got %d", seq)
	}
	if l.Length() != 1 {
		t.Fatalf("expected length 1, got %d", l.Length())
	}
}

func TestLedgerChainIntegrity(t *testing.T) {
	l := NewLedger(LedgerTypePolicy)
	l.Append("create", "admin", map[string]interface{}{"policy": "p1"})
	l.Append("update", "admin", map[string]interface{}{"policy": "p1", "version": "2"})
	l.Append("update", "admin", map[string]interface{}{"policy": "p1", "version": "3"})

	ok, reason := l.Verify()
	if !ok {
		t.Fatalf("expected valid chain, got: %s", reason)
	}
}

func TestLedgerGet(t *testing.T) {
	l := NewLedger(LedgerTypeEvidence)
	l.Append("receipt", "executor", map[string]interface{}{"hash": "abc"})

	entry, err := l.Get(1)
	if err != nil {
		t.Fatal(err)
	}
	if entry.EntryType != "receipt" {
		t.Fatalf("expected receipt, got %s", entry.EntryType)
	}
}

func TestLedgerGetNotFound(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	_, err := l.Get(99)
	if err == nil {
		t.Fatal("expected error for missing entry")
	}
}

func TestLedgerHead(t *testing.T) {
	l := NewLedger(LedgerTypeRelease)
	if l.Head() != "genesis" {
		t.Fatal("expected genesis head")
	}
	l.Append("release", "ci", map[string]interface{}{"v": "1.0"})
	if l.Head() == "genesis" {
		t.Fatal("head should change after append")
	}
}

func TestLedgerHashChaining(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	l.Append("a", "sys", map[string]interface{}{"x": 1})
	l.Append("b", "sys", map[string]interface{}{"x": 2})

	e1, _ := l.Get(1)
	e2, _ := l.Get(2)
	if e2.PrevHash != e1.ContentHash {
		t.Fatal("second entry prev_hash should match first content_hash")
	}
}

func TestLedgerType(t *testing.T) {
	l := NewLedger(LedgerTypeRelease)
	if l.Type() != LedgerTypeRelease {
		t.Fatalf("expected RELEASE, got %s", l.Type())
	}
}

func TestLedgerDeterministicHash(t *testing.T) {
	l1 := NewLedger(LedgerTypeRun)
	l1.Append("a", "sys", map[string]interface{}{"x": 1})
	l2 := NewLedger(LedgerTypeRun)
	l2.Append("a", "sys", map[string]interface{}{"x": 1})

	e1, _ := l1.Get(1)
	e2, _ := l2.Get(1)
	if e1.ContentHash != e2.ContentHash {
		t.Fatal("same input should produce same hash")
	}
}
