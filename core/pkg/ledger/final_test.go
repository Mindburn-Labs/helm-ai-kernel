package ledger

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFinal_LedgerTypeConstants(t *testing.T) {
	types := []LedgerType{LedgerTypeRelease, LedgerTypePolicy, LedgerTypeRun, LedgerTypeEvidence}
	if len(types) != 4 {
		t.Fatal("expected 4 types")
	}
}

func TestFinal_LedgerEntryJSONRoundTrip(t *testing.T) {
	e := LedgerEntry{Sequence: 1, EntryType: "policy_change", Author: "admin"}
	data, _ := json.Marshal(e)
	var got LedgerEntry
	json.Unmarshal(data, &got)
	if got.Sequence != 1 || got.Author != "admin" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_NewLedger(t *testing.T) {
	l := NewLedger(LedgerTypePolicy)
	if l == nil || l.Type() != LedgerTypePolicy {
		t.Fatal("new ledger")
	}
}

func TestFinal_LedgerAppend(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	seq, err := l.Append("run_start", "system", map[string]interface{}{"id": "r1"})
	if err != nil || seq != 1 {
		t.Fatal("append failed")
	}
}

func TestFinal_LedgerGet(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	l.Append("run_start", "system", nil)
	e, err := l.Get(1)
	if err != nil || e.Sequence != 1 {
		t.Fatal("get failed")
	}
}

func TestFinal_LedgerGetOutOfRange(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	_, err := l.Get(0)
	if err == nil {
		t.Fatal("seq 0 should fail")
	}
	_, err = l.Get(1)
	if err == nil {
		t.Fatal("empty ledger get should fail")
	}
}

func TestFinal_LedgerHead(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	if l.Head() != "genesis" {
		t.Fatal("initial head should be genesis")
	}
	l.Append("a", "b", nil)
	if l.Head() == "genesis" {
		t.Fatal("head should change")
	}
}

func TestFinal_LedgerLength(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	l.Append("a", "b", nil)
	l.Append("c", "d", nil)
	if l.Length() != 2 {
		t.Fatal("length mismatch")
	}
}

func TestFinal_LedgerVerifyEmpty(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	ok, _ := l.Verify()
	if !ok {
		t.Fatal("empty ledger should verify")
	}
}

func TestFinal_LedgerVerifyValid(t *testing.T) {
	l := NewLedger(LedgerTypePolicy)
	l.Append("a", "b", nil)
	l.Append("c", "d", nil)
	ok, msg := l.Verify()
	if !ok {
		t.Fatalf("should verify: %s", msg)
	}
}

func TestFinal_LedgerContentHashPrefix(t *testing.T) {
	l := NewLedger(LedgerTypeRun)
	l.Append("a", "b", nil)
	e, _ := l.Get(1)
	if !strings.HasPrefix(e.ContentHash, "sha256:") {
		t.Fatal("missing sha256 prefix")
	}
}

func TestFinal_LedgerWithClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := NewLedger(LedgerTypeRun).WithClock(func() time.Time { return fixed })
	l.Append("a", "b", nil)
	e, _ := l.Get(1)
	if !e.Timestamp.Equal(fixed) {
		t.Fatal("clock not injected")
	}
}

func TestFinal_TypedLedgerAppendAndGet(t *testing.T) {
	tl := NewTypedLedger(LedgerPolicy)
	entry := tl.Append("policy_change", "payload-data")
	if entry.Sequence != 1 {
		t.Fatal("sequence mismatch")
	}
	got, _ := tl.Get(1)
	if got.Payload != "payload-data" {
		t.Fatal("payload mismatch")
	}
}

func TestFinal_TypedLedgerHead(t *testing.T) {
	tl := NewTypedLedger(LedgerRun)
	if tl.Head() != "genesis" {
		t.Fatal("initial head")
	}
	tl.Append("a", "b")
	if tl.Head() == "genesis" {
		t.Fatal("head should change")
	}
}

func TestFinal_TypedLedgerVerify(t *testing.T) {
	tl := NewTypedLedger(LedgerEvidence)
	tl.Append("a", "b")
	tl.Append("c", "d")
	ok, err := tl.Verify()
	if !ok || err != nil {
		t.Fatal("should verify")
	}
}

func TestFinal_TypedLedgerLength(t *testing.T) {
	tl := NewTypedLedger(LedgerPolicy)
	tl.Append("a", "b")
	tl.Append("c", "d")
	if tl.Length() != 2 {
		t.Fatal("length")
	}
}

func TestFinal_TypedLedgerType(t *testing.T) {
	tl := NewTypedLedger(LedgerEvidence)
	if tl.Type() != LedgerEvidence {
		t.Fatal("type mismatch")
	}
}

func TestFinal_TypedLedgerGetOutOfRange(t *testing.T) {
	tl := NewTypedLedger(LedgerRun)
	_, err := tl.Get(1)
	if err == nil {
		t.Fatal("should error")
	}
}

func TestFinal_TypedEntryJSONRoundTrip(t *testing.T) {
	te := TypedEntry{Sequence: 1, LedgerType: LedgerPolicy, Payload: "test"}
	data, _ := json.Marshal(te)
	var got TypedEntry
	json.Unmarshal(data, &got)
	if got.Sequence != 1 || got.Payload != "test" {
		t.Fatal("typed entry round-trip")
	}
}

func TestFinal_TypedLedgerWithClock(t *testing.T) {
	fixed := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	tl := NewTypedLedger(LedgerRun).WithClock(func() time.Time { return fixed })
	entry := tl.Append("a", "b")
	if !entry.Timestamp.Equal(fixed) {
		t.Fatal("clock not injected")
	}
}

func TestFinal_ReleaseLedgerCreate(t *testing.T) {
	rl := NewReleaseLedger()
	if rl == nil || rl.Length() != 0 {
		t.Fatal("new release ledger")
	}
}

func TestFinal_ReleaseLedgerRecordRelease(t *testing.T) {
	rl := NewReleaseLedger()
	rec, err := rl.RecordRelease(ReleaseRecord{Version: "1.0.0"})
	if err != nil || rec == nil {
		t.Fatal("record release")
	}
}

func TestFinal_ReleaseLedgerGetRelease(t *testing.T) {
	rl := NewReleaseLedger()
	rl.RecordRelease(ReleaseRecord{Version: "1.0.0"})
	rec, err := rl.GetRelease(0)
	if err != nil || rec.Version != "1.0.0" {
		t.Fatal("get release")
	}
}

func TestFinal_ReleaseLedgerGetOutOfRange(t *testing.T) {
	rl := NewReleaseLedger()
	_, err := rl.GetRelease(0)
	if err == nil {
		t.Fatal("should error on empty")
	}
}

func TestFinal_ReleaseLedgerVerify(t *testing.T) {
	rl := NewReleaseLedger()
	rl.RecordRelease(ReleaseRecord{Version: "1.0.0"})
	rl.RecordRelease(ReleaseRecord{Version: "1.1.0"})
	ok, _ := rl.Verify()
	if !ok {
		t.Fatal("should verify")
	}
}

func TestFinal_ReleaseLedgerContentHash(t *testing.T) {
	rl := NewReleaseLedger()
	rec, _ := rl.RecordRelease(ReleaseRecord{Version: "1.0.0"})
	if !strings.HasPrefix(rec.ContentHash, "sha256:") {
		t.Fatal("missing sha256 prefix")
	}
}

func TestFinal_ReleaseLedgerWithClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := NewReleaseLedger().WithClock(func() time.Time { return fixed })
	rec, _ := rl.RecordRelease(ReleaseRecord{Version: "1.0.0"})
	if !rec.ReleasedAt.Equal(fixed) {
		t.Fatal("clock not injected")
	}
}

func TestFinal_ReleaseRecordJSONRoundTrip(t *testing.T) {
	rr := ReleaseRecord{ReleaseID: "r1", Version: "1.0.0", PolicyVersion: "p-v1"}
	data, _ := json.Marshal(rr)
	var got ReleaseRecord
	json.Unmarshal(data, &got)
	if got.ReleaseID != "r1" || got.PolicyVersion != "p-v1" {
		t.Fatal("release record round-trip")
	}
}

func TestFinal_ReleaseLedgerPrevHash(t *testing.T) {
	rl := NewReleaseLedger()
	r1, _ := rl.RecordRelease(ReleaseRecord{Version: "1.0.0"})
	r2, _ := rl.RecordRelease(ReleaseRecord{Version: "1.1.0"})
	if r2.PrevReleaseHash != r1.ContentHash {
		t.Fatal("prev hash should chain")
	}
}

func TestFinal_LedgerAliasConstants(t *testing.T) {
	if LedgerPolicy != LedgerTypePolicy || LedgerRun != LedgerTypeRun || LedgerEvidence != LedgerTypeEvidence {
		t.Fatal("alias mismatch")
	}
}
