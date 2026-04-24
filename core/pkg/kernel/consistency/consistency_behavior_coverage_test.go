package consistency

import (
	"testing"
	"time"
)

// ── VectorClock ─────────────────────────────────────────────────

func TestVectorClock_IncrementAndGet(t *testing.T) {
	vc := NewVectorClock()
	vc.Increment("node-1")
	if vc.Get("node-1") != 1 {
		t.Errorf("expected 1, got %d", vc.Get("node-1"))
	}
}

func TestVectorClock_Merge(t *testing.T) {
	a := NewVectorClock()
	a.Increment("n1")
	a.Increment("n1")
	b := NewVectorClock()
	b.Increment("n1")
	b.Increment("n2")
	a.Merge(b)
	if a.Get("n1") != 2 {
		t.Errorf("expected max(2,1)=2, got %d", a.Get("n1"))
	}
	if a.Get("n2") != 1 {
		t.Errorf("expected n2=1, got %d", a.Get("n2"))
	}
}

func TestVectorClock_HappensBefore(t *testing.T) {
	a := NewVectorClock()
	a.Increment("n1")
	b := a.Clone()
	b.Increment("n1")
	if !a.HappensBefore(b) {
		t.Error("a should happen-before b")
	}
}

func TestVectorClock_Concurrent(t *testing.T) {
	a := NewVectorClock()
	a.Increment("n1")
	b := NewVectorClock()
	b.Increment("n2")
	if !a.IsConcurrent(b) {
		t.Error("a and b should be concurrent")
	}
}

func TestVectorClock_Clone(t *testing.T) {
	vc := NewVectorClock()
	vc.Increment("n1")
	clone := vc.Clone()
	clone.Increment("n1")
	if vc.Get("n1") != 1 {
		t.Error("clone should not affect original")
	}
}

func TestVectorClock_SerializeDeserialize(t *testing.T) {
	vc := NewVectorClock()
	vc.Increment("node-a")
	vc.Increment("node-b")
	serialized := SerializeVectorClock(vc)
	restored, err := DeserializeVectorClock(serialized)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if restored.Get("node-a") != 1 || restored.Get("node-b") != 1 {
		t.Error("deserialized clock should match original")
	}
}

// ── ConsistencyToken ────────────────────────────────────────────

func TestConsistencyToken_Advance(t *testing.T) {
	ct := NewConsistencyToken("shard-1")
	ct.Advance("node-x")
	if ct.SequenceNum != 1 {
		t.Errorf("expected seq 1, got %d", ct.SequenceNum)
	}
	if ct.VectorClock.Get("node-x") != 1 {
		t.Error("vector clock should be incremented")
	}
}

func TestConsistencyToken_Staleness(t *testing.T) {
	ct := NewConsistencyToken("shard-1")
	ct.UpdateStaleness(time.Now().Add(-5 * time.Second))
	if !ct.IsStale(1 * time.Second) {
		t.Error("should be stale when staleness exceeds bound")
	}
	if ct.IsStale(10 * time.Second) {
		t.Error("should not be stale when within bound")
	}
}

// ── GCounter ────────────────────────────────────────────────────

func TestGCounter_IncrementAndValue(t *testing.T) {
	gc := NewGCounter()
	gc.Increment("a")
	gc.Increment("a")
	gc.Increment("b")
	if gc.Value() != 3 {
		t.Errorf("expected 3, got %d", gc.Value())
	}
}

// ── PNCounter ───────────────────────────────────────────────────

func TestPNCounter_IncrementDecrement(t *testing.T) {
	pn := NewPNCounter()
	pn.Increment("a")
	pn.Increment("a")
	pn.Decrement("a")
	if pn.Value() != 1 {
		t.Errorf("expected 1, got %d", pn.Value())
	}
}

// ── LWWRegister ─────────────────────────────────────────────────

func TestLWWRegister_SetAndGet(t *testing.T) {
	r := NewLWWRegister()
	now := time.Now()
	r.Set([]byte("first"), now, "n1")
	r.Set([]byte("second"), now.Add(time.Second), "n2")
	if string(r.Get()) != "second" {
		t.Errorf("expected second, got %s", string(r.Get()))
	}
}

func TestLWWRegister_OlderWriteIgnored(t *testing.T) {
	r := NewLWWRegister()
	now := time.Now()
	r.Set([]byte("newer"), now.Add(time.Second), "n1")
	ok := r.Set([]byte("older"), now, "n2")
	if ok {
		t.Error("older write should be rejected")
	}
}

// ── GSet ────────────────────────────────────────────────────────

func TestGSet_AddContainsElements(t *testing.T) {
	gs := NewGSet()
	gs.Add("x")
	gs.Add("y")
	if !gs.Contains("x") {
		t.Error("should contain x")
	}
	if gs.Size() != 2 {
		t.Errorf("expected size 2, got %d", gs.Size())
	}
}

// ── ShardOrdering ───────────────────────────────────────────────

func TestShardOrdering_RegisterAndRecord(t *testing.T) {
	so := NewShardOrdering()
	so.RegisterShard("s1")
	err := so.RecordOperation("s1", "node-a")
	if err != nil {
		t.Fatalf("RecordOperation: %v", err)
	}
}

func TestShardOrdering_UnknownShard(t *testing.T) {
	so := NewShardOrdering()
	_, err := so.GetToken("missing")
	if err == nil {
		t.Error("should error for unknown shard")
	}
}

// ── BoundedStaleness ────────────────────────────────────────────

func TestBoundedStaleness_FreshAndStale(t *testing.T) {
	bs := NewBoundedStaleness(100 * time.Millisecond)
	bs.RecordUpdate("key1")
	if bs.IsStale("key1") {
		t.Error("recently updated key should not be stale")
	}
	if !bs.IsStale("unknown") {
		t.Error("never-updated key should be stale")
	}
}
