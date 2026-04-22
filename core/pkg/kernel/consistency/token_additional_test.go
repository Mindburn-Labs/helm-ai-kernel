package consistency

import (
	"testing"
	"time"
)

func TestVectorClockMergeExtended(t *testing.T) {
	vc1 := NewVectorClock()
	vc1.Increment("node1")
	vc1.Increment("node1")
	vc1.Increment("node2")

	vc2 := NewVectorClock()
	vc2.Increment("node2")
	vc2.Increment("node2")
	vc2.Increment("node3")

	// Before merge
	if vc1.Get("node3") != 0 {
		t.Error("vc1 should not have node3 before merge")
	}

	// Merge
	vc1.Merge(vc2)

	// After merge - should have max of each
	if vc1.Get("node1") != 2 {
		t.Errorf("node1 = %d, want 2", vc1.Get("node1"))
	}
	if vc1.Get("node2") != 2 {
		t.Errorf("node2 = %d, want 2 (max of 1 and 2)", vc1.Get("node2"))
	}
	if vc1.Get("node3") != 1 {
		t.Errorf("node3 = %d, want 1", vc1.Get("node3"))
	}
}

func TestGSetMergeExtended(t *testing.T) {
	gs1 := NewGSet()
	gs1.Add("a")
	gs1.Add("b")

	gs2 := NewGSet()
	gs2.Add("b")
	gs2.Add("c")

	gs1.Merge(gs2)

	if !gs1.Contains("a") || !gs1.Contains("b") || !gs1.Contains("c") {
		t.Error("GSet merge should produce union")
	}
	if gs1.Size() != 3 {
		t.Errorf("Size = %d, want 3", gs1.Size())
	}
}

func TestLWWRegisterMerge(t *testing.T) {
	r1 := NewLWWRegister()
	r2 := NewLWWRegister()

	earlier := time.Now()
	later := earlier.Add(time.Second)

	r1.Set([]byte("old"), earlier, "node1")
	r2.Set([]byte("new"), later, "node2")

	r1.Merge(r2)

	if string(r1.Get()) != "new" {
		t.Errorf("LWW merge should keep later value, got %q", string(r1.Get()))
	}
}

func TestPNCounterMergeExtended(t *testing.T) {
	pn1 := NewPNCounter()
	pn2 := NewPNCounter()

	pn1.Increment("node1")
	pn1.Increment("node1")
	pn1.Decrement("node1")

	pn2.Increment("node2")
	pn2.Increment("node2")

	pn1.Merge(pn2)

	// pn1: +2-1=1, pn2: +2=2, merged: (+2+2)-(1) = 3
	if pn1.Value() != 3 {
		t.Errorf("PNCounter value = %d, want 3", pn1.Value())
	}
}

func TestGCounterMergeExtended(t *testing.T) {
	gc1 := NewGCounter()
	gc2 := NewGCounter()

	gc1.Increment("node1")
	gc1.Increment("node1")
	gc1.Increment("node2")

	gc2.Increment("node2")
	gc2.Increment("node2")
	gc2.Increment("node3")

	gc1.Merge(gc2)

	// node1: 2, node2: max(1,2)=2, node3: 1 => total: 5
	if gc1.Value() != 5 {
		t.Errorf("GCounter value = %d, want 5", gc1.Value())
	}
}

func TestShardOrderingCheckOrdering(t *testing.T) {
	so := NewShardOrdering()
	so.RegisterShard("shard1")
	so.RegisterShard("shard2")

	// Record operations
	_ = so.RecordOperation("shard1", "node1")

	// Get token from shard1 and merge into shard2's vector clock
	t1, _ := so.GetToken("shard1")
	t2, _ := so.GetToken("shard2")
	t2.VectorClock.Merge(t1.VectorClock)
	t2.VectorClock.Increment("node2")

	// Check ordering
	happensBefore, err := so.CheckOrdering("shard1", "shard2")
	if err != nil {
		t.Fatalf("CheckOrdering error: %v", err)
	}
	if !happensBefore {
		t.Error("shard1 should happen before shard2")
	}
}

func TestShardOrderingCheckOrderingUnknownShard(t *testing.T) {
	so := NewShardOrdering()
	so.RegisterShard("shard1")

	_, err := so.CheckOrdering("shard1", "unknown")
	if err == nil {
		t.Error("Should error for unknown shard")
	}
}

func TestBoundedStalenessStaleness(t *testing.T) {
	bs := NewBoundedStaleness(100 * time.Millisecond)

	// Unknown key
	staleness := bs.Staleness("unknown")
	if staleness <= 100*time.Millisecond {
		t.Error("Unknown key should be definitely stale")
	}

	// Record update
	bs.RecordUpdate("key1")

	// Check staleness immediately
	staleness = bs.Staleness("key1")
	if staleness > 10*time.Millisecond {
		t.Errorf("Just updated key should have low staleness, got %v", staleness)
	}
}

func TestDeserializeVectorClock(t *testing.T) {
	vc := NewVectorClock()
	vc.Increment("node1")
	vc.Increment("node2")

	serialized := SerializeVectorClock(vc)
	deserialized, err := DeserializeVectorClock(serialized)
	if err != nil {
		t.Fatalf("DeserializeVectorClock error: %v", err)
	}

	if deserialized.Get("node1") != 1 || deserialized.Get("node2") != 1 {
		t.Error("Deserialized clock doesn't match original")
	}
}

func TestDeserializeVectorClockInvalid(t *testing.T) {
	_, err := DeserializeVectorClock("invalid-hex")
	if err == nil {
		t.Error("Should error on invalid hex")
	}
}
