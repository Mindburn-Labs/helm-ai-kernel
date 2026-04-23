package consistency

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVectorClock(t *testing.T) {
	vc := NewVectorClock()
	require.NotNil(t, vc)

	vc.Increment("node1")
	require.Equal(t, uint64(1), vc.Get("node1"))

	vc.Increment("node1")
	require.Equal(t, uint64(2), vc.Get("node1"))

	vc.Increment("node2")
	require.Equal(t, uint64(1), vc.Get("node2"))
}

func TestVectorClockMerge(t *testing.T) {
	vc1 := NewVectorClock()
	vc1.Increment("node1")
	vc1.Increment("node1")

	vc2 := NewVectorClock()
	vc2.Increment("node2")
	vc2.Increment("node2")
	vc2.Increment("node2")

	vc1.Merge(vc2)

	require.Equal(t, uint64(2), vc1.Get("node1"))
	require.Equal(t, uint64(3), vc1.Get("node2"))
}

func TestVectorClockCompare(t *testing.T) {
	vc1 := NewVectorClock()
	vc1.clocks["node1"] = 1

	vc2 := NewVectorClock()
	vc2.clocks["node1"] = 2

	require.Equal(t, -1, vc1.Compare(vc2)) // vc1 < vc2
	require.Equal(t, 1, vc2.Compare(vc1))  // vc2 > vc1
	require.True(t, vc1.HappensBefore(vc2))
}

func TestVectorClockConcurrent(t *testing.T) {
	vc1 := NewVectorClock()
	vc1.clocks["node1"] = 2
	vc1.clocks["node2"] = 1

	vc2 := NewVectorClock()
	vc2.clocks["node1"] = 1
	vc2.clocks["node2"] = 2

	require.Equal(t, 0, vc1.Compare(vc2)) // Concurrent
	require.True(t, vc1.IsConcurrent(vc2))
}

func TestVectorClockClone(t *testing.T) {
	vc := NewVectorClock()
	vc.Increment("node1")

	clone := vc.Clone()
	require.Equal(t, vc.Get("node1"), clone.Get("node1"))

	clone.Increment("node1")
	require.NotEqual(t, vc.Get("node1"), clone.Get("node1"))
}

func TestConsistencyToken(t *testing.T) {
	token := NewConsistencyToken("shard1")
	require.Equal(t, "shard1", token.ShardID)
	require.NotNil(t, token.VectorClock)

	token.Advance("node1")
	require.Equal(t, uint64(1), token.SequenceNum)
	require.Equal(t, uint64(1), token.VectorClock.Get("node1"))
}

func TestConsistencyTokenStaleness(t *testing.T) {
	token := NewConsistencyToken("shard1")

	ref := time.Now().Add(-2 * time.Second)
	token.UpdateStaleness(ref)

	require.True(t, token.Staleness > 0)
	require.False(t, token.IsStale(10*time.Second))
	require.True(t, token.IsStale(1*time.Second))
}

func TestGCounter(t *testing.T) {
	gc := NewGCounter()
	require.Equal(t, uint64(0), gc.Value())

	gc.Increment("node1")
	gc.Increment("node1")
	gc.Increment("node2")

	require.Equal(t, uint64(3), gc.Value())
}

func TestGCounterMerge(t *testing.T) {
	gc1 := NewGCounter()
	gc1.Increment("node1")
	gc1.Increment("node1")

	gc2 := NewGCounter()
	gc2.Increment("node1")
	gc2.Increment("node2")
	gc2.Increment("node2")

	gc1.Merge(gc2)

	// node1: max(2, 1) = 2
	// node2: max(0, 2) = 2
	require.Equal(t, uint64(4), gc1.Value())
}

func TestPNCounter(t *testing.T) {
	pn := NewPNCounter()

	pn.Increment("node1")
	pn.Increment("node1")
	pn.Increment("node1")
	pn.Decrement("node2")

	require.Equal(t, int64(2), pn.Value())
}

func TestPNCounterMerge(t *testing.T) {
	pn1 := NewPNCounter()
	pn1.Increment("node1")

	pn2 := NewPNCounter()
	pn2.Decrement("node2")

	pn1.Merge(pn2)
	require.Equal(t, int64(0), pn1.Value())
}

func TestLWWRegister(t *testing.T) {
	reg := NewLWWRegister()

	t1 := time.Now()
	t2 := t1.Add(time.Second)

	reg.Set([]byte("first"), t1, "node1")
	require.Equal(t, []byte("first"), reg.Get())

	reg.Set([]byte("second"), t2, "node2")
	require.Equal(t, []byte("second"), reg.Get())

	// Older timestamp should not overwrite
	reg.Set([]byte("old"), t1, "node3")
	require.Equal(t, []byte("second"), reg.Get())
}

func TestLWWRegisterTieBreaker(t *testing.T) {
	reg := NewLWWRegister()
	ts := time.Now()

	reg.Set([]byte("a"), ts, "node_a")
	reg.Set([]byte("b"), ts, "node_b") // node_b > node_a

	require.Equal(t, []byte("b"), reg.Get())
}

func TestGSet(t *testing.T) {
	gs := NewGSet()

	gs.Add("apple")
	gs.Add("banana")
	gs.Add("apple") // Duplicate

	require.Equal(t, 2, gs.Size())
	require.True(t, gs.Contains("apple"))
	require.True(t, gs.Contains("banana"))
	require.False(t, gs.Contains("cherry"))
}

func TestGSetMerge(t *testing.T) {
	gs1 := NewGSet()
	gs1.Add("a")
	gs1.Add("b")

	gs2 := NewGSet()
	gs2.Add("b")
	gs2.Add("c")

	gs1.Merge(gs2)

	require.Equal(t, 3, gs1.Size())
	elements := gs1.Elements()
	require.Equal(t, []string{"a", "b", "c"}, elements)
}

func TestShardOrdering(t *testing.T) {
	so := NewShardOrdering()

	so.RegisterShard("shard1")
	so.RegisterShard("shard2")

	token, err := so.GetToken("shard1")
	require.NoError(t, err)
	require.NotNil(t, token)

	_, err = so.GetToken("unknown")
	require.Error(t, err)
}

func TestShardOrderingOperations(t *testing.T) {
	so := NewShardOrdering()
	so.RegisterShard("shard1")

	err := so.RecordOperation("shard1", "node1")
	require.NoError(t, err)

	token, _ := so.GetToken("shard1")
	require.Equal(t, uint64(1), token.SequenceNum)
}

func TestBoundedStaleness(t *testing.T) {
	bs := NewBoundedStaleness(100 * time.Millisecond)

	require.True(t, bs.IsStale("key1")) // Never updated

	bs.RecordUpdate("key1")
	require.False(t, bs.IsStale("key1"))

	time.Sleep(150 * time.Millisecond)
	require.True(t, bs.IsStale("key1"))
}

func TestBoundedStalenessRequiresFresh(t *testing.T) {
	bs := NewBoundedStaleness(50 * time.Millisecond)

	bs.RecordUpdate("key1")
	bs.RecordUpdate("key2")

	time.Sleep(60 * time.Millisecond)

	stale := bs.RequiresFresh()
	require.Len(t, stale, 2)
}

func TestSerializeVectorClock(t *testing.T) {
	vc := NewVectorClock()
	vc.clocks["node1"] = 5
	vc.clocks["node2"] = 3

	serialized := SerializeVectorClock(vc)
	require.NotEmpty(t, serialized)

	deserialized, err := DeserializeVectorClock(serialized)
	require.NoError(t, err)
	require.Equal(t, uint64(5), deserialized.Get("node1"))
	require.Equal(t, uint64(3), deserialized.Get("node2"))
}

func TestVectorClockBytes(t *testing.T) {
	vc := NewVectorClock()
	vc.Increment("node1")

	bytes := vc.Bytes()
	require.NotEmpty(t, bytes)
}
