// Package consistency implements causal consistency primitives for HELM.
//
// Features:
// - Vector clocks for causal ordering
// - Conflict-free replicated data types (CRDTs)
// - Cross-shard ordering guarantees
// - Bounded staleness enforcement
package consistency

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// NodeID represents a unique node identifier.
type NodeID string

// VectorClock implements Lamport-style vector timestamps for causal ordering.
type VectorClock struct {
	mu     sync.RWMutex
	clocks map[NodeID]uint64
}

// NewVectorClock creates a new vector clock.
func NewVectorClock() *VectorClock {
	return &VectorClock{
		clocks: make(map[NodeID]uint64),
	}
}

// Increment increments the clock for a specific node.
func (vc *VectorClock) Increment(nodeID NodeID) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.clocks[nodeID]++
}

// Get returns the current timestamp for a node.
func (vc *VectorClock) Get(nodeID NodeID) uint64 {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return vc.clocks[nodeID]
}

// Merge merges another vector clock into this one (max of each component).
func (vc *VectorClock) Merge(other *VectorClock) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	other.mu.RLock()
	defer other.mu.RUnlock()

	for nodeID, ts := range other.clocks {
		if vc.clocks[nodeID] < ts {
			vc.clocks[nodeID] = ts
		}
	}
}

// Compare returns ordering relationship between two vector clocks.
// Returns: -1 if vc < other, 0 if concurrent, 1 if vc > other
func (vc *VectorClock) Compare(other *VectorClock) int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	other.mu.RLock()
	defer other.mu.RUnlock()

	allNodes := make(map[NodeID]struct{})
	for n := range vc.clocks {
		allNodes[n] = struct{}{}
	}
	for n := range other.clocks {
		allNodes[n] = struct{}{}
	}

	hasLess := false
	hasGreater := false

	for n := range allNodes {
		vcVal := vc.clocks[n]
		otherVal := other.clocks[n]

		if vcVal < otherVal {
			hasLess = true
		}
		if vcVal > otherVal {
			hasGreater = true
		}
	}

	if hasLess && !hasGreater {
		return -1
	}
	if hasGreater && !hasLess {
		return 1
	}
	return 0 // Concurrent
}

// HappensBefore returns true if vc happens-before other.
func (vc *VectorClock) HappensBefore(other *VectorClock) bool {
	return vc.Compare(other) == -1
}

// IsConcurrent returns true if the clocks are concurrent.
func (vc *VectorClock) IsConcurrent(other *VectorClock) bool {
	return vc.Compare(other) == 0
}

// Bytes returns binary representation.
func (vc *VectorClock) Bytes() []byte {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	data, _ := json.Marshal(vc.clocks)
	return data
}

// Clone creates a deep copy of the vector clock.
func (vc *VectorClock) Clone() *VectorClock {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	newVC := NewVectorClock()
	for n, t := range vc.clocks {
		newVC.clocks[n] = t
	}
	return newVC
}

// ---- Consistency Token ----

// ConsistencyToken encapsulates causality information for ordering.
type ConsistencyToken struct {
	VectorClock *VectorClock  `json:"vector_clock"`
	ShardID     string        `json:"shard_id"`
	SequenceNum uint64        `json:"sequence_num"`
	Timestamp   time.Time     `json:"timestamp"`
	Staleness   time.Duration `json:"staleness"`
}

// NewConsistencyToken creates a new token for a shard.
func NewConsistencyToken(shardID string) *ConsistencyToken {
	return &ConsistencyToken{
		VectorClock: NewVectorClock(),
		ShardID:     shardID,
		Timestamp:   time.Now(),
	}
}

// Advance increments the token for a node operation.
func (ct *ConsistencyToken) Advance(nodeID NodeID) {
	ct.VectorClock.Increment(nodeID)
	ct.SequenceNum++
	ct.Timestamp = time.Now()
}

// UpdateStaleness calculates staleness from a reference time.
func (ct *ConsistencyToken) UpdateStaleness(reference time.Time) {
	ct.Staleness = time.Since(reference)
}

// IsStale returns true if staleness exceeds the bound.
func (ct *ConsistencyToken) IsStale(bound time.Duration) bool {
	return ct.Staleness > bound
}

// ---- GCounter CRDT ----

// GCounter is a grow-only counter CRDT.
type GCounter struct {
	mu     sync.RWMutex
	counts map[NodeID]uint64
}

// NewGCounter creates a new grow-only counter.
func NewGCounter() *GCounter {
	return &GCounter{
		counts: make(map[NodeID]uint64),
	}
}

// Increment increments the counter for a node.
func (gc *GCounter) Increment(nodeID NodeID) {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	gc.counts[nodeID]++
}

// Value returns the total counter value.
func (gc *GCounter) Value() uint64 {
	gc.mu.RLock()
	defer gc.mu.RUnlock()

	var total uint64
	for _, c := range gc.counts {
		total += c
	}
	return total
}

// Merge merges another GCounter (max of each node).
func (gc *GCounter) Merge(other *GCounter) {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	other.mu.RLock()
	defer other.mu.RUnlock()

	for n, c := range other.counts {
		if gc.counts[n] < c {
			gc.counts[n] = c
		}
	}
}

// ---- PNCounter CRDT ----

// PNCounter is a positive-negative counter CRDT.
type PNCounter struct {
	positive *GCounter
	negative *GCounter
}

// NewPNCounter creates a new positive-negative counter.
func NewPNCounter() *PNCounter {
	return &PNCounter{
		positive: NewGCounter(),
		negative: NewGCounter(),
	}
}

// Increment adds to the counter.
func (pn *PNCounter) Increment(nodeID NodeID) {
	pn.positive.Increment(nodeID)
}

// Decrement subtracts from the counter.
func (pn *PNCounter) Decrement(nodeID NodeID) {
	pn.negative.Increment(nodeID)
}

// Value returns the counter value (positive - negative).
func (pn *PNCounter) Value() int64 {
	return int64(pn.positive.Value()) - int64(pn.negative.Value()) //nolint:gosec // Token logic
}

// Merge merges another PNCounter.
func (pn *PNCounter) Merge(other *PNCounter) {
	pn.positive.Merge(other.positive)
	pn.negative.Merge(other.negative)
}

// ---- LWWRegister CRDT ----

// LWWRegister is a last-writer-wins register.
type LWWRegister struct {
	mu        sync.RWMutex
	value     []byte
	timestamp time.Time
	nodeID    NodeID
}

// NewLWWRegister creates a new LWW register.
func NewLWWRegister() *LWWRegister {
	return &LWWRegister{}
}

// Set updates the register if the timestamp is newer.
func (r *LWWRegister) Set(value []byte, timestamp time.Time, nodeID NodeID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if timestamp.After(r.timestamp) ||
		(timestamp.Equal(r.timestamp) && string(nodeID) > string(r.nodeID)) {
		r.value = value
		r.timestamp = timestamp
		r.nodeID = nodeID
		return true
	}
	return false
}

// Get returns the current value.
func (r *LWWRegister) Get() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.value
}

// Merge merges another register (keeps latest).
func (r *LWWRegister) Merge(other *LWWRegister) {
	other.mu.RLock()
	v, t, n := other.value, other.timestamp, other.nodeID
	other.mu.RUnlock()

	r.Set(v, t, n)
}

// ---- GSet CRDT ----

// GSet is a grow-only set CRDT.
type GSet struct {
	mu       sync.RWMutex
	elements map[string]struct{}
}

// NewGSet creates a new grow-only set.
func NewGSet() *GSet {
	return &GSet{
		elements: make(map[string]struct{}),
	}
}

// Add adds an element to the set.
func (gs *GSet) Add(element string) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.elements[element] = struct{}{}
}

// Contains returns true if the element is in the set.
func (gs *GSet) Contains(element string) bool {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	_, ok := gs.elements[element]
	return ok
}

// Elements returns all elements.
func (gs *GSet) Elements() []string {
	gs.mu.RLock()
	defer gs.mu.RUnlock()

	result := make([]string, 0, len(gs.elements))
	for e := range gs.elements {
		result = append(result, e)
	}
	sort.Strings(result)
	return result
}

// Merge merges another GSet (union).
func (gs *GSet) Merge(other *GSet) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	other.mu.RLock()
	defer other.mu.RUnlock()

	for e := range other.elements {
		gs.elements[e] = struct{}{}
	}
}

// Size returns the set size.
func (gs *GSet) Size() int {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	return len(gs.elements)
}

// ---- Cross-Shard Ordering ----

// ShardOrdering manages cross-shard ordering guarantees.
type ShardOrdering struct {
	mu       sync.RWMutex
	shards   map[string]*ConsistencyToken
	ordering []string
}

// NewShardOrdering creates a shard ordering manager.
func NewShardOrdering() *ShardOrdering {
	return &ShardOrdering{
		shards: make(map[string]*ConsistencyToken),
	}
}

// RegisterShard registers a new shard.
func (so *ShardOrdering) RegisterShard(shardID string) {
	so.mu.Lock()
	defer so.mu.Unlock()

	if _, exists := so.shards[shardID]; !exists {
		so.shards[shardID] = NewConsistencyToken(shardID)
		so.ordering = append(so.ordering, shardID)
	}
}

// GetToken returns the token for a shard.
func (so *ShardOrdering) GetToken(shardID string) (*ConsistencyToken, error) {
	so.mu.RLock()
	defer so.mu.RUnlock()

	token, exists := so.shards[shardID]
	if !exists {
		return nil, fmt.Errorf("unknown shard: %s", shardID)
	}
	return token, nil
}

// RecordOperation records an operation on a shard.
func (so *ShardOrdering) RecordOperation(shardID string, nodeID NodeID) error {
	so.mu.Lock()
	defer so.mu.Unlock()

	token, exists := so.shards[shardID]
	if !exists {
		return fmt.Errorf("unknown shard: %s", shardID)
	}

	token.Advance(nodeID)
	return nil
}

// CheckOrdering returns true if shard1 -> shard2 is causally valid.
func (so *ShardOrdering) CheckOrdering(shard1, shard2 string) (bool, error) {
	so.mu.RLock()
	defer so.mu.RUnlock()

	t1, ok1 := so.shards[shard1]
	t2, ok2 := so.shards[shard2]

	if !ok1 || !ok2 {
		return false, fmt.Errorf("unknown shard(s)")
	}

	return t1.VectorClock.HappensBefore(t2.VectorClock), nil
}

// ---- Bounded Staleness ----

// BoundedStaleness enforces staleness bounds.
type BoundedStaleness struct {
	mu          sync.RWMutex
	bound       time.Duration
	lastUpdates map[string]time.Time
}

// NewBoundedStaleness creates a staleness enforcer.
func NewBoundedStaleness(bound time.Duration) *BoundedStaleness {
	return &BoundedStaleness{
		bound:       bound,
		lastUpdates: make(map[string]time.Time),
	}
}

// RecordUpdate records an update for a key.
func (bs *BoundedStaleness) RecordUpdate(key string) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.lastUpdates[key] = time.Now()
}

// IsStale returns true if the key is stale.
func (bs *BoundedStaleness) IsStale(key string) bool {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	lastUpdate, exists := bs.lastUpdates[key]
	if !exists {
		return true // Never updated = stale
	}
	return time.Since(lastUpdate) > bs.bound
}

// Staleness returns the staleness duration for a key.
func (bs *BoundedStaleness) Staleness(key string) time.Duration {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	lastUpdate, exists := bs.lastUpdates[key]
	if !exists {
		return bs.bound + time.Second // Definitely stale
	}
	return time.Since(lastUpdate)
}

// RequiresFresh returns keys that need refreshing.
func (bs *BoundedStaleness) RequiresFresh() []string {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	var stale []string
	for key, lastUpdate := range bs.lastUpdates {
		if time.Since(lastUpdate) > bs.bound {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	return stale
}

// ---- Serialization Helpers ----

// SerializeVectorClock serializes a vector clock to hex.
func SerializeVectorClock(vc *VectorClock) string {
	return hex.EncodeToString(vc.Bytes())
}

// DeserializeVectorClock deserializes a vector clock from hex.
func DeserializeVectorClock(data string) (*VectorClock, error) {
	bytes, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}

	vc := NewVectorClock()
	if err := json.Unmarshal(bytes, &vc.clocks); err != nil {
		return nil, err
	}
	return vc, nil
}
