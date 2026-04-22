// Package kernel provides a deterministic event scheduler.
// Per Section 1.2 - Deterministic Scheduler
package kernel

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// SchedulerEvent represents a scheduled event.
type SchedulerEvent struct {
	EventID     string                 `json:"event_id"`
	EventType   string                 `json:"event_type"`
	ScheduledAt time.Time              `json:"scheduled_at"`
	Priority    int                    `json:"priority"` // Lower = higher priority
	SequenceNum uint64                 `json:"sequence_num"`
	Payload     map[string]interface{} `json:"payload"`
	LoopID      string                 `json:"loop_id,omitempty"`

	// For deterministic ordering
	SortKey string `json:"sort_key"`
}

// DeterministicScheduler provides stable ordering for kernel events.
// Per Section 1.2:
// - Kernel MUST schedule events in deterministic order
// - If two events have same timestamp, ordering MUST be stable (sort_key)
type DeterministicScheduler interface {
	// Schedule adds an event to the scheduler.
	Schedule(ctx context.Context, event *SchedulerEvent) error

	// Next returns the next event to process, blocking if none available.
	Next(ctx context.Context) (*SchedulerEvent, error)

	// Peek returns the next event without removing it.
	Peek(ctx context.Context) (*SchedulerEvent, error)

	// Len returns the number of pending events.
	Len() int

	// SnapshotHash returns a deterministic hash of the current queue state.
	SnapshotHash() string
}

// schedulerHeap implements heap.Interface for priority scheduling.
type schedulerHeap []*SchedulerEvent

func (h schedulerHeap) Len() int { return len(h) }

func (h schedulerHeap) Less(i, j int) bool {
	// Primary: scheduled time
	if !h[i].ScheduledAt.Equal(h[j].ScheduledAt) {
		return h[i].ScheduledAt.Before(h[j].ScheduledAt)
	}
	// Secondary: priority (lower = higher priority)
	if h[i].Priority != h[j].Priority {
		return h[i].Priority < h[j].Priority
	}
	// Tertiary: sort key (for determinism)
	if h[i].SortKey != h[j].SortKey {
		return h[i].SortKey < h[j].SortKey
	}
	// Final: sequence number (monotonicity as fallback)
	return h[i].SequenceNum < h[j].SequenceNum
}

func (h schedulerHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *schedulerHeap) Push(x interface{}) {
	*h = append(*h, x.(*SchedulerEvent))
}

func (h *schedulerHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// InMemoryScheduler provides a deterministic in-memory scheduler.
type InMemoryScheduler struct {
	mu      sync.Mutex
	events  schedulerHeap
	nextSeq uint64
	cond    *sync.Cond
	closed  bool
}

// NewInMemoryScheduler creates a new deterministic scheduler.
func NewInMemoryScheduler() *InMemoryScheduler {
	s := &InMemoryScheduler{
		events:  make(schedulerHeap, 0),
		nextSeq: 1,
	}
	s.cond = sync.NewCond(&s.mu)
	heap.Init(&s.events)
	return s
}

// Schedule implements DeterministicScheduler.
func (s *InMemoryScheduler) Schedule(ctx context.Context, event *SchedulerEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrSchedulerClosed
	}

	// Assign sequence number for monotonicity
	event.SequenceNum = s.nextSeq
	s.nextSeq++

	// Generate sort key if not provided
	if event.SortKey == "" {
		event.SortKey = generateSortKey(event)
	}

	heap.Push(&s.events, event)
	s.cond.Signal()
	return nil
}

// Next implements DeterministicScheduler.
func (s *InMemoryScheduler) Next(ctx context.Context) (*SchedulerEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for s.events.Len() == 0 && !s.closed {
		s.cond.Wait()
	}

	if s.closed && s.events.Len() == 0 {
		return nil, ErrSchedulerClosed
	}

	return heap.Pop(&s.events).(*SchedulerEvent), nil
}

// Peek implements DeterministicScheduler.
func (s *InMemoryScheduler) Peek(ctx context.Context) (*SchedulerEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.events.Len() == 0 {
		return nil, nil
	}

	return s.events[0], nil
}

// Len implements DeterministicScheduler.
func (s *InMemoryScheduler) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// SnapshotHash implements DeterministicScheduler.
func (s *InMemoryScheduler) SnapshotHash() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create deterministic snapshot
	events := make([]*SchedulerEvent, len(s.events))
	copy(events, s.events)

	// Sort for determinism
	sortEvents(events)

	data, _ := json.Marshal(events)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// Close closes the scheduler.
func (s *InMemoryScheduler) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.cond.Broadcast()
}

// sortEvents sorts events deterministically using O(n log n) sort.
func sortEvents(events []*SchedulerEvent) {
	sort.Slice(events, func(i, j int) bool {
		return compareEvents(events[i], events[j]) < 0
	})
}

func compareEvents(a, b *SchedulerEvent) int {
	if a.ScheduledAt.Before(b.ScheduledAt) {
		return -1
	}
	if a.ScheduledAt.After(b.ScheduledAt) {
		return 1
	}
	if a.Priority < b.Priority {
		return -1
	}
	if a.Priority > b.Priority {
		return 1
	}
	if a.SortKey < b.SortKey {
		return -1
	}
	if a.SortKey > b.SortKey {
		return 1
	}
	if a.SequenceNum < b.SequenceNum {
		return -1
	}
	if a.SequenceNum > b.SequenceNum {
		return 1
	}
	return 0
}

func generateSortKey(event *SchedulerEvent) string {
	data, _ := json.Marshal(map[string]interface{}{
		"event_id":   event.EventID,
		"event_type": event.EventType,
		"loop_id":    event.LoopID,
	})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:16])
}

// Error types
var (
	ErrSchedulerClosed = errorString("scheduler closed")
)

type errorString string

func (e errorString) Error() string { return string(e) }

// TestSchedulerMonotonicity removed - was dead code
