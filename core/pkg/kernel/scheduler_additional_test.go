package kernel

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSchedulerPeek(t *testing.T) {
	s := NewInMemoryScheduler()
	ctx := context.Background()

	// Peek empty scheduler
	e, err := s.Peek(ctx)
	if err != nil || e != nil {
		t.Errorf("Peek empty should return nil, nil")
	}

	// Add event and peek
	event := &SchedulerEvent{
		EventID:     "e1",
		EventType:   "test",
		ScheduledAt: time.Now(),
		Priority:    1,
	}
	if err := s.Schedule(ctx, event); err != nil {
		t.Fatal(err)
	}

	peeked, err := s.Peek(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if peeked == nil || peeked.EventID != "e1" {
		t.Error("Peek should return first event")
	}

	// Len should still be 1
	if s.Len() != 1 {
		t.Error("Len should be 1 after peek")
	}
}

func TestSchedulerClose(t *testing.T) {
	s := NewInMemoryScheduler()
	ctx := context.Background()

	// Close and try to schedule
	s.Close()

	event := &SchedulerEvent{
		EventID:   "e1",
		EventType: "test",
	}
	err := s.Schedule(ctx, event)
	if !errors.Is(err, ErrSchedulerClosed) {
		t.Error("Schedule on closed should error")
	}
}

func TestSchedulerSnapshotHash(t *testing.T) {
	s := NewInMemoryScheduler()
	ctx := context.Background()

	hash1 := s.SnapshotHash()
	if hash1 == "" {
		t.Error("SnapshotHash should not be empty")
	}

	// Add event
	_ = s.Schedule(ctx, &SchedulerEvent{
		EventID:     "e1",
		EventType:   "test",
		ScheduledAt: time.Now(),
	})

	hash2 := s.SnapshotHash()
	if hash1 == hash2 {
		t.Error("SnapshotHash should change after adding event")
	}

	// Same state should produce same hash
	hash3 := s.SnapshotHash()
	if hash2 != hash3 {
		t.Error("SnapshotHash should be deterministic")
	}
}

func TestCompareEvents(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	e1 := &SchedulerEvent{
		ScheduledAt: base,
		Priority:    1,
		SequenceNum: 1,
		SortKey:     "a",
	}
	e2 := &SchedulerEvent{
		ScheduledAt: base.Add(time.Hour),
		Priority:    1,
		SequenceNum: 2,
		SortKey:     "b",
	}

	// Different times
	if compareEvents(e1, e2) >= 0 {
		t.Error("Earlier time should be less")
	}
	if compareEvents(e2, e1) <= 0 {
		t.Error("Later time should be greater")
	}

	// Same time, different priority
	e2.ScheduledAt = base
	e1.Priority = 1
	e2.Priority = 2
	if compareEvents(e1, e2) >= 0 {
		t.Error("Lower priority should be less")
	}

	// Same time and priority, different sequence
	e2.Priority = 1
	e1.SequenceNum = 1
	e2.SequenceNum = 2
	if compareEvents(e1, e2) >= 0 {
		t.Error("Lower sequence should be less")
	}

	// Same all, different sort key
	e2.SequenceNum = 1
	e1.SortKey = "a"
	e2.SortKey = "b"
	if compareEvents(e1, e2) >= 0 {
		t.Error("Lower sort key should be less")
	}

	// Identical
	e2.SortKey = "a"
	if compareEvents(e1, e2) != 0 {
		t.Error("Same events should be equal")
	}
}

func TestErrorStringError(t *testing.T) {
	e := errorString("test error")
	if e.Error() != "test error" {
		t.Errorf("Error() = %q", e.Error())
	}
}
