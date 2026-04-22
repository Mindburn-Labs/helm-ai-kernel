package kernel

import (
	"context"
	"testing"
	"time"
)

func TestScheduler_DeterministicOrdering(t *testing.T) {
	scheduler := NewInMemoryScheduler()
	ctx := context.Background()

	// Schedule events with same timestamp
	now := time.Now().UTC()
	events := []*SchedulerEvent{
		{EventID: "e3", EventType: "test", ScheduledAt: now, Priority: 1, SortKey: "same"},
		{EventID: "e1", EventType: "test", ScheduledAt: now, Priority: 1, SortKey: "same"},
		{EventID: "e2", EventType: "test", ScheduledAt: now, Priority: 1, SortKey: "same"},
	}

	for _, e := range events {
		if err := scheduler.Schedule(ctx, e); err != nil {
			t.Fatalf("Schedule failed: %v", err)
		}
	}

	// Events are ordered by sequence number when time/priority are equal
	// Sequence numbers are assigned in insertion order, so output matches input order
	expectedIDs := []string{"e3", "e1", "e2"}
	for i := 0; i < len(expectedIDs); i++ {
		e, err := scheduler.Next(ctx)
		if err != nil {
			t.Fatalf("Next failed: %v", err)
		}
		if e.EventID != expectedIDs[i] {
			t.Errorf("Expected event ID %s, got %s (seq=%d)", expectedIDs[i], e.EventID, e.SequenceNum)
		}
	}
}

func TestScheduler_PriorityOrdering(t *testing.T) {
	scheduler := NewInMemoryScheduler()
	ctx := context.Background()

	now := time.Now().UTC()
	events := []*SchedulerEvent{
		{EventID: "low", EventType: "test", ScheduledAt: now, Priority: 10},
		{EventID: "high", EventType: "test", ScheduledAt: now, Priority: 1},
		{EventID: "medium", EventType: "test", ScheduledAt: now, Priority: 5},
	}

	for _, e := range events {
		_ = scheduler.Schedule(ctx, e)
	}

	// Verify priority order (lower priority number = higher priority)
	expectedIDs := []string{"high", "medium", "low"}
	for i := 0; i < len(expectedIDs); i++ {
		e, _ := scheduler.Next(ctx)
		if e.EventID != expectedIDs[i] {
			t.Errorf("Expected ID %s, got %s", expectedIDs[i], e.EventID)
		}
	}
}

func TestScheduler_SnapshotHashDeterminism(t *testing.T) {
	ctx := context.Background()

	// Create two schedulers with same events
	s1 := NewInMemoryScheduler()
	s2 := NewInMemoryScheduler()

	now := time.Now().UTC()
	events := []*SchedulerEvent{
		{EventID: "e1", EventType: "test", ScheduledAt: now, Priority: 1},
		{EventID: "e2", EventType: "test", ScheduledAt: now.Add(time.Second), Priority: 2},
	}

	for _, e := range events {
		_ = s1.Schedule(ctx, e)
		_ = s2.Schedule(ctx, e)
	}

	hash1 := s1.SnapshotHash()
	hash2 := s2.SnapshotHash()

	if hash1 != hash2 {
		t.Errorf("Snapshot hashes should be equal: %s vs %s", hash1, hash2)
	}
}

//nolint:gocognit // test complexity is acceptable
func TestIOCapture_RequestResponse(t *testing.T) {
	store := NewInMemoryIOCaptureStore()
	log := NewInMemoryEventLog()
	interceptor := NewIOInterceptor(store, log)
	ctx := context.Background()

	// Capture request
	req := &HTTPRequestCapture{
		Method:         "POST",
		URL:            "https://api.example.com/data",
		Headers:        map[string]string{"Content-Type": "application/json"},
		Body:           []byte(`{"key": "value"}`),
		IdempotencyKey: "idem-123",
	}

	record, err := interceptor.CaptureRequest(ctx, "rec-001", "effect-001", "loop-001", req)
	if err != nil {
		t.Fatalf("CaptureRequest failed: %v", err)
	}

	if record.RequestHash == "" {
		t.Error("Request hash should not be empty")
	}
	if record.IdempotencyKey != "idem-123" {
		t.Error("Idempotency key mismatch")
	}

	// Capture response
	resp := &HTTPResponseCapture{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       []byte(`{"result": "success"}`),
	}

	err = interceptor.CaptureResponse(ctx, record, resp, 150)
	if err != nil {
		t.Fatalf("CaptureResponse failed: %v", err)
	}

	if record.ResponseHash == "" {
		t.Error("Response hash should not be empty")
	}
	if record.DurationMs != 150 {
		t.Errorf("Duration mismatch: expected 150, got %d", record.DurationMs)
	}

	// Verify retrieval - both request and updated-with-response are stored
	records, _ := store.ListByEffect(ctx, "effect-001")
	if len(records) != 2 {
		t.Errorf("Expected 2 records (request + response update), got %d", len(records))
	}
}

func TestIOCapture_RetryTracking(t *testing.T) {
	store := NewInMemoryIOCaptureStore()
	interceptor := NewIOInterceptor(store, nil)
	ctx := context.Background()

	record := &IORecord{
		RecordID:       "rec-retry-test",
		EffectID:       "effect-002",
		IdempotencyKey: "idem-456",
	}

	// Capture retries
	err := interceptor.CaptureRetry(ctx, record, 1, 100*time.Millisecond, "connection timeout")
	if err != nil {
		t.Fatalf("CaptureRetry failed: %v", err)
	}

	err = interceptor.CaptureRetry(ctx, record, 2, 200*time.Millisecond, "server error")
	if err != nil {
		t.Fatalf("CaptureRetry failed: %v", err)
	}

	// Verify retries were captured
	records, _ := store.ListByEffect(ctx, "effect-002")
	if len(records) != 2 {
		t.Errorf("Expected 2 retry records, got %d", len(records))
	}
}
