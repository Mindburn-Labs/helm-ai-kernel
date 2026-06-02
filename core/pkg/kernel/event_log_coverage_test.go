package kernel

import (
	"context"
	"math"
	"testing"
)

func TestEventLogRejectsUncanonicalPayload(t *testing.T) {
	log := NewInMemoryEventLog()

	_, err := log.Append(context.Background(), &EventEnvelope{
		EventID:   "event-invalid",
		EventType: "test.invalid",
		Payload: map[string]interface{}{
			"not_finite": math.Inf(1),
		},
	})
	if err == nil {
		t.Fatal("expected invalid canonical payload to fail append")
	}
}

func TestEventLogGetAndRangeEdges(t *testing.T) {
	ctx := context.Background()
	log := NewInMemoryEventLog()

	appendEventForCoverage(t, log, "event-1")
	appendEventForCoverage(t, log, "event-2")

	if _, err := log.Get(ctx, 0); err == nil {
		t.Fatal("expected sequence zero lookup to fail")
	}
	if _, err := log.Get(ctx, 3); err == nil {
		t.Fatal("expected out-of-range lookup to fail")
	}

	if _, err := log.Range(ctx, 0, 1); err == nil {
		t.Fatal("expected zero start range to fail")
	}
	if _, err := log.Range(ctx, 2, 1); err == nil {
		t.Fatal("expected reversed range to fail")
	}

	empty, err := log.Range(ctx, 10, 12)
	if err != nil {
		t.Fatalf("start beyond log should return empty slice without error: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected empty slice for start beyond log, got %d events", len(empty))
	}

	clipped, err := log.Range(ctx, 1, 99)
	if err != nil {
		t.Fatalf("clipped range should succeed: %v", err)
	}
	if len(clipped) != 2 || clipped[0].EventID != "event-1" || clipped[1].EventID != "event-2" {
		t.Fatalf("unexpected clipped range: %+v", clipped)
	}

	subset, err := log.Range(ctx, 2, 2)
	if err != nil {
		t.Fatalf("subset range should succeed: %v", err)
	}
	if len(subset) != 1 || subset[0].EventID != "event-2" {
		t.Fatalf("unexpected subset range: %+v", subset)
	}
}

func appendEventForCoverage(t *testing.T, log *InMemoryEventLog, eventID string) {
	t.Helper()

	_, err := log.Append(context.Background(), &EventEnvelope{
		EventID:   eventID,
		EventType: "test.event",
		Payload: map[string]interface{}{
			"id": eventID,
		},
	})
	if err != nil {
		t.Fatalf("append %s failed: %v", eventID, err)
	}
}
