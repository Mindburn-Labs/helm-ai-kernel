package observability

import (
	"testing"
	"time"
)

func TestTimelineRecord(t *testing.T) {
	tl := NewAuditTimeline()
	err := tl.Record(TimelineEntry{
		EntryType: EntryTypeAction,
		RunID:     "run-1",
		TenantID:  "t1",
		Summary:   "deployed service",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tl.Count() != 1 {
		t.Fatalf("expected 1, got %d", tl.Count())
	}
}

func TestTimelineQueryByRun(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, RunID: "run-1", TenantID: "t1", Summary: "a"})
	tl.Record(TimelineEntry{EntryType: EntryTypeDecision, RunID: "run-1", TenantID: "t1", Summary: "b"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, RunID: "run-2", TenantID: "t1", Summary: "c"})

	results := tl.Query(TimelineQuery{RunID: "run-1"})
	if len(results) != 2 {
		t.Fatalf("expected 2 results for run-1, got %d", len(results))
	}
}

func TestTimelineQueryByType(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, RunID: "run-1", Summary: "a"})
	tl.Record(TimelineEntry{EntryType: EntryTypeDecision, RunID: "run-1", Summary: "b"})
	tl.Record(TimelineEntry{EntryType: EntryTypeProof, RunID: "run-1", Summary: "c"})

	entryType := EntryTypeDecision
	results := tl.Query(TimelineQuery{RunID: "run-1", EntryType: &entryType})
	if len(results) != 1 {
		t.Fatalf("expected 1 DECISION, got %d", len(results))
	}
}

func TestTimelineQueryByTimeRange(t *testing.T) {
	tl := NewAuditTimeline()
	t1 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 1, 14, 0, 0, 0, time.UTC)

	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Timestamp: t1, Summary: "early"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Timestamp: t2, Summary: "mid"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Timestamp: t3, Summary: "late"})

	after := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)
	before := time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC)
	results := tl.Query(TimelineQuery{After: &after, Before: &before})
	if len(results) != 1 {
		t.Fatalf("expected 1 entry in range, got %d", len(results))
	}
	if results[0].Summary != "mid" {
		t.Fatalf("expected 'mid', got %s", results[0].Summary)
	}
}

func TestTimelineQueryLimit(t *testing.T) {
	tl := NewAuditTimeline()
	for i := 0; i < 10; i++ {
		tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "x"})
	}

	results := tl.Query(TimelineQuery{Limit: 3})
	if len(results) != 3 {
		t.Fatalf("expected 3, got %d", len(results))
	}
}

func TestTimelineContentHash(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{
		EntryType: EntryTypeProof,
		Summary:   "proof generated",
		Details:   map[string]interface{}{"hash": "abc"},
	})

	results := tl.Query(TimelineQuery{})
	if results[0].ContentHash == "" {
		t.Fatal("expected content hash")
	}
}

func TestTimelineQueryByTenant(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, TenantID: "t1", Summary: "a"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, TenantID: "t2", Summary: "b"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, TenantID: "t1", Summary: "c"})

	results := tl.Query(TimelineQuery{TenantID: "t1"})
	if len(results) != 2 {
		t.Fatalf("expected 2 for t1, got %d", len(results))
	}
}
