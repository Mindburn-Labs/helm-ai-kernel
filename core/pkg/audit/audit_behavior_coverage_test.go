package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewLoggerDefaultWriter(t *testing.T) {
	l := NewLogger()
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestNewLoggerWithNilWriter(t *testing.T) {
	l := NewLoggerWithWriter(nil)
	if l == nil {
		t.Fatal("expected non-nil logger with nil writer fallback")
	}
}

func TestLoggerRecordOutputPrefix(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter(&buf)
	l.Record(context.Background(), EventAccess, "read", "/data", nil)
	if !strings.HasPrefix(buf.String(), "AUDIT: ") {
		t.Fatal("expected AUDIT: prefix")
	}
}

func TestLoggerRecordProducesValidJSON(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter(&buf)
	l.Record(context.Background(), EventMutation, "write", "/files", nil)
	jsonStr := strings.TrimPrefix(strings.TrimSpace(buf.String()), "AUDIT: ")
	var evt Event
	if err := json.Unmarshal([]byte(jsonStr), &evt); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestLoggerRecordEventType(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter(&buf)
	l.Record(context.Background(), EventSystem, "boot", "/system", nil)
	jsonStr := strings.TrimPrefix(strings.TrimSpace(buf.String()), "AUDIT: ")
	var evt Event
	json.Unmarshal([]byte(jsonStr), &evt)
	if evt.Type != EventSystem {
		t.Fatalf("expected SYSTEM, got %s", evt.Type)
	}
}

func TestLoggerRecordMetadata(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter(&buf)
	meta := map[string]interface{}{"key": "val"}
	l.Record(context.Background(), EventPolicy, "update", "/policy", meta)
	jsonStr := strings.TrimPrefix(strings.TrimSpace(buf.String()), "AUDIT: ")
	var evt Event
	json.Unmarshal([]byte(jsonStr), &evt)
	if evt.Metadata["key"] != "val" {
		t.Fatal("expected metadata key=val")
	}
}

func TestLoggerRecordDefaultActor(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter(&buf)
	l.Record(context.Background(), EventAccess, "act", "/res", nil)
	jsonStr := strings.TrimPrefix(strings.TrimSpace(buf.String()), "AUDIT: ")
	var evt Event
	json.Unmarshal([]byte(jsonStr), &evt)
	if evt.ActorID != "system" {
		t.Fatalf("expected system actor, got %s", evt.ActorID)
	}
}

func TestLoggerRecordHasUUID(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter(&buf)
	l.Record(context.Background(), EventAccess, "act", "/res", nil)
	jsonStr := strings.TrimPrefix(strings.TrimSpace(buf.String()), "AUDIT: ")
	var evt Event
	json.Unmarshal([]byte(jsonStr), &evt)
	if len(evt.ID) != 36 {
		t.Fatalf("expected UUID, got %q", evt.ID)
	}
}

func TestLoggerRecordHasTimestamp(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter(&buf)
	l.Record(context.Background(), EventAccess, "act", "/res", nil)
	jsonStr := strings.TrimPrefix(strings.TrimSpace(buf.String()), "AUDIT: ")
	var evt Event
	json.Unmarshal([]byte(jsonStr), &evt)
	if evt.Timestamp.IsZero() {
		t.Fatal("expected non-zero timestamp")
	}
}

func TestNewTimeline(t *testing.T) {
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()
	tl := NewTimeline("tenant-1", from, to)
	if tl.TenantID != "tenant-1" || len(tl.Events) != 0 {
		t.Fatal("bad timeline init")
	}
}

func TestTimelineAddSorts(t *testing.T) {
	tl := NewTimeline("t1", time.Now(), time.Now())
	t2 := time.Now()
	t1 := t2.Add(-time.Hour)
	tl.Add(TimelineEvent{ID: "e2", Timestamp: t2, Type: TLEventExecution})
	tl.Add(TimelineEvent{ID: "e1", Timestamp: t1, Type: TLEventDecision})
	if tl.Events[0].ID != "e1" {
		t.Fatal("expected sorted order")
	}
}

func TestTimelineFilter(t *testing.T) {
	tl := NewTimeline("t1", time.Now(), time.Now())
	tl.Add(TimelineEvent{ID: "e1", Timestamp: time.Now(), Type: TLEventDecision})
	tl.Add(TimelineEvent{ID: "e2", Timestamp: time.Now(), Type: TLEventSpend})
	filtered := tl.Filter(TLEventSpend)
	if len(filtered) != 1 || filtered[0].ID != "e2" {
		t.Fatal("filter failed")
	}
}

func TestTimelineFilterEmpty(t *testing.T) {
	tl := NewTimeline("t1", time.Now(), time.Now())
	tl.Add(TimelineEvent{ID: "e1", Timestamp: time.Now(), Type: TLEventDecision})
	if len(tl.Filter(TLEventDispute)) != 0 {
		t.Fatal("expected empty for unmatched type")
	}
}

func TestTimelineForActor(t *testing.T) {
	tl := NewTimeline("t1", time.Now(), time.Now())
	tl.Add(TimelineEvent{ID: "e1", Timestamp: time.Now(), Type: TLEventApproval, ActorID: "alice"})
	tl.Add(TimelineEvent{ID: "e2", Timestamp: time.Now(), Type: TLEventDenial, ActorID: "bob"})
	results := tl.ForActor("alice")
	if len(results) != 1 || results[0].ID != "e1" {
		t.Fatal("ForActor failed")
	}
}

func TestTimelineForRun(t *testing.T) {
	tl := NewTimeline("t1", time.Now(), time.Now())
	tl.Add(TimelineEvent{ID: "e1", Timestamp: time.Now(), Type: TLEventExecution, RunID: "run-1"})
	tl.Add(TimelineEvent{ID: "e2", Timestamp: time.Now(), Type: TLEventExecution, RunID: "run-2"})
	results := tl.ForRun("run-1")
	if len(results) != 1 {
		t.Fatal("ForRun failed")
	}
}

func TestTimelineForRunEmpty(t *testing.T) {
	tl := NewTimeline("t1", time.Now(), time.Now())
	if len(tl.ForRun("missing")) != 0 {
		t.Fatal("expected empty for missing run")
	}
}

func TestEventTypeConstants(t *testing.T) {
	types := []EventType{EventAccess, EventMutation, EventSystem, EventPolicy}
	seen := map[EventType]bool{}
	for _, et := range types {
		if seen[et] {
			t.Fatalf("duplicate event type: %s", et)
		}
		seen[et] = true
	}
}

func TestTLEventKindConstants(t *testing.T) {
	kinds := []TLEventKind{TLEventDecision, TLEventExecution, TLEventApproval, TLEventDenial, TLEventEscalation, TLEventSpend, TLEventPolicy, TLEventDispute}
	if len(kinds) != 8 {
		t.Fatalf("expected 8 timeline event kinds, got %d", len(kinds))
	}
}

func TestTimelineForActorEmpty(t *testing.T) {
	tl := NewTimeline("t1", time.Now(), time.Now())
	if len(tl.ForActor("nobody")) != 0 {
		t.Fatal("expected empty")
	}
}
