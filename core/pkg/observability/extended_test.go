package observability

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── SLO with Multiple Operations ────────────────────────────

func TestSLO_MultipleOperations(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "s1", Operation: "compile", LatencyP99: 100 * time.Millisecond, SuccessRate: 0.99, WindowHours: 1})
	tracker.SetTarget(&SLOTarget{SLOID: "s2", Operation: "verify", LatencyP99: 50 * time.Millisecond, SuccessRate: 0.999, WindowHours: 1})
	tracker.Record(SLOObservation{Operation: "compile", Latency: 10 * time.Millisecond, Success: true})
	tracker.Record(SLOObservation{Operation: "verify", Latency: 5 * time.Millisecond, Success: true})
	s1, _ := tracker.Status("compile")
	s2, _ := tracker.Status("verify")
	if !s1.InCompliance || !s2.InCompliance {
		t.Error("both operations should be in compliance")
	}
}

func TestSLO_UnknownOperationReturnsError(t *testing.T) {
	tracker := NewSLOTracker()
	_, err := tracker.Status("nonexistent")
	if err == nil {
		t.Error("unknown operation should return error")
	}
}

func TestSLO_WindowFiltersOldObservations(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tracker := NewSLOTracker().WithClock(func() time.Time { return now })
	tracker.SetTarget(&SLOTarget{SLOID: "s1", Operation: "op", LatencyP99: 100 * time.Millisecond, SuccessRate: 0.9, WindowHours: 1})
	tracker.Record(SLOObservation{Operation: "op", Latency: 10 * time.Millisecond, Success: false, Timestamp: now.Add(-2 * time.Hour)})
	tracker.Record(SLOObservation{Operation: "op", Latency: 10 * time.Millisecond, Success: true, Timestamp: now.Add(-30 * time.Minute)})
	status, _ := tracker.Status("op")
	if status.ObservationCount != 1 {
		t.Errorf("expected 1 observation in window, got %d", status.ObservationCount)
	}
}

// ── Burn Rate Edge Cases ────────────────────────────────────

func TestSLO_ZeroObservationsInCompliance(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "s1", Operation: "op", LatencyP99: 100 * time.Millisecond, SuccessRate: 0.99, WindowHours: 1})
	status, _ := tracker.Status("op")
	if !status.InCompliance || status.ObservationCount != 0 {
		t.Error("zero observations should be in compliance")
	}
}

func TestSLO_AllFailures100PercentBurnRate(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "s1", Operation: "op", LatencyP99: 100 * time.Millisecond, SuccessRate: 0.99, WindowHours: 24})
	for i := 0; i < 10; i++ {
		tracker.Record(SLOObservation{Operation: "op", Latency: 10 * time.Millisecond, Success: false})
	}
	status, _ := tracker.Status("op")
	if status.InCompliance {
		t.Error("100% failure should NOT be in compliance")
	}
	if status.BurnRate < 1.0 {
		t.Errorf("burn rate should be >= 1.0, got %f", status.BurnRate)
	}
	if status.ErrorBudgetLeft != 0 {
		t.Errorf("error budget should be 0, got %f", status.ErrorBudgetLeft)
	}
}

func TestSLO_AllSuccessesZeroBurnRate(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "s1", Operation: "op", LatencyP99: 100 * time.Millisecond, SuccessRate: 0.99, WindowHours: 24})
	for i := 0; i < 100; i++ {
		tracker.Record(SLOObservation{Operation: "op", Latency: 5 * time.Millisecond, Success: true})
	}
	status, _ := tracker.Status("op")
	if status.BurnRate != 0 {
		t.Errorf("expected burn rate 0, got %f", status.BurnRate)
	}
	if status.ErrorBudgetLeft != 100.0 {
		t.Errorf("expected 100%% budget left, got %f", status.ErrorBudgetLeft)
	}
}

func TestSLO_LatencyViolationOutOfCompliance(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "s1", Operation: "op", LatencyP99: 50 * time.Millisecond, SuccessRate: 0.5, WindowHours: 24})
	tracker.Record(SLOObservation{Operation: "op", Latency: 200 * time.Millisecond, Success: true})
	status, _ := tracker.Status("op")
	if status.InCompliance {
		t.Error("p99 latency violation should be out of compliance")
	}
}

// ── SLI Multi-Source ────────────────────────────────────────

func TestSLI_RegisterMultipleSources(t *testing.T) {
	reg := NewSLIRegistry()
	_ = reg.Register(&SLI{SLIID: "sli-1", Name: "Latency", Operation: "compile", Source: SLISourceMetric, Unit: "ms"})
	_ = reg.Register(&SLI{SLIID: "sli-2", Name: "Errors", Operation: "compile", Source: SLISourceLog, Unit: "count"})
	_ = reg.Register(&SLI{SLIID: "sli-3", Name: "Probe", Operation: "compile", Source: SLISourceProbe, Unit: "%"})
	slis := reg.ByOperation("compile")
	if len(slis) != 3 {
		t.Errorf("expected 3 SLIs for compile, got %d", len(slis))
	}
}

func TestSLI_LinkToSLO(t *testing.T) {
	reg := NewSLIRegistry()
	_ = reg.Register(&SLI{SLIID: "sli-1", Name: "L", Operation: "op"})
	_ = reg.LinkToSLO("sli-1", "slo-99")
	sli, _ := reg.Get("sli-1")
	if sli.LinkedSLOID != "slo-99" {
		t.Errorf("expected linked SLO slo-99, got %s", sli.LinkedSLOID)
	}
}

func TestSLI_LinkToSLONotFound(t *testing.T) {
	reg := NewSLIRegistry()
	err := reg.LinkToSLO("ghost", "slo-1")
	if err == nil {
		t.Error("linking nonexistent SLI should error")
	}
}

func TestSLI_CountAfterRegistration(t *testing.T) {
	reg := NewSLIRegistry()
	for i := 0; i < 5; i++ {
		_ = reg.Register(&SLI{SLIID: fmt.Sprintf("s%d", i), Name: "N", Operation: "op"})
	}
	if reg.Count() != 5 {
		t.Errorf("expected 5, got %d", reg.Count())
	}
}

func TestSLI_RegisterMissingFieldsError(t *testing.T) {
	reg := NewSLIRegistry()
	err := reg.Register(&SLI{})
	if err == nil {
		t.Error("registering SLI with empty fields should error")
	}
}

// ── Timeline with Many Entries ──────────────────────────────

func TestTimeline_100Entries(t *testing.T) {
	tl := NewAuditTimeline()
	for i := 0; i < 100; i++ {
		_ = tl.Record(TimelineEntry{RunID: "run-1", EntryType: EntryTypeAction, Summary: fmt.Sprintf("action-%d", i)})
	}
	if tl.Count() != 100 {
		t.Errorf("expected 100 entries, got %d", tl.Count())
	}
}

func TestTimeline_QueryByRunID(t *testing.T) {
	tl := NewAuditTimeline()
	_ = tl.Record(TimelineEntry{RunID: "run-a", EntryType: EntryTypeAction, Summary: "a"})
	_ = tl.Record(TimelineEntry{RunID: "run-b", EntryType: EntryTypeAction, Summary: "b"})
	results := tl.Query(TimelineQuery{RunID: "run-a"})
	if len(results) != 1 {
		t.Errorf("expected 1 result for run-a, got %d", len(results))
	}
}

func TestTimeline_QueryWithLimit(t *testing.T) {
	tl := NewAuditTimeline()
	for i := 0; i < 10; i++ {
		_ = tl.Record(TimelineEntry{RunID: "r", EntryType: EntryTypeAction, Summary: "s"})
	}
	results := tl.Query(TimelineQuery{RunID: "r", Limit: 3})
	if len(results) != 3 {
		t.Errorf("expected 3, got %d", len(results))
	}
}

func TestTimeline_QueryByEntryType(t *testing.T) {
	tl := NewAuditTimeline()
	_ = tl.Record(TimelineEntry{EntryType: EntryTypeProof, Summary: "proof"})
	_ = tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "action"})
	proofType := EntryTypeProof
	results := tl.Query(TimelineQuery{EntryType: &proofType})
	if len(results) != 1 || results[0].EntryType != EntryTypeProof {
		t.Error("filter by entry type failed")
	}
}

func TestTimeline_ContentHashComputed(t *testing.T) {
	tl := NewAuditTimeline()
	_ = tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "test", Details: map[string]interface{}{"k": "v"}})
	results := tl.Query(TimelineQuery{})
	if len(results) != 1 || results[0].ContentHash == "" {
		t.Error("content hash should be computed on record")
	}
}

// ── Concurrent Recording ────────────────────────────────────

func TestTimeline_ConcurrentRecording(t *testing.T) {
	tl := NewAuditTimeline()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = tl.Record(TimelineEntry{RunID: "conc", EntryType: EntryTypeAction, Summary: fmt.Sprintf("s%d", idx)})
		}(i)
	}
	wg.Wait()
	if tl.Count() != 100 {
		t.Errorf("expected 100, got %d", tl.Count())
	}
}

func TestSLI_ByOperationEmpty(t *testing.T) {
	reg := NewSLIRegistry()
	slis := reg.ByOperation("nonexistent")
	if len(slis) != 0 {
		t.Errorf("expected empty slice for unknown operation, got %d", len(slis))
	}
}

func TestSLO_ConcurrentRecordAndStatus(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "s1", Operation: "op", LatencyP99: 100 * time.Millisecond, SuccessRate: 0.9, WindowHours: 1})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			tracker.Record(SLOObservation{Operation: "op", Latency: 5 * time.Millisecond, Success: true})
		}()
		go func() {
			defer wg.Done()
			_, _ = tracker.Status("op")
		}()
	}
	wg.Wait()
}
