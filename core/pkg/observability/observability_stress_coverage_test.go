package observability

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────────────
// SLO with 5000 observations
// ────────────────────────────────────────────────────────────────────────

func TestStress_SLO5000Observations(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "slo-1", Name: "execute", Operation: "execute", LatencyP99: 100 * time.Millisecond, SuccessRate: 0.99, WindowHours: 24})
	for i := 0; i < 5000; i++ {
		tracker.Record(SLOObservation{Operation: "execute", Latency: time.Duration(i%100) * time.Millisecond, Success: i%100 != 0, Timestamp: time.Now()})
	}
	status, err := tracker.Status("execute")
	if err != nil || status.ObservationCount != 5000 {
		t.Fatalf("expected 5000 observations, got %d err=%v", status.ObservationCount, err)
	}
}

func TestStress_SLO5000AllSuccess(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "slo-2", Name: "compile", Operation: "compile", LatencyP99: 200 * time.Millisecond, SuccessRate: 0.99, WindowHours: 24})
	for i := 0; i < 5000; i++ {
		tracker.Record(SLOObservation{Operation: "compile", Latency: 10 * time.Millisecond, Success: true, Timestamp: time.Now()})
	}
	status, _ := tracker.Status("compile")
	if !status.InCompliance {
		t.Fatal("expected compliance with all successes")
	}
}

func TestStress_SLO5000AllFailures(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "slo-3", Name: "plan", Operation: "plan", LatencyP99: 100 * time.Millisecond, SuccessRate: 0.99, WindowHours: 24})
	for i := 0; i < 5000; i++ {
		tracker.Record(SLOObservation{Operation: "plan", Latency: 10 * time.Millisecond, Success: false, Timestamp: time.Now()})
	}
	status, _ := tracker.Status("plan")
	if status.InCompliance {
		t.Fatal("expected non-compliance with all failures")
	}
}

func TestStress_SLONoObservationsInCompliance(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "slo-4", Name: "verify", Operation: "verify", LatencyP99: 50 * time.Millisecond, SuccessRate: 0.99, WindowHours: 1})
	status, _ := tracker.Status("verify")
	if !status.InCompliance {
		t.Fatal("expected compliance with zero observations")
	}
}

func TestStress_SLONoTargetReturnsError(t *testing.T) {
	tracker := NewSLOTracker()
	_, err := tracker.Status("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing SLO target")
	}
}

// ────────────────────────────────────────────────────────────────────────
// 200 concurrent records
// ────────────────────────────────────────────────────────────────────────

func TestStress_200ConcurrentSLORecords(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "slo-c", Name: "exec", Operation: "exec", LatencyP99: 100 * time.Millisecond, SuccessRate: 0.95, WindowHours: 24})
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			tracker.Record(SLOObservation{Operation: "exec", Latency: time.Duration(n) * time.Microsecond, Success: true, Timestamp: time.Now()})
		}(i)
	}
	wg.Wait()
	status, _ := tracker.Status("exec")
	if status.ObservationCount != 200 {
		t.Fatalf("expected 200 observations, got %d", status.ObservationCount)
	}
}

func TestStress_200ConcurrentTimelineRecords(t *testing.T) {
	tl := NewAuditTimeline()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = tl.Record(TimelineEntry{RunID: "run-1", TenantID: "t1", EntryType: EntryTypeAction, Summary: fmt.Sprintf("action-%d", n)})
		}(i)
	}
	wg.Wait()
	if tl.Count() != 200 {
		t.Fatalf("expected 200 entries, got %d", tl.Count())
	}
}

// ────────────────────────────────────────────────────────────────────────
// Burn rate at every threshold (0.5x, 1x, 2x, 5x, 10x)
// ────────────────────────────────────────────────────────────────────────

func helperSLOTrackerWithFailRate(failRate float64) *SLOTracker {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "slo-br", Name: "op", Operation: "op", LatencyP99: 1 * time.Second, SuccessRate: 0.99, WindowHours: 24})
	total := 1000
	failures := int(float64(total) * failRate)
	for i := 0; i < total; i++ {
		tracker.Record(SLOObservation{Operation: "op", Latency: 1 * time.Millisecond, Success: i >= failures, Timestamp: time.Now()})
	}
	return tracker
}

func TestStress_BurnRateHalf(t *testing.T) {
	tracker := helperSLOTrackerWithFailRate(0.005) // 0.5x of 1% error budget
	status, _ := tracker.Status("op")
	if status.BurnRate < 0.4 || status.BurnRate > 0.6 {
		t.Fatalf("expected ~0.5x burn rate, got %f", status.BurnRate)
	}
}

func TestStress_BurnRate1x(t *testing.T) {
	tracker := helperSLOTrackerWithFailRate(0.01) // 1x
	status, _ := tracker.Status("op")
	if status.BurnRate < 0.9 || status.BurnRate > 1.1 {
		t.Fatalf("expected ~1x burn rate, got %f", status.BurnRate)
	}
}

func TestStress_BurnRate2x(t *testing.T) {
	tracker := helperSLOTrackerWithFailRate(0.02)
	status, _ := tracker.Status("op")
	if status.BurnRate < 1.8 || status.BurnRate > 2.2 {
		t.Fatalf("expected ~2x burn rate, got %f", status.BurnRate)
	}
}

func TestStress_BurnRate5x(t *testing.T) {
	tracker := helperSLOTrackerWithFailRate(0.05)
	status, _ := tracker.Status("op")
	if status.BurnRate < 4.5 || status.BurnRate > 5.5 {
		t.Fatalf("expected ~5x burn rate, got %f", status.BurnRate)
	}
}

func TestStress_BurnRate10x(t *testing.T) {
	tracker := helperSLOTrackerWithFailRate(0.10)
	status, _ := tracker.Status("op")
	if status.BurnRate < 9.0 || status.BurnRate > 11.0 {
		t.Fatalf("expected ~10x burn rate, got %f", status.BurnRate)
	}
}

// ────────────────────────────────────────────────────────────────────────
// SLI with all 4 sources x 5 each
// ────────────────────────────────────────────────────────────────────────

func TestStress_SLIMetricSource5Each(t *testing.T) {
	reg := NewSLIRegistry()
	for i := 0; i < 5; i++ {
		_ = reg.Register(&SLI{SLIID: fmt.Sprintf("metric-%d", i), Name: fmt.Sprintf("m-%d", i), Operation: "execute", Source: SLISourceMetric, Unit: "ms"})
	}
	slis := reg.ByOperation("execute")
	if len(slis) != 5 {
		t.Fatalf("expected 5, got %d", len(slis))
	}
}

func TestStress_SLILogSource5Each(t *testing.T) {
	reg := NewSLIRegistry()
	for i := 0; i < 5; i++ {
		_ = reg.Register(&SLI{SLIID: fmt.Sprintf("log-%d", i), Name: fmt.Sprintf("l-%d", i), Operation: "compile", Source: SLISourceLog, Unit: "%"})
	}
	if reg.Count() != 5 {
		t.Fatalf("expected 5 SLIs, got %d", reg.Count())
	}
}

func TestStress_SLITraceSource5Each(t *testing.T) {
	reg := NewSLIRegistry()
	for i := 0; i < 5; i++ {
		_ = reg.Register(&SLI{SLIID: fmt.Sprintf("trace-%d", i), Name: fmt.Sprintf("t-%d", i), Operation: "plan", Source: SLISourceTrace, Unit: "count"})
	}
	sli, err := reg.Get("trace-3")
	if err != nil || sli.Source != SLISourceTrace {
		t.Fatal("expected trace source SLI")
	}
}

func TestStress_SLIProbeSource5Each(t *testing.T) {
	reg := NewSLIRegistry()
	for i := 0; i < 5; i++ {
		_ = reg.Register(&SLI{SLIID: fmt.Sprintf("probe-%d", i), Name: fmt.Sprintf("p-%d", i), Operation: "verify", Source: SLISourceProbe, Unit: "bool"})
	}
	slis := reg.ByOperation("verify")
	if len(slis) != 5 {
		t.Fatalf("expected 5, got %d", len(slis))
	}
}

func TestStress_SLIRegisterMissingFields(t *testing.T) {
	reg := NewSLIRegistry()
	err := reg.Register(&SLI{SLIID: "", Name: "n", Operation: "op"})
	if err == nil {
		t.Fatal("expected error for missing SLI ID")
	}
}

func TestStress_SLIGetNotFound(t *testing.T) {
	reg := NewSLIRegistry()
	_, err := reg.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing SLI")
	}
}

func TestStress_SLILinkToSLO(t *testing.T) {
	reg := NewSLIRegistry()
	_ = reg.Register(&SLI{SLIID: "sli-1", Name: "n", Operation: "op"})
	err := reg.LinkToSLO("sli-1", "slo-1")
	if err != nil {
		t.Fatal(err)
	}
	sli, _ := reg.Get("sli-1")
	if sli.LinkedSLOID != "slo-1" {
		t.Fatal("link not set")
	}
}

func TestStress_SLILinkToSLONotFound(t *testing.T) {
	reg := NewSLIRegistry()
	err := reg.LinkToSLO("missing", "slo-1")
	if err == nil {
		t.Fatal("expected error for missing SLI")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Timeline with 1000 entries
// ────────────────────────────────────────────────────────────────────────

func TestStress_Timeline1000Entries(t *testing.T) {
	tl := NewAuditTimeline()
	for i := 0; i < 1000; i++ {
		_ = tl.Record(TimelineEntry{RunID: fmt.Sprintf("run-%d", i%10), TenantID: "t1", EntryType: EntryTypeAction, Summary: fmt.Sprintf("s-%d", i)})
	}
	if tl.Count() != 1000 {
		t.Fatalf("expected 1000, got %d", tl.Count())
	}
}

func TestStress_TimelineQueryByRunID(t *testing.T) {
	tl := NewAuditTimeline()
	for i := 0; i < 100; i++ {
		_ = tl.Record(TimelineEntry{RunID: "run-special", TenantID: "t1", EntryType: EntryTypeAction, Summary: fmt.Sprintf("s-%d", i)})
	}
	for i := 0; i < 100; i++ {
		_ = tl.Record(TimelineEntry{RunID: "run-other", TenantID: "t1", EntryType: EntryTypeAction, Summary: fmt.Sprintf("o-%d", i)})
	}
	results := tl.Query(TimelineQuery{RunID: "run-special"})
	if len(results) != 100 {
		t.Fatalf("expected 100, got %d", len(results))
	}
}

func TestStress_TimelineQueryByEntryType(t *testing.T) {
	tl := NewAuditTimeline()
	_ = tl.Record(TimelineEntry{RunID: "r1", EntryType: EntryTypeDecision, Summary: "d"})
	_ = tl.Record(TimelineEntry{RunID: "r1", EntryType: EntryTypeAction, Summary: "a"})
	eType := EntryTypeDecision
	results := tl.Query(TimelineQuery{RunID: "r1", EntryType: &eType})
	if len(results) != 1 {
		t.Fatalf("expected 1 decision entry, got %d", len(results))
	}
}

func TestStress_TimelineQueryWithLimit(t *testing.T) {
	tl := NewAuditTimeline()
	for i := 0; i < 100; i++ {
		_ = tl.Record(TimelineEntry{RunID: "r1", EntryType: EntryTypeAction, Summary: fmt.Sprintf("s-%d", i)})
	}
	results := tl.Query(TimelineQuery{RunID: "r1", Limit: 10})
	if len(results) != 10 {
		t.Fatalf("expected 10, got %d", len(results))
	}
}

func TestStress_TimelineEntryContentHashSet(t *testing.T) {
	tl := NewAuditTimeline()
	_ = tl.Record(TimelineEntry{RunID: "r1", EntryType: EntryTypeProof, Summary: "proof"})
	results := tl.Query(TimelineQuery{RunID: "r1"})
	if len(results) != 1 || results[0].ContentHash == "" {
		t.Fatal("content hash not set")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Every entry type constant verified
// ────────────────────────────────────────────────────────────────────────

func TestStress_EntryTypeAction(t *testing.T) {
	if EntryTypeAction != "ACTION" {
		t.Fatal("ACTION mismatch")
	}
}

func TestStress_EntryTypeToolCall(t *testing.T) {
	if EntryTypeToolCall != "TOOL_CALL" {
		t.Fatal("TOOL_CALL mismatch")
	}
}

func TestStress_EntryTypeDecision(t *testing.T) {
	if EntryTypeDecision != "DECISION" {
		t.Fatal("DECISION mismatch")
	}
}

func TestStress_EntryTypeProof(t *testing.T) {
	if EntryTypeProof != "PROOF" {
		t.Fatal("PROOF mismatch")
	}
}

func TestStress_EntryTypeReconciliation(t *testing.T) {
	if EntryTypeReconciliation != "RECONCILIATION" {
		t.Fatal("RECONCILIATION mismatch")
	}
}

func TestStress_EntryTypeEscalation(t *testing.T) {
	if EntryTypeEscalation != "ESCALATION" {
		t.Fatal("ESCALATION mismatch")
	}
}

func TestStress_EntryTypeEvidence(t *testing.T) {
	if EntryTypeEvidence != "EVIDENCE" {
		t.Fatal("EVIDENCE mismatch")
	}
}

func TestStress_SLISourceConstants(t *testing.T) {
	if SLISourceMetric != "METRIC" || SLISourceLog != "LOG" || SLISourceTrace != "TRACE" || SLISourceProbe != "PROBE" {
		t.Fatal("SLI source constants mismatch")
	}
}

func TestStress_TimelineQueryByTenantID(t *testing.T) {
	tl := NewAuditTimeline()
	_ = tl.Record(TimelineEntry{TenantID: "t1", EntryType: EntryTypeAction, Summary: "a"})
	_ = tl.Record(TimelineEntry{TenantID: "t2", EntryType: EntryTypeAction, Summary: "b"})
	results := tl.Query(TimelineQuery{TenantID: "t1"})
	if len(results) != 1 {
		t.Fatalf("expected 1, got %d", len(results))
	}
}

func TestStress_TimelineQueryAfterBefore(t *testing.T) {
	tl := NewAuditTimeline()
	now := time.Now()
	_ = tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "old", Timestamp: now.Add(-2 * time.Hour)})
	_ = tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "new", Timestamp: now})
	after := now.Add(-time.Hour)
	results := tl.Query(TimelineQuery{After: &after})
	if len(results) != 1 || results[0].Summary != "new" {
		t.Fatalf("expected 'new', got %v", results)
	}
}

func TestStress_TimelineQueryNoResults(t *testing.T) {
	tl := NewAuditTimeline()
	results := tl.Query(TimelineQuery{RunID: "nonexistent"})
	if len(results) != 0 {
		t.Fatal("expected no results")
	}
}

func TestStress_TimelineEntryAutoID(t *testing.T) {
	tl := NewAuditTimeline()
	_ = tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "auto"})
	results := tl.Query(TimelineQuery{})
	if results[0].EntryID == "" {
		t.Fatal("auto-generated entry ID should not be empty")
	}
}

func TestStress_SLOTrackerWithClock(t *testing.T) {
	fixed := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	tracker := NewSLOTracker().WithClock(func() time.Time { return fixed })
	tracker.SetTarget(&SLOTarget{SLOID: "s", Name: "n", Operation: "op", LatencyP99: time.Second, SuccessRate: 0.9, WindowHours: 24})
	tracker.Record(SLOObservation{Operation: "op", Latency: time.Millisecond, Success: true})
	status, _ := tracker.Status("op")
	if status.ObservationCount != 1 {
		t.Fatal("expected 1 observation with clock override")
	}
}

func TestStress_SLOLatencyViolation(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{SLOID: "s", Name: "n", Operation: "op", LatencyP99: 10 * time.Millisecond, SuccessRate: 0.5, WindowHours: 24})
	for i := 0; i < 100; i++ {
		tracker.Record(SLOObservation{Operation: "op", Latency: 500 * time.Millisecond, Success: true, Timestamp: time.Now()})
	}
	status, _ := tracker.Status("op")
	if status.InCompliance {
		t.Fatal("expected non-compliance due to latency violation")
	}
}

func TestStress_TimelineWithClockOverride(t *testing.T) {
	fixed := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	tl := NewAuditTimeline().WithClock(func() time.Time { return fixed })
	_ = tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "clocked"})
	results := tl.Query(TimelineQuery{})
	if !results[0].Timestamp.Equal(fixed) {
		t.Fatal("clock override not applied to timeline")
	}
}
