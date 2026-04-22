package observability

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func fixedClock() time.Time { return time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC) }

// ── 1-5: SLO with 1000 observations ────────────────────────────

func TestDeep_SLO1000Observations(t *testing.T) {
	tracker := NewSLOTracker().WithClock(fixedClock)
	tracker.SetTarget(&SLOTarget{
		SLOID: "slo-1", Name: "exec", Operation: "execute",
		LatencyP99: 100 * time.Millisecond, SuccessRate: 0.99, WindowHours: 24,
	})
	for i := 0; i < 1000; i++ {
		tracker.Record(SLOObservation{
			Operation: "execute", Latency: 10 * time.Millisecond, Success: true,
			Timestamp: fixedClock().Add(-time.Duration(i) * time.Second),
		})
	}
	status, err := tracker.Status("execute")
	if err != nil {
		t.Fatal(err)
	}
	if status.ObservationCount != 1000 {
		t.Fatalf("want 1000 observations got %d", status.ObservationCount)
	}
	if status.CurrentSuccess != 1.0 {
		t.Fatalf("100%% success got %f", status.CurrentSuccess)
	}
}

func TestDeep_SLO1000WithFailures(t *testing.T) {
	tracker := NewSLOTracker().WithClock(fixedClock)
	tracker.SetTarget(&SLOTarget{
		SLOID: "slo-1", Name: "exec", Operation: "execute",
		LatencyP99: 100 * time.Millisecond, SuccessRate: 0.99, WindowHours: 24,
	})
	for i := 0; i < 1000; i++ {
		tracker.Record(SLOObservation{
			Operation: "execute", Latency: 10 * time.Millisecond, Success: i >= 20,
			Timestamp: fixedClock().Add(-time.Duration(i) * time.Second),
		})
	}
	status, _ := tracker.Status("execute")
	// 20 failures out of 1000 = 0.98 success rate, below 0.99 target
	if status.InCompliance {
		t.Error("98% success should be out of compliance with 99% target")
	}
}

func TestDeep_SLONoTarget(t *testing.T) {
	tracker := NewSLOTracker()
	_, err := tracker.Status("unknown_op")
	if err == nil {
		t.Error("no target must return error")
	}
}

func TestDeep_SLONoObservations(t *testing.T) {
	tracker := NewSLOTracker().WithClock(fixedClock)
	tracker.SetTarget(&SLOTarget{
		SLOID: "slo-1", Operation: "execute", WindowHours: 24, SuccessRate: 0.99,
	})
	status, _ := tracker.Status("execute")
	if !status.InCompliance {
		t.Error("no observations should be in compliance")
	}
	if status.ErrorBudgetLeft != 100.0 {
		t.Fatalf("no observations = 100%% budget, got %f", status.ErrorBudgetLeft)
	}
}

func TestDeep_SLOWindowFiltering(t *testing.T) {
	tracker := NewSLOTracker().WithClock(fixedClock)
	tracker.SetTarget(&SLOTarget{
		SLOID: "slo-1", Operation: "execute", WindowHours: 1, SuccessRate: 0.99, LatencyP99: time.Second,
	})
	// Old observation outside window
	tracker.Record(SLOObservation{
		Operation: "execute", Latency: time.Millisecond, Success: false,
		Timestamp: fixedClock().Add(-2 * time.Hour),
	})
	// Recent observation inside window
	tracker.Record(SLOObservation{
		Operation: "execute", Latency: time.Millisecond, Success: true,
		Timestamp: fixedClock().Add(-30 * time.Minute),
	})
	status, _ := tracker.Status("execute")
	if status.ObservationCount != 1 {
		t.Fatalf("only 1 observation in window, got %d", status.ObservationCount)
	}
}

// ── 6-10: Burn rate precision at boundary ───────────────────────

func TestDeep_BurnRateExactBudget(t *testing.T) {
	tracker := NewSLOTracker().WithClock(fixedClock)
	tracker.SetTarget(&SLOTarget{
		SLOID: "slo-br", Operation: "plan", SuccessRate: 0.99,
		LatencyP99: time.Second, WindowHours: 24,
	})
	// 1% failure = exactly at error budget (1 - 0.99)
	for i := 0; i < 100; i++ {
		tracker.Record(SLOObservation{
			Operation: "plan", Latency: time.Millisecond, Success: i != 0,
			Timestamp: fixedClock().Add(-time.Duration(i) * time.Minute),
		})
	}
	status, _ := tracker.Status("plan")
	if status.BurnRate < 0.9 || status.BurnRate > 1.1 {
		t.Fatalf("burn rate should be ~1.0, got %f", status.BurnRate)
	}
}

func TestDeep_BurnRateDouble(t *testing.T) {
	tracker := NewSLOTracker().WithClock(fixedClock)
	tracker.SetTarget(&SLOTarget{
		SLOID: "slo-2x", Operation: "compile", SuccessRate: 0.99,
		LatencyP99: time.Second, WindowHours: 24,
	})
	// 2% failure = 2x burn rate
	for i := 0; i < 100; i++ {
		tracker.Record(SLOObservation{
			Operation: "compile", Latency: time.Millisecond, Success: i >= 2,
			Timestamp: fixedClock().Add(-time.Duration(i) * time.Minute),
		})
	}
	status, _ := tracker.Status("compile")
	if status.BurnRate < 1.5 || status.BurnRate > 2.5 {
		t.Fatalf("burn rate should be ~2.0, got %f", status.BurnRate)
	}
}

func TestDeep_ErrorBudgetExhausted(t *testing.T) {
	tracker := NewSLOTracker().WithClock(fixedClock)
	tracker.SetTarget(&SLOTarget{
		SLOID: "slo-ex", Operation: "verify", SuccessRate: 0.99,
		LatencyP99: time.Second, WindowHours: 24,
	})
	for i := 0; i < 100; i++ {
		tracker.Record(SLOObservation{
			Operation: "verify", Latency: time.Millisecond, Success: i >= 5,
			Timestamp: fixedClock().Add(-time.Duration(i) * time.Minute),
		})
	}
	status, _ := tracker.Status("verify")
	if status.ErrorBudgetLeft != 0 {
		t.Fatalf("5%% failure with 1%% budget should exhaust budget, got %f", status.ErrorBudgetLeft)
	}
}

func TestDeep_ErrorBudgetRecovery(t *testing.T) {
	tracker := NewSLOTracker().WithClock(fixedClock)
	tracker.SetTarget(&SLOTarget{
		SLOID: "slo-rec", Operation: "replay", SuccessRate: 0.95,
		LatencyP99: time.Second, WindowHours: 24,
	})
	// All successful
	for i := 0; i < 100; i++ {
		tracker.Record(SLOObservation{
			Operation: "replay", Latency: time.Millisecond, Success: true,
			Timestamp: fixedClock().Add(-time.Duration(i) * time.Minute),
		})
	}
	status, _ := tracker.Status("replay")
	if status.ErrorBudgetLeft != 100.0 {
		t.Fatalf("all success should give 100%% budget, got %f", status.ErrorBudgetLeft)
	}
}

func TestDeep_LatencyP99Compliance(t *testing.T) {
	tracker := NewSLOTracker().WithClock(fixedClock)
	tracker.SetTarget(&SLOTarget{
		SLOID: "slo-lat", Operation: "escalation", SuccessRate: 0.5,
		LatencyP99: 50 * time.Millisecond, WindowHours: 24,
	})
	for i := 0; i < 100; i++ {
		tracker.Record(SLOObservation{
			Operation: "escalation", Latency: time.Duration(i) * time.Millisecond, Success: true,
			Timestamp: fixedClock().Add(-time.Duration(i) * time.Minute),
		})
	}
	status, _ := tracker.Status("escalation")
	// p99 of 0..99ms is 99ms, target is 50ms → out of compliance
	if status.InCompliance {
		t.Error("p99 of 99ms should violate 50ms target")
	}
}

// ── 11-15: SLI with all 4 source types ──────────────────────────

func TestDeep_SLIMetricSource(t *testing.T) {
	reg := NewSLIRegistry()
	err := reg.Register(&SLI{SLIID: "sli-1", Name: "latency", Operation: "execute", Source: SLISourceMetric})
	if err != nil {
		t.Fatal(err)
	}
	sli, _ := reg.Get("sli-1")
	if sli.Source != SLISourceMetric {
		t.Error("source mismatch")
	}
}

func TestDeep_SLILogSource(t *testing.T) {
	reg := NewSLIRegistry()
	reg.Register(&SLI{SLIID: "sli-2", Name: "errors", Operation: "compile", Source: SLISourceLog})
	sli, _ := reg.Get("sli-2")
	if sli.Source != SLISourceLog {
		t.Error("source mismatch")
	}
}

func TestDeep_SLITraceSource(t *testing.T) {
	reg := NewSLIRegistry()
	reg.Register(&SLI{SLIID: "sli-3", Name: "spans", Operation: "plan", Source: SLISourceTrace})
	sli, _ := reg.Get("sli-3")
	if sli.Source != SLISourceTrace {
		t.Error("source mismatch")
	}
}

func TestDeep_SLIProbeSource(t *testing.T) {
	reg := NewSLIRegistry()
	reg.Register(&SLI{SLIID: "sli-4", Name: "health", Operation: "verify", Source: SLISourceProbe})
	sli, _ := reg.Get("sli-4")
	if sli.Source != SLISourceProbe {
		t.Error("source mismatch")
	}
}

func TestDeep_SLIRegistryByOperation(t *testing.T) {
	reg := NewSLIRegistry()
	reg.Register(&SLI{SLIID: "a", Name: "lat", Operation: "execute", Source: SLISourceMetric})
	reg.Register(&SLI{SLIID: "b", Name: "err", Operation: "execute", Source: SLISourceLog})
	reg.Register(&SLI{SLIID: "c", Name: "health", Operation: "verify", Source: SLISourceProbe})
	slis := reg.ByOperation("execute")
	if len(slis) != 2 {
		t.Fatalf("want 2 SLIs for execute got %d", len(slis))
	}
}

// ── 16-20: Timeline with 500 entries ────────────────────────────

func TestDeep_Timeline500Entries(t *testing.T) {
	tl := NewAuditTimeline().WithClock(fixedClock)
	for i := 0; i < 500; i++ {
		tl.Record(TimelineEntry{
			EntryType: EntryTypeAction,
			RunID:     fmt.Sprintf("run-%d", i%10),
			TenantID:  "tenant-1",
			Summary:   fmt.Sprintf("action-%d", i),
			Timestamp: fixedClock().Add(-time.Duration(500-i) * time.Second),
		})
	}
	if tl.Count() != 500 {
		t.Fatalf("want 500 entries got %d", tl.Count())
	}
}

func TestDeep_TimelineQueryByRunID(t *testing.T) {
	tl := NewAuditTimeline().WithClock(fixedClock)
	for i := 0; i < 500; i++ {
		tl.Record(TimelineEntry{
			EntryType: EntryTypeAction, RunID: fmt.Sprintf("run-%d", i%10), TenantID: "t1",
			Timestamp: fixedClock().Add(-time.Duration(500-i) * time.Second),
		})
	}
	results := tl.Query(TimelineQuery{RunID: "run-0"})
	if len(results) != 50 {
		t.Fatalf("want 50 results for run-0 got %d", len(results))
	}
}

func TestDeep_TimelineQueryByType(t *testing.T) {
	tl := NewAuditTimeline().WithClock(fixedClock)
	types := []TimelineEntryType{EntryTypeAction, EntryTypeToolCall, EntryTypeDecision, EntryTypeProof, EntryTypeEvidence}
	for i := 0; i < 500; i++ {
		tl.Record(TimelineEntry{
			EntryType: types[i%len(types)], RunID: "r1", TenantID: "t1",
			Timestamp: fixedClock().Add(-time.Duration(500-i) * time.Second),
		})
	}
	et := EntryTypeToolCall
	results := tl.Query(TimelineQuery{EntryType: &et})
	if len(results) != 100 {
		t.Fatalf("want 100 TOOL_CALL entries got %d", len(results))
	}
}

func TestDeep_TimelineQueryTimeRange(t *testing.T) {
	tl := NewAuditTimeline()
	base := fixedClock()
	for i := 0; i < 500; i++ {
		tl.Record(TimelineEntry{
			EntryType: EntryTypeAction, RunID: "r1", TenantID: "t1",
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}
	after := base.Add(100 * time.Second)
	before := base.Add(200 * time.Second)
	results := tl.Query(TimelineQuery{After: &after, Before: &before})
	for _, r := range results {
		if r.Timestamp.Before(after) || r.Timestamp.After(before) {
			t.Error("entry outside time range")
		}
	}
}

func TestDeep_TimelineQueryLimit(t *testing.T) {
	tl := NewAuditTimeline().WithClock(fixedClock)
	for i := 0; i < 500; i++ {
		tl.Record(TimelineEntry{
			EntryType: EntryTypeAction, RunID: "r1", TenantID: "t1",
			Timestamp: fixedClock().Add(time.Duration(i) * time.Second),
		})
	}
	results := tl.Query(TimelineQuery{Limit: 10})
	if len(results) != 10 {
		t.Fatalf("limit 10 should return 10 entries got %d", len(results))
	}
}

// ── 21-25: Edge cases and concurrency ───────────────────────────

func TestDeep_TimelineContentHash(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{
		EntryType: EntryTypeDecision, RunID: "r1", TenantID: "t1",
		Summary:   "decided",
		Details:   map[string]interface{}{"verdict": "ALLOW"},
	})
	results := tl.Query(TimelineQuery{RunID: "r1"})
	if len(results) != 1 {
		t.Fatal("expected 1 result")
	}
	if results[0].ContentHash == "" {
		t.Error("content hash should be computed")
	}
}

func TestDeep_TimelineAutoID(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, RunID: "r1"})
	results := tl.Query(TimelineQuery{RunID: "r1"})
	if results[0].EntryID == "" {
		t.Error("auto-generated entry ID should be set")
	}
}

func TestDeep_SLILinkToSLO(t *testing.T) {
	reg := NewSLIRegistry()
	reg.Register(&SLI{SLIID: "sli-x", Name: "lat", Operation: "execute"})
	err := reg.LinkToSLO("sli-x", "slo-1")
	if err != nil {
		t.Fatal(err)
	}
	sli, _ := reg.Get("sli-x")
	if sli.LinkedSLOID != "slo-1" {
		t.Error("link failed")
	}
}

func TestDeep_SLILinkNotFound(t *testing.T) {
	reg := NewSLIRegistry()
	err := reg.LinkToSLO("nonexistent", "slo-1")
	if err == nil {
		t.Error("link to nonexistent SLI must error")
	}
}

func TestDeep_ConcurrentSLORecords(t *testing.T) {
	tracker := NewSLOTracker().WithClock(fixedClock)
	tracker.SetTarget(&SLOTarget{
		SLOID: "slo-c", Operation: "execute", SuccessRate: 0.99,
		LatencyP99: time.Second, WindowHours: 24,
	})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tracker.Record(SLOObservation{
				Operation: "execute", Latency: time.Millisecond, Success: true,
				Timestamp: fixedClock().Add(-time.Duration(i) * time.Minute),
			})
		}(i)
	}
	wg.Wait()
	status, _ := tracker.Status("execute")
	if status.ObservationCount != 100 {
		t.Fatalf("want 100 concurrent observations got %d", status.ObservationCount)
	}
}
