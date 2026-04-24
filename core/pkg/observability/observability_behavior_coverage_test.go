package observability

import (
	"strings"
	"testing"
	"time"
)

// ── SLOTracker: NewSLOTracker ──

func TestNewSLOTrackerReturnsNonNil(t *testing.T) {
	tr := NewSLOTracker()
	if tr == nil {
		t.Fatal("expected non-nil tracker")
	}
}

func TestNewSLOTrackerEmptyTargets(t *testing.T) {
	tr := NewSLOTracker()
	_, err := tr.Status("anything")
	if err == nil {
		t.Fatal("expected error when no targets registered")
	}
}

func TestNewSLOTrackerInitializesMaps(t *testing.T) {
	tr := NewSLOTracker()
	if tr.targets == nil || tr.observations == nil {
		t.Fatal("expected initialized maps")
	}
}

// ── SLOTracker: SetTarget ──

func TestSetTargetRegistersOperation(t *testing.T) {
	tr := NewSLOTracker()
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "compile", LatencyP99: 100 * time.Millisecond, SuccessRate: 0.99, WindowHours: 1})
	if _, ok := tr.targets["compile"]; !ok {
		t.Fatal("expected compile target to be registered")
	}
}

func TestSetTargetOverwritesPrevious(t *testing.T) {
	tr := NewSLOTracker()
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "compile", LatencyP99: 100 * time.Millisecond, SuccessRate: 0.99, WindowHours: 1})
	tr.SetTarget(&SLOTarget{SLOID: "s2", Operation: "compile", LatencyP99: 200 * time.Millisecond, SuccessRate: 0.95, WindowHours: 2})
	if tr.targets["compile"].SLOID != "s2" {
		t.Fatal("expected overwritten target")
	}
}

func TestSetTargetMultipleOperations(t *testing.T) {
	tr := NewSLOTracker()
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "compile", LatencyP99: 100 * time.Millisecond, SuccessRate: 0.99, WindowHours: 1})
	tr.SetTarget(&SLOTarget{SLOID: "s2", Operation: "execute", LatencyP99: 200 * time.Millisecond, SuccessRate: 0.95, WindowHours: 1})
	if len(tr.targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(tr.targets))
	}
}

// ── SLOTracker: Record ──

func TestRecordAddsObservation(t *testing.T) {
	tr := NewSLOTracker()
	tr.Record(SLOObservation{Operation: "compile", Latency: 10 * time.Millisecond, Success: true})
	if len(tr.observations["compile"]) != 1 {
		t.Fatal("expected 1 observation")
	}
}

func TestRecordSetsTimestampWhenZero(t *testing.T) {
	fixed := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	tr := NewSLOTracker().WithClock(func() time.Time { return fixed })
	tr.Record(SLOObservation{Operation: "compile", Latency: 5 * time.Millisecond, Success: true})
	if !tr.observations["compile"][0].Timestamp.Equal(fixed) {
		t.Fatal("expected clock-provided timestamp")
	}
}

func TestRecordPreservesExplicitTimestamp(t *testing.T) {
	explicit := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	tr := NewSLOTracker()
	tr.Record(SLOObservation{Operation: "compile", Latency: 5 * time.Millisecond, Success: true, Timestamp: explicit})
	if !tr.observations["compile"][0].Timestamp.Equal(explicit) {
		t.Fatal("expected explicit timestamp to be preserved")
	}
}

func TestRecordMultipleOperations(t *testing.T) {
	tr := NewSLOTracker()
	tr.Record(SLOObservation{Operation: "compile", Latency: 10 * time.Millisecond, Success: true})
	tr.Record(SLOObservation{Operation: "execute", Latency: 20 * time.Millisecond, Success: true})
	if len(tr.observations["compile"]) != 1 || len(tr.observations["execute"]) != 1 {
		t.Fatal("expected 1 observation per operation")
	}
}

// ── SLOTracker: Status ──

func TestStatusErrorForUnknownOperation(t *testing.T) {
	tr := NewSLOTracker()
	_, err := tr.Status("nope")
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatal("expected error mentioning the operation")
	}
}

func TestStatusNoObservationsIsCompliant(t *testing.T) {
	tr := NewSLOTracker()
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "plan", LatencyP99: 500 * time.Millisecond, SuccessRate: 0.99, WindowHours: 1})
	st, _ := tr.Status("plan")
	if !st.InCompliance || st.ErrorBudgetLeft != 100.0 || st.ObservationCount != 0 {
		t.Fatal("empty tracker should report full compliance")
	}
}

func TestStatusReturnsCorrectSLOID(t *testing.T) {
	tr := NewSLOTracker()
	tr.SetTarget(&SLOTarget{SLOID: "my-slo", Operation: "verify", LatencyP99: 1 * time.Second, SuccessRate: 0.9, WindowHours: 1})
	tr.Record(SLOObservation{Operation: "verify", Latency: 10 * time.Millisecond, Success: true})
	st, _ := tr.Status("verify")
	if st.SLOID != "my-slo" {
		t.Fatalf("expected SLOID my-slo, got %s", st.SLOID)
	}
}

func TestStatusBurnRateBelowOne(t *testing.T) {
	tr := NewSLOTracker()
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "compile", LatencyP99: 1 * time.Second, SuccessRate: 0.90, WindowHours: 1})
	for i := 0; i < 100; i++ {
		tr.Record(SLOObservation{Operation: "compile", Latency: 10 * time.Millisecond, Success: true})
	}
	st, _ := tr.Status("compile")
	if st.BurnRate > 0.01 {
		t.Fatalf("expected burn rate ~0, got %.4f", st.BurnRate)
	}
}

func TestStatusErrorBudgetExhausted(t *testing.T) {
	tr := NewSLOTracker()
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "execute", LatencyP99: 1 * time.Second, SuccessRate: 0.99, WindowHours: 1})
	for i := 0; i < 90; i++ {
		tr.Record(SLOObservation{Operation: "execute", Latency: 10 * time.Millisecond, Success: true})
	}
	for i := 0; i < 10; i++ {
		tr.Record(SLOObservation{Operation: "execute", Latency: 10 * time.Millisecond, Success: false})
	}
	st, _ := tr.Status("execute")
	if st.ErrorBudgetLeft != 0.0 {
		t.Fatalf("expected 0%% budget left, got %.2f", st.ErrorBudgetLeft)
	}
}

func TestStatusP99LatencyComputation(t *testing.T) {
	tr := NewSLOTracker()
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "compile", LatencyP99: 1 * time.Second, SuccessRate: 0.9, WindowHours: 1})
	for i := 0; i < 99; i++ {
		tr.Record(SLOObservation{Operation: "compile", Latency: 10 * time.Millisecond, Success: true})
	}
	tr.Record(SLOObservation{Operation: "compile", Latency: 900 * time.Millisecond, Success: true})
	st, _ := tr.Status("compile")
	if st.CurrentP99 < 100 {
		t.Fatalf("expected p99 >= 100ms, got %.2fms", st.CurrentP99)
	}
}

func TestStatusLatencyBreachCausesNonCompliance(t *testing.T) {
	tr := NewSLOTracker()
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "compile", LatencyP99: 50 * time.Millisecond, SuccessRate: 0.9, WindowHours: 1})
	tr.Record(SLOObservation{Operation: "compile", Latency: 200 * time.Millisecond, Success: true})
	st, _ := tr.Status("compile")
	if st.InCompliance {
		t.Fatal("expected out of compliance due to high p99")
	}
}

func TestStatusObservationCountAccurate(t *testing.T) {
	tr := NewSLOTracker()
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "plan", LatencyP99: 1 * time.Second, SuccessRate: 0.9, WindowHours: 1})
	for i := 0; i < 7; i++ {
		tr.Record(SLOObservation{Operation: "plan", Latency: 5 * time.Millisecond, Success: true})
	}
	st, _ := tr.Status("plan")
	if st.ObservationCount != 7 {
		t.Fatalf("expected 7 observations, got %d", st.ObservationCount)
	}
}

func TestStatusSuccessRateComputation(t *testing.T) {
	tr := NewSLOTracker()
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "verify", LatencyP99: 1 * time.Second, SuccessRate: 0.5, WindowHours: 1})
	tr.Record(SLOObservation{Operation: "verify", Latency: 10 * time.Millisecond, Success: true})
	tr.Record(SLOObservation{Operation: "verify", Latency: 10 * time.Millisecond, Success: false})
	st, _ := tr.Status("verify")
	if st.CurrentSuccess != 0.5 {
		t.Fatalf("expected 50%% success rate, got %.2f", st.CurrentSuccess)
	}
}

// ── SLOTracker: WithClock ──

func TestWithClockReturnsSameTracker(t *testing.T) {
	tr := NewSLOTracker()
	tr2 := tr.WithClock(time.Now)
	if tr != tr2 {
		t.Fatal("WithClock should return same tracker for chaining")
	}
}

func TestWithClockAffectsWindowFiltering(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	tr := NewSLOTracker().WithClock(func() time.Time { return now })
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "compile", LatencyP99: 1 * time.Second, SuccessRate: 0.9, WindowHours: 1})
	old := now.Add(-2 * time.Hour)
	tr.Record(SLOObservation{Operation: "compile", Latency: 10 * time.Millisecond, Success: false, Timestamp: old})
	tr.Record(SLOObservation{Operation: "compile", Latency: 10 * time.Millisecond, Success: true})
	st, _ := tr.Status("compile")
	if st.ObservationCount != 1 {
		t.Fatalf("expected 1 in-window observation, got %d", st.ObservationCount)
	}
}

// ── SLIRegistry: NewSLIRegistry ──

func TestNewSLIRegistryReturnsNonNil(t *testing.T) {
	r := NewSLIRegistry()
	if r == nil {
		t.Fatal("expected non-nil registry")
	}
}

func TestNewSLIRegistryStartsEmpty(t *testing.T) {
	r := NewSLIRegistry()
	if r.Count() != 0 {
		t.Fatal("expected 0 SLIs")
	}
}

// ── SLIRegistry: Register ──

func TestRegisterValidSLI(t *testing.T) {
	r := NewSLIRegistry()
	err := r.Register(&SLI{SLIID: "sli-1", Name: "Latency", Operation: "compile", Source: SLISourceMetric, Unit: "ms"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRegisterEmptyIDFails(t *testing.T) {
	r := NewSLIRegistry()
	err := r.Register(&SLI{SLIID: "", Name: "X", Operation: "compile"})
	if err == nil {
		t.Fatal("expected error for empty SLIID")
	}
}

func TestRegisterEmptyNameFails(t *testing.T) {
	r := NewSLIRegistry()
	err := r.Register(&SLI{SLIID: "s1", Name: "", Operation: "compile"})
	if err == nil {
		t.Fatal("expected error for empty Name")
	}
}

func TestRegisterEmptyOperationFails(t *testing.T) {
	r := NewSLIRegistry()
	err := r.Register(&SLI{SLIID: "s1", Name: "X", Operation: ""})
	if err == nil {
		t.Fatal("expected error for empty Operation")
	}
}

func TestRegisterOverwritesSameID(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{SLIID: "s1", Name: "A", Operation: "compile"})
	r.Register(&SLI{SLIID: "s1", Name: "B", Operation: "compile"})
	sli, _ := r.Get("s1")
	if sli.Name != "B" {
		t.Fatal("expected overwritten SLI")
	}
}

func TestRegisterIncreasesCount(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{SLIID: "s1", Name: "A", Operation: "compile"})
	r.Register(&SLI{SLIID: "s2", Name: "B", Operation: "execute"})
	if r.Count() != 2 {
		t.Fatalf("expected 2, got %d", r.Count())
	}
}

// ── SLIRegistry: Get ──

func TestGetExistingSLI(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{SLIID: "s1", Name: "Latency", Operation: "compile", Source: SLISourceTrace})
	sli, err := r.Get("s1")
	if err != nil || sli.Source != SLISourceTrace {
		t.Fatal("expected to retrieve registered SLI")
	}
}

func TestGetMissingSLIReturnsError(t *testing.T) {
	r := NewSLIRegistry()
	_, err := r.Get("missing")
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatal("expected error mentioning missing ID")
	}
}

// ── SLIRegistry: ByOperation ──

func TestByOperationReturnsMatchingSLIs(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{SLIID: "s1", Name: "A", Operation: "compile"})
	r.Register(&SLI{SLIID: "s2", Name: "B", Operation: "compile"})
	r.Register(&SLI{SLIID: "s3", Name: "C", Operation: "execute"})
	result := r.ByOperation("compile")
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
}

func TestByOperationReturnsNilForUnknown(t *testing.T) {
	r := NewSLIRegistry()
	result := r.ByOperation("nonexistent")
	if result != nil {
		t.Fatal("expected nil for unknown operation")
	}
}

func TestByOperationDoesNotCrossOperations(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{SLIID: "s1", Name: "A", Operation: "execute"})
	result := r.ByOperation("compile")
	if len(result) != 0 {
		t.Fatal("expected no results for different operation")
	}
}

// ── SLIRegistry: LinkToSLO ──

func TestLinkToSLOSuccess(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{SLIID: "s1", Name: "A", Operation: "compile"})
	err := r.LinkToSLO("s1", "slo-42")
	if err != nil {
		t.Fatal(err)
	}
	sli, _ := r.Get("s1")
	if sli.LinkedSLOID != "slo-42" {
		t.Fatal("expected linked SLO ID to be set")
	}
}

func TestLinkToSLOMissingSLIFails(t *testing.T) {
	r := NewSLIRegistry()
	err := r.LinkToSLO("no-such-sli", "slo-1")
	if err == nil {
		t.Fatal("expected error for missing SLI")
	}
}

func TestLinkToSLOOverwritesPrevious(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{SLIID: "s1", Name: "A", Operation: "compile"})
	r.LinkToSLO("s1", "slo-1")
	r.LinkToSLO("s1", "slo-2")
	sli, _ := r.Get("s1")
	if sli.LinkedSLOID != "slo-2" {
		t.Fatal("expected overwritten linked SLO")
	}
}

// ── AuditTimeline: NewAuditTimeline ──

func TestNewAuditTimelineReturnsNonNil(t *testing.T) {
	tl := NewAuditTimeline()
	if tl == nil {
		t.Fatal("expected non-nil timeline")
	}
}

func TestNewAuditTimelineStartsEmpty(t *testing.T) {
	tl := NewAuditTimeline()
	if tl.Count() != 0 {
		t.Fatal("expected 0 entries")
	}
}

// ── AuditTimeline: Record (RecordEntry) ──

func TestRecordEntryAssignsAutoID(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "test"})
	results := tl.Query(TimelineQuery{})
	if results[0].EntryID == "" {
		t.Fatal("expected auto-assigned entry ID")
	}
}

func TestRecordEntryPreservesExplicitID(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryID: "custom-id", EntryType: EntryTypeAction, Summary: "test"})
	results := tl.Query(TimelineQuery{})
	if results[0].EntryID != "custom-id" {
		t.Fatal("expected custom entry ID preserved")
	}
}

func TestRecordEntryComputesContentHash(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeProof, Summary: "x", Details: map[string]interface{}{"k": "v"}})
	results := tl.Query(TimelineQuery{})
	if !strings.HasPrefix(results[0].ContentHash, "sha256:") {
		t.Fatal("expected sha256 content hash")
	}
}

func TestRecordEntryDifferentDetailsProduceDifferentHashes(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "a", Details: map[string]interface{}{"x": 1}})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "b", Details: map[string]interface{}{"x": 2}})
	results := tl.Query(TimelineQuery{})
	if results[0].ContentHash == results[1].ContentHash {
		t.Fatal("expected different hashes for different details")
	}
}

func TestRecordEntrySetsTimestampFromClock(t *testing.T) {
	fixed := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	tl := NewAuditTimeline().WithClock(func() time.Time { return fixed })
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "test"})
	results := tl.Query(TimelineQuery{})
	if !results[0].Timestamp.Equal(fixed) {
		t.Fatal("expected clock-injected timestamp")
	}
}

func TestRecordEntryPreservesExplicitTimestamp(t *testing.T) {
	explicit := time.Date(2025, 3, 15, 8, 0, 0, 0, time.UTC)
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Timestamp: explicit, Summary: "test"})
	results := tl.Query(TimelineQuery{})
	if !results[0].Timestamp.Equal(explicit) {
		t.Fatal("expected explicit timestamp preserved")
	}
}

func TestRecordEntryIncreasesCount(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "a"})
	tl.Record(TimelineEntry{EntryType: EntryTypeDecision, Summary: "b"})
	if tl.Count() != 2 {
		t.Fatalf("expected 2 entries, got %d", tl.Count())
	}
}

// ── AuditTimeline: Query by RunID ──

func TestQueryByRunIDFiltersCorrectly(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, RunID: "r1", Summary: "a"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, RunID: "r2", Summary: "b"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, RunID: "r1", Summary: "c"})
	results := tl.Query(TimelineQuery{RunID: "r1"})
	if len(results) != 2 {
		t.Fatalf("expected 2, got %d", len(results))
	}
}

func TestQueryByRunIDReturnsNilForUnknown(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, RunID: "r1", Summary: "a"})
	results := tl.Query(TimelineQuery{RunID: "nope"})
	if results != nil {
		t.Fatal("expected nil for unknown RunID")
	}
}

// ── AuditTimeline: Query by EntryType ──

func TestQueryByEntryTypeFiltersCorrectly(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, RunID: "r1", Summary: "a"})
	tl.Record(TimelineEntry{EntryType: EntryTypeEscalation, RunID: "r1", Summary: "b"})
	tl.Record(TimelineEntry{EntryType: EntryTypeEvidence, RunID: "r1", Summary: "c"})
	et := EntryTypeEscalation
	results := tl.Query(TimelineQuery{RunID: "r1", EntryType: &et})
	if len(results) != 1 || results[0].Summary != "b" {
		t.Fatal("expected single ESCALATION entry")
	}
}

func TestQueryAllEntryTypes(t *testing.T) {
	tl := NewAuditTimeline()
	types := []TimelineEntryType{EntryTypeAction, EntryTypeToolCall, EntryTypeDecision, EntryTypeProof, EntryTypeReconciliation, EntryTypeEscalation, EntryTypeEvidence}
	for _, et := range types {
		tl.Record(TimelineEntry{EntryType: et, RunID: "r1", Summary: string(et)})
	}
	results := tl.Query(TimelineQuery{RunID: "r1"})
	if len(results) != 7 {
		t.Fatalf("expected 7 entries, got %d", len(results))
	}
}

// ── AuditTimeline: Query by time range ──

func TestQueryAfterFiltersOlderEntries(t *testing.T) {
	tl := NewAuditTimeline()
	t1 := time.Date(2026, 1, 1, 8, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Timestamp: t1, Summary: "old"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Timestamp: t2, Summary: "new"})
	after := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	results := tl.Query(TimelineQuery{After: &after})
	if len(results) != 1 || results[0].Summary != "new" {
		t.Fatal("expected only entry after cutoff")
	}
}

func TestQueryBeforeFiltersNewerEntries(t *testing.T) {
	tl := NewAuditTimeline()
	t1 := time.Date(2026, 1, 1, 8, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 1, 16, 0, 0, 0, time.UTC)
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Timestamp: t1, Summary: "old"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Timestamp: t2, Summary: "new"})
	before := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	results := tl.Query(TimelineQuery{Before: &before})
	if len(results) != 1 || results[0].Summary != "old" {
		t.Fatal("expected only entry before cutoff")
	}
}

func TestQueryTimeRangeReturnsNothing(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Timestamp: time.Date(2026, 1, 1, 5, 0, 0, 0, time.UTC), Summary: "a"})
	after := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	before := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	results := tl.Query(TimelineQuery{After: &after, Before: &before})
	if len(results) != 0 {
		t.Fatal("expected 0 results outside time range")
	}
}

// ── AuditTimeline: Query with Limit ──

func TestQueryLimitTruncatesResults(t *testing.T) {
	tl := NewAuditTimeline()
	for i := 0; i < 20; i++ {
		tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "x"})
	}
	results := tl.Query(TimelineQuery{Limit: 5})
	if len(results) != 5 {
		t.Fatalf("expected 5, got %d", len(results))
	}
}

func TestQueryLimitZeroReturnsAll(t *testing.T) {
	tl := NewAuditTimeline()
	for i := 0; i < 4; i++ {
		tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "x"})
	}
	results := tl.Query(TimelineQuery{Limit: 0})
	if len(results) != 4 {
		t.Fatalf("expected 4 (no limit), got %d", len(results))
	}
}

func TestQueryLimitLargerThanResultsReturnsAll(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "x"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "y"})
	results := tl.Query(TimelineQuery{Limit: 100})
	if len(results) != 2 {
		t.Fatalf("expected 2, got %d", len(results))
	}
}

// ── AuditTimeline: Query sorted by timestamp ──

func TestQueryResultsSortedByTimestamp(t *testing.T) {
	tl := NewAuditTimeline()
	t3 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Timestamp: t3, Summary: "third"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Timestamp: t1, Summary: "first"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Timestamp: t2, Summary: "second"})
	results := tl.Query(TimelineQuery{})
	if results[0].Summary != "first" || results[1].Summary != "second" || results[2].Summary != "third" {
		t.Fatal("expected results sorted by timestamp")
	}
}

// ── AuditTimeline: Query combined filters ──

func TestQueryCombinedRunIDAndEntryType(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, RunID: "r1", Summary: "a"})
	tl.Record(TimelineEntry{EntryType: EntryTypeProof, RunID: "r1", Summary: "b"})
	tl.Record(TimelineEntry{EntryType: EntryTypeProof, RunID: "r2", Summary: "c"})
	et := EntryTypeProof
	results := tl.Query(TimelineQuery{RunID: "r1", EntryType: &et})
	if len(results) != 1 || results[0].Summary != "b" {
		t.Fatal("expected 1 PROOF in r1")
	}
}

func TestQueryCombinedTenantAndTimeRange(t *testing.T) {
	tl := NewAuditTimeline()
	t1 := time.Date(2026, 1, 1, 8, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 1, 16, 0, 0, 0, time.UTC)
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, TenantID: "t1", Timestamp: t1, Summary: "a"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, TenantID: "t1", Timestamp: t2, Summary: "b"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, TenantID: "t2", Timestamp: t1, Summary: "c"})
	after := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	results := tl.Query(TimelineQuery{TenantID: "t1", After: &after})
	if len(results) != 1 || results[0].Summary != "b" {
		t.Fatal("expected 1 result for t1 after cutoff")
	}
}

// ── AuditTimeline: WithClock ──

func TestAuditTimelineWithClockReturnsSame(t *testing.T) {
	tl := NewAuditTimeline()
	tl2 := tl.WithClock(time.Now)
	if tl != tl2 {
		t.Fatal("WithClock should return same instance")
	}
}

// ── AuditTimeline: Query empty timeline ──

func TestQueryEmptyTimelineReturnsNil(t *testing.T) {
	tl := NewAuditTimeline()
	results := tl.Query(TimelineQuery{})
	if results != nil {
		t.Fatal("expected nil from empty timeline query")
	}
}

// ── SLI source constants ──

func TestSLISourceConstants(t *testing.T) {
	sources := []SLISource{SLISourceMetric, SLISourceLog, SLISourceTrace, SLISourceProbe}
	seen := make(map[SLISource]bool)
	for _, s := range sources {
		if seen[s] {
			t.Fatalf("duplicate source constant: %s", s)
		}
		seen[s] = true
	}
}

// ── Timeline entry type constants ──

func TestTimelineEntryTypeConstants(t *testing.T) {
	types := []TimelineEntryType{EntryTypeAction, EntryTypeToolCall, EntryTypeDecision, EntryTypeProof, EntryTypeReconciliation, EntryTypeEscalation, EntryTypeEvidence}
	if len(types) != 7 {
		t.Fatalf("expected 7 entry types, got %d", len(types))
	}
}

// ── AuditTimeline: Record with nil Details ──

func TestRecordEntryNilDetailsProducesHash(t *testing.T) {
	tl := NewAuditTimeline()
	err := tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "no details"})
	if err != nil {
		t.Fatal(err)
	}
	results := tl.Query(TimelineQuery{})
	if !strings.HasPrefix(results[0].ContentHash, "sha256:") {
		t.Fatal("expected hash even with nil details")
	}
}

// ── SLO: Window filtering excludes old observations ──

func TestStatusWindowExcludesExpiredObservations(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	tr := NewSLOTracker().WithClock(func() time.Time { return now })
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "replay", LatencyP99: 1 * time.Second, SuccessRate: 0.9, WindowHours: 1})
	expired := now.Add(-3 * time.Hour)
	tr.Record(SLOObservation{Operation: "replay", Latency: 10 * time.Millisecond, Success: false, Timestamp: expired})
	recent := now.Add(-10 * time.Minute)
	tr.Record(SLOObservation{Operation: "replay", Latency: 10 * time.Millisecond, Success: true, Timestamp: recent})
	st, _ := tr.Status("replay")
	if st.ObservationCount != 1 || st.CurrentSuccess != 1.0 {
		t.Fatal("expected only in-window observation counted")
	}
}

// ── SLO: 100% success rate → zero burn rate ──

func TestStatusPerfectSuccessZeroBurnRate(t *testing.T) {
	tr := NewSLOTracker()
	tr.SetTarget(&SLOTarget{SLOID: "s1", Operation: "escalation", LatencyP99: 1 * time.Second, SuccessRate: 0.99, WindowHours: 1})
	for i := 0; i < 50; i++ {
		tr.Record(SLOObservation{Operation: "escalation", Latency: 5 * time.Millisecond, Success: true})
	}
	st, _ := tr.Status("escalation")
	if st.BurnRate != 0.0 {
		t.Fatalf("expected 0 burn rate, got %.4f", st.BurnRate)
	}
	if st.ErrorBudgetLeft != 100.0 {
		t.Fatalf("expected 100%% budget left, got %.2f", st.ErrorBudgetLeft)
	}
}

// ── SLI: Register preserves all fields ──

func TestRegisterPreservesAllFields(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{
		SLIID: "s1", Name: "P99", Operation: "execute",
		EssentialVariable: "exec_latency", Source: SLISourceProbe,
		Unit: "ms", GoodEventQuery: "status=ok", TotalEventQuery: "count(*)",
	})
	sli, _ := r.Get("s1")
	if sli.EssentialVariable != "exec_latency" || sli.GoodEventQuery != "status=ok" || sli.TotalEventQuery != "count(*)" {
		t.Fatal("expected all fields preserved")
	}
}

// ── AuditTimeline: sequential entry IDs ──

func TestRecordEntrySequentialAutoIDs(t *testing.T) {
	tl := NewAuditTimeline()
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "a"})
	tl.Record(TimelineEntry{EntryType: EntryTypeAction, Summary: "b"})
	results := tl.Query(TimelineQuery{})
	if results[0].EntryID == results[1].EntryID {
		t.Fatal("expected distinct auto IDs")
	}
}
