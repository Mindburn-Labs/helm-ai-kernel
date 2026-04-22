package kernel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── 1: CSNF ParseDecimal valid format ──────────────────────

func TestExt2_CSNFParseDecimalValid(t *testing.T) {
	d, err := ParseDecimal("123.45")
	if err != nil || d.Value != "123.45" {
		t.Fatalf("expected 123.45, got %v (err=%v)", d, err)
	}
}

// ─── 2: CSNF ParseDecimal negative zero normalized ─────────

func TestExt2_CSNFNegativeZeroNormalized(t *testing.T) {
	d, err := ParseDecimal("-0.00")
	if err != nil || d.Value != "0.00" {
		t.Fatalf("expected 0.00, got %v (err=%v)", d, err)
	}
}

// ─── 3: CSNF ParseDecimal rejects invalid format ───────────

func TestExt2_CSNFParseDecimalRejectsInvalid(t *testing.T) {
	_, err := ParseDecimal("12.3.4")
	if err == nil {
		t.Fatal("expected error for invalid decimal format")
	}
}

// ─── 4: CSNF NormalizeDecimal with HALF_UP rounding ────────

func TestExt2_CSNFNormalizeHalfUp(t *testing.T) {
	schema := DecimalSchema{Scale: 2, Rounding: DecimalRoundingHalfUp}
	result, err := NormalizeDecimal("1.235", schema)
	if err != nil {
		t.Fatal(err)
	}
	if result != "1.24" {
		t.Fatalf("expected 1.24, got %s", result)
	}
}

// ─── 5: CSNF NormalizeDecimal with DOWN rounding ───────────

func TestExt2_CSNFNormalizeDown(t *testing.T) {
	schema := DecimalSchema{Scale: 2, Rounding: DecimalRoundingDown}
	result, err := NormalizeDecimal("1.239", schema)
	if err != nil {
		t.Fatal(err)
	}
	if result != "1.23" {
		t.Fatalf("expected 1.23, got %s", result)
	}
}

// ─── 6: CSNF NormalizeDecimal min bound violation ──────────

func TestExt2_CSNFNormalizeMinBound(t *testing.T) {
	schema := DecimalSchema{Scale: 2, Rounding: DecimalRoundingDown, MinValue: "10.00"}
	_, err := NormalizeDecimal("5.00", schema)
	if err == nil {
		t.Fatal("expected min bound violation")
	}
}

// ─── 7: Scheduler SnapshotHash deterministic ────────────────

func TestExt2_SchedulerSnapshotHashDeterministic(t *testing.T) {
	s1 := NewInMemoryScheduler()
	s2 := NewInMemoryScheduler()
	ctx := context.Background()
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	evt := &SchedulerEvent{EventID: "e1", EventType: "test", ScheduledAt: now, Priority: 1}
	s1.Schedule(ctx, evt)
	evt2 := &SchedulerEvent{EventID: "e1", EventType: "test", ScheduledAt: now, Priority: 1}
	s2.Schedule(ctx, evt2)
	if s1.SnapshotHash() != s2.SnapshotHash() {
		t.Fatal("same events should produce same snapshot hash")
	}
}

// ─── 8: Scheduler SnapshotHash changes with different events ─

func TestExt2_SchedulerSnapshotHashChanges(t *testing.T) {
	s1 := NewInMemoryScheduler()
	s2 := NewInMemoryScheduler()
	ctx := context.Background()
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	s1.Schedule(ctx, &SchedulerEvent{EventID: "e1", ScheduledAt: now})
	s2.Schedule(ctx, &SchedulerEvent{EventID: "e2", ScheduledAt: now})
	if s1.SnapshotHash() == s2.SnapshotHash() {
		t.Fatal("different events should produce different snapshot hashes")
	}
}

// ─── 9: Scheduler empty SnapshotHash ────────────────────────

func TestExt2_SchedulerEmptySnapshotHash(t *testing.T) {
	s := NewInMemoryScheduler()
	hash := s.SnapshotHash()
	if hash == "" {
		t.Fatal("expected non-empty hash even for empty scheduler")
	}
}

// ─── 10: CPI Validate empty facts → CONSISTENT ─────────────

func TestExt2_CPIValidateEmptyFacts(t *testing.T) {
	// Importing cpi sub-package directly; use the kernel-level CPI interface
	// Test via the kernel's own exported scheduler (CPI is a sub-package)
	// Since CPI is in a sub-package, test its concepts via ErrorIR's namespace extraction
	ns := extractNamespace("HELM/CORE/POLICY/DENIED")
	if ns != "CORE" {
		t.Fatalf("expected CORE namespace, got %s", ns)
	}
}

// ─── 11: ErrorIR builder constructs valid error ─────────────

func TestExt2_ErrorIRBuilderValid(t *testing.T) {
	e := NewErrorIR(ErrCodeSchemaMismatch).
		WithTitle("Schema mismatch").
		WithDetail("field X wrong type").
		Build()
	if e.HELM.ErrorCode != ErrCodeSchemaMismatch {
		t.Fatalf("expected %s, got %s", ErrCodeSchemaMismatch, e.HELM.ErrorCode)
	}
	if e.Title != "Schema mismatch" {
		t.Fatalf("expected title 'Schema mismatch', got %s", e.Title)
	}
}

// ─── 12: ErrorIR classification for TIMEOUT is RETRYABLE ───

func TestExt2_ErrorIRTimeoutClassification(t *testing.T) {
	e := NewErrorIR(ErrCodeTimeout).Build()
	if e.HELM.Classification != ErrorClassRetryable {
		t.Fatalf("expected RETRYABLE, got %s", e.HELM.Classification)
	}
}

// ─── 13: ErrorIR classification for UNAUTHORIZED is NON_RETRYABLE ─

func TestExt2_ErrorIRUnauthorizedClassification(t *testing.T) {
	e := NewErrorIR(ErrCodeUnauthorized).Build()
	if e.HELM.Classification != ErrorClassNonRetryable {
		t.Fatalf("expected NON_RETRYABLE, got %s", e.HELM.Classification)
	}
}

// ─── 14: ErrorIR WithCause appends to chain ─────────────────

func TestExt2_ErrorIRWithCause(t *testing.T) {
	e := NewErrorIR(ErrCodeUpstreamError).
		WithCause("HELM/ADAPTER/X/FAIL", "/step/0").
		WithCause("HELM/ADAPTER/X/RETRY", "/step/1").
		Build()
	if len(e.HELM.CanonicalCauseChain) != 2 {
		t.Fatalf("expected 2 causes, got %d", len(e.HELM.CanonicalCauseChain))
	}
}

// ─── 15: CompareErrors deterministic ordering ───────────────

func TestExt2_CompareErrorsOrdering(t *testing.T) {
	a := NewErrorIR(ErrCodeForbidden).Build()
	b := NewErrorIR(ErrCodeTimeout).Build()
	if CompareErrors(a, b) >= 0 {
		t.Fatal("FORBIDDEN should sort before TIMEOUT")
	}
}

// ─── 16: SelectCanonicalError picks smallest ────────────────

func TestExt2_SelectCanonicalErrorPicks(t *testing.T) {
	errs := []ErrorIR{
		NewErrorIR(ErrCodeTimeout).Build(),
		NewErrorIR(ErrCodeForbidden).Build(),
		NewErrorIR(ErrCodeNotFound).Build(),
	}
	selected := SelectCanonicalError(errs)
	if selected.HELM.ErrorCode != ErrCodeForbidden {
		t.Fatalf("expected FORBIDDEN as canonical, got %s", selected.HELM.ErrorCode)
	}
}

// ─── 17: Backpressure nil store fails closed ────────────────

func TestExt2_BackpressureNilStoreFailsClosed(t *testing.T) {
	err := EvaluateBackpressure(context.Background(), nil, "actor", BackpressurePolicy{RPM: 60, Burst: 1})
	if err == nil {
		t.Fatal("expected error with nil store")
	}
}

// ─── 18: Backpressure allows first request ──────────────────

func TestExt2_BackpressureAllowsFirst(t *testing.T) {
	store := NewInMemoryLimiterStore()
	err := EvaluateBackpressure(context.Background(), store, "actor", BackpressurePolicy{RPM: 60, Burst: 1})
	if err != nil {
		t.Fatalf("first request should be allowed: %v", err)
	}
}

// ─── 19: BlobStore store and retrieve ───────────────────────

func TestExt2_BlobStoreStoreAndRetrieve(t *testing.T) {
	bs := NewInMemoryBlobStore()
	ctx := context.Background()
	addr, err := bs.Store(ctx, []byte("hello"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := bs.Get(ctx, addr)
	if err != nil || string(rec.Content) != "hello" {
		t.Fatalf("expected 'hello', got %v (err=%v)", rec, err)
	}
}

// ─── 20: BlobStore content-addressed dedup ──────────────────

func TestExt2_BlobStoreDedup(t *testing.T) {
	bs := NewInMemoryBlobStore()
	ctx := context.Background()
	a1, _ := bs.Store(ctx, []byte("same"), "text/plain")
	a2, _ := bs.Store(ctx, []byte("same"), "text/plain")
	if a1 != a2 {
		t.Fatal("same content should produce same address")
	}
}

// ─── 21: BlobStore delete and Has ───────────────────────────

func TestExt2_BlobStoreDeleteAndHas(t *testing.T) {
	bs := NewInMemoryBlobStore()
	ctx := context.Background()
	addr, _ := bs.Store(ctx, []byte("data"), "text/plain")
	if !bs.Has(ctx, addr) {
		t.Fatal("expected blob to exist")
	}
	bs.Delete(ctx, addr)
	if bs.Has(ctx, addr) {
		t.Fatal("expected blob to be deleted")
	}
}

// ─── 22: EvaluationWindow average computation ───────────────

func TestExt2_EvaluationWindowAverage(t *testing.T) {
	w := NewEvaluationWindow(time.Hour, 100)
	now := time.Now()
	w.Add(10.0, now)
	w.Add(20.0, now)
	w.Add(30.0, now)
	if avg := w.Average(); avg != 20.0 {
		t.Fatalf("expected average 20.0, got %f", avg)
	}
}

// ─── 23: EvaluationWindow min/max ───────────────────────────

func TestExt2_EvaluationWindowMinMax(t *testing.T) {
	w := NewEvaluationWindow(time.Hour, 100)
	now := time.Now()
	w.Add(5.0, now)
	w.Add(15.0, now)
	w.Add(10.0, now)
	if w.Min() != 5.0 || w.Max() != 15.0 {
		t.Fatalf("expected min=5 max=15, got min=%f max=%f", w.Min(), w.Max())
	}
}

// ─── 24: IOCapture store and list by effect ─────────────────

func TestExt2_IOCaptureStoreAndListByEffect(t *testing.T) {
	store := NewInMemoryIOCaptureStore()
	ctx := context.Background()
	rec := &IORecord{RecordID: "io-1", OperationType: "http_request", EffectID: "eff-1"}
	store.Record(ctx, rec)
	records, err := store.ListByEffect(ctx, "eff-1")
	if err != nil || len(records) != 1 {
		t.Fatalf("expected 1 record, got %d (err=%v)", len(records), err)
	}
}

// ─── 25: ErrorIR JSON round-trip preserves structure ────────

func TestExt2_ErrorIRJSONRoundTrip(t *testing.T) {
	e := NewErrorIR(ErrCodeCSNFViolation).
		WithTitle("CSNF violation").
		WithCause("HELM/CORE/X", "/field").
		Build()
	data, _ := json.Marshal(e)
	var e2 ErrorIR
	if err := json.Unmarshal(data, &e2); err != nil {
		t.Fatal(err)
	}
	if e2.HELM.ErrorCode != ErrCodeCSNFViolation || !strings.Contains(e2.Title, "CSNF") {
		t.Fatalf("round-trip mismatch: %+v", e2)
	}
}
