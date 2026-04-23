package effects

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mockClock returns a clock function and a time-advance function for
// deterministic testing.
func mockClock(start time.Time) (clock func() time.Time, advance func(d time.Duration)) {
	mu := sync.Mutex{}
	now := start
	clock = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance = func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}
	return clock, advance
}

// mustAllow is a test helper that calls Allow and fails the test if it
// returns an error.
func mustAllow(t *testing.T, cb *CircuitBreaker) {
	t.Helper()
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected Allow() to succeed, got: %v", err)
	}
}

// mustDeny is a test helper that calls Allow and fails the test if it does
// NOT return ErrCircuitOpen.
func mustDeny(t *testing.T, cb *CircuitBreaker) {
	t.Helper()
	err := cb.Allow()
	if err == nil {
		t.Fatal("expected Allow() to return ErrCircuitOpen, got nil")
	}
	var errOpen *ErrCircuitOpen
	if !errors.As(err, &errOpen) {
		t.Fatalf("expected ErrCircuitOpen, got: %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// State transition tests
// ---------------------------------------------------------------------------

func TestCircuitBreaker_CLOSED_to_OPEN_to_HALFOPEN_to_CLOSED(t *testing.T) {
	clock, advance := mockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	cb := NewCircuitBreaker("test-conn",
		WithFailureThreshold(3),
		WithRecoveryTimeout(10*time.Second),
		WithBreakerClock(clock),
	)

	// Start CLOSED.
	if s := cb.State(); s != CircuitStateClosed {
		t.Fatalf("expected CLOSED, got %s", s)
	}

	// Record 3 failures — should trip to OPEN.
	for i := 0; i < 3; i++ {
		mustAllow(t, cb)
		cb.RecordFailure()
	}
	if s := cb.State(); s != CircuitStateOpen {
		t.Fatalf("expected OPEN after 3 failures, got %s", s)
	}

	// Requests should be denied.
	mustDeny(t, cb)

	// Advance past recovery timeout.
	advance(11 * time.Second)

	// Next Allow should transition to HALF_OPEN and succeed.
	mustAllow(t, cb)
	if s := cb.State(); s != CircuitStateHalfOpen {
		t.Fatalf("expected HALF_OPEN after recovery timeout, got %s", s)
	}

	// Record success — should close the circuit.
	cb.RecordSuccess()
	if s := cb.State(); s != CircuitStateClosed {
		t.Fatalf("expected CLOSED after successful probe, got %s", s)
	}

	// Normal operation resumes.
	mustAllow(t, cb)
}

func TestCircuitBreaker_HALFOPEN_to_OPEN_on_ProbeFailure(t *testing.T) {
	clock, advance := mockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	cb := NewCircuitBreaker("test-conn",
		WithFailureThreshold(2),
		WithRecoveryTimeout(5*time.Second),
		WithBreakerClock(clock),
	)

	// Trip to OPEN.
	mustAllow(t, cb)
	cb.RecordFailure()
	mustAllow(t, cb)
	cb.RecordFailure()
	if s := cb.State(); s != CircuitStateOpen {
		t.Fatalf("expected OPEN, got %s", s)
	}

	// Advance past recovery.
	advance(6 * time.Second)

	// Allow transitions to HALF_OPEN.
	mustAllow(t, cb)
	if s := cb.State(); s != CircuitStateHalfOpen {
		t.Fatalf("expected HALF_OPEN, got %s", s)
	}

	// Probe fails — back to OPEN.
	cb.RecordFailure()
	if s := cb.State(); s != CircuitStateOpen {
		t.Fatalf("expected OPEN after probe failure, got %s", s)
	}
}

// ---------------------------------------------------------------------------
// Failure threshold tests
// ---------------------------------------------------------------------------

func TestCircuitBreaker_FailureThreshold_NotReachedStaysClosed(t *testing.T) {
	cb := NewCircuitBreaker("test-conn", WithFailureThreshold(5))

	for i := 0; i < 4; i++ {
		cb.RecordFailure()
	}
	if s := cb.State(); s != CircuitStateClosed {
		t.Fatalf("expected CLOSED with 4/5 failures, got %s", s)
	}
}

func TestCircuitBreaker_FailureThreshold_ExactlyReachedTrips(t *testing.T) {
	cb := NewCircuitBreaker("test-conn", WithFailureThreshold(5))

	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}
	if s := cb.State(); s != CircuitStateOpen {
		t.Fatalf("expected OPEN at 5/5 failures, got %s", s)
	}
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	cb := NewCircuitBreaker("test-conn", WithFailureThreshold(3))

	cb.RecordFailure()
	cb.RecordFailure()
	// 2 failures, then a success should reset.
	cb.RecordSuccess()

	stats := cb.Stats()
	if stats.FailureCount != 0 {
		t.Fatalf("expected failure count 0 after success, got %d", stats.FailureCount)
	}

	// Need 3 more failures to trip.
	cb.RecordFailure()
	cb.RecordFailure()
	if s := cb.State(); s != CircuitStateClosed {
		t.Fatalf("expected CLOSED with 2 new failures, got %s", s)
	}
	cb.RecordFailure()
	if s := cb.State(); s != CircuitStateOpen {
		t.Fatalf("expected OPEN with 3 failures, got %s", s)
	}
}

// ---------------------------------------------------------------------------
// Recovery timeout tests
// ---------------------------------------------------------------------------

func TestCircuitBreaker_RecoveryTimeout_DeniedBeforeTimeout(t *testing.T) {
	clock, _ := mockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	cb := NewCircuitBreaker("test-conn",
		WithFailureThreshold(1),
		WithRecoveryTimeout(30*time.Second),
		WithBreakerClock(clock),
	)

	cb.RecordFailure()
	mustDeny(t, cb)
}

func TestCircuitBreaker_RecoveryTimeout_AllowedAfterTimeout(t *testing.T) {
	clock, advance := mockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	cb := NewCircuitBreaker("test-conn",
		WithFailureThreshold(1),
		WithRecoveryTimeout(30*time.Second),
		WithBreakerClock(clock),
	)

	cb.RecordFailure()
	advance(31 * time.Second)
	mustAllow(t, cb)
	if s := cb.State(); s != CircuitStateHalfOpen {
		t.Fatalf("expected HALF_OPEN, got %s", s)
	}
}

func TestCircuitBreaker_RecoveryTimeout_ExactBoundary(t *testing.T) {
	clock, advance := mockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	cb := NewCircuitBreaker("test-conn",
		WithFailureThreshold(1),
		WithRecoveryTimeout(10*time.Second),
		WithBreakerClock(clock),
	)

	cb.RecordFailure()

	// One nanosecond before timeout — should be denied.
	advance(10*time.Second - 1*time.Nanosecond)
	mustDeny(t, cb)

	// Exactly at timeout boundary — now.Before(recoveryAt) is false, so allowed.
	advance(1 * time.Nanosecond)
	mustAllow(t, cb)
}

// ---------------------------------------------------------------------------
// Half-open max attempts tests
// ---------------------------------------------------------------------------

func TestCircuitBreaker_HalfOpenMaxAttempts_LimitsProbes(t *testing.T) {
	clock, advance := mockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	cb := NewCircuitBreaker("test-conn",
		WithFailureThreshold(1),
		WithRecoveryTimeout(5*time.Second),
		WithHalfOpenMaxAttempts(3),
		WithSuccessThreshold(3),
		WithBreakerClock(clock),
	)

	// Trip to OPEN.
	cb.RecordFailure()
	advance(6 * time.Second)

	// First Allow transitions to HALF_OPEN and counts as attempt 1.
	mustAllow(t, cb)
	if s := cb.State(); s != CircuitStateHalfOpen {
		t.Fatalf("expected HALF_OPEN, got %s", s)
	}

	// Attempts 2 and 3 should be allowed.
	mustAllow(t, cb)
	mustAllow(t, cb)

	// Attempt 4 should be denied.
	mustDeny(t, cb)
}

// ---------------------------------------------------------------------------
// Success threshold tests
// ---------------------------------------------------------------------------

func TestCircuitBreaker_SuccessThreshold_MultipleRequired(t *testing.T) {
	clock, advance := mockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	cb := NewCircuitBreaker("test-conn",
		WithFailureThreshold(1),
		WithRecoveryTimeout(5*time.Second),
		WithHalfOpenMaxAttempts(3),
		WithSuccessThreshold(3),
		WithBreakerClock(clock),
	)

	// Trip to OPEN, advance to HALF_OPEN.
	cb.RecordFailure()
	advance(6 * time.Second)
	mustAllow(t, cb)

	// 1 success — still HALF_OPEN.
	cb.RecordSuccess()
	if s := cb.State(); s != CircuitStateHalfOpen {
		t.Fatalf("expected HALF_OPEN after 1/3 successes, got %s", s)
	}

	// 2 successes — still HALF_OPEN.
	cb.RecordSuccess()
	if s := cb.State(); s != CircuitStateHalfOpen {
		t.Fatalf("expected HALF_OPEN after 2/3 successes, got %s", s)
	}

	// 3 successes — should close.
	cb.RecordSuccess()
	if s := cb.State(); s != CircuitStateClosed {
		t.Fatalf("expected CLOSED after 3/3 successes, got %s", s)
	}
}

// ---------------------------------------------------------------------------
// Thread safety tests
// ---------------------------------------------------------------------------

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	cb := NewCircuitBreaker("concurrent-conn",
		WithFailureThreshold(100),
		WithRecoveryTimeout(1*time.Second),
	)

	const goroutines = 50
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent Allow calls.
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = cb.Allow()
			}
		}()
	}

	// Concurrent RecordSuccess calls.
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				cb.RecordSuccess()
			}
		}()
	}

	// Concurrent RecordFailure calls.
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				cb.RecordFailure()
			}
		}()
	}

	wg.Wait()

	// Verify we can still read stats without panic.
	_ = cb.Stats()
	_ = cb.State()
}

func TestCircuitBreaker_ConcurrentAllowAndRecord(t *testing.T) {
	clock, advance := mockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	cb := NewCircuitBreaker("concurrent-conn",
		WithFailureThreshold(3),
		WithRecoveryTimeout(5*time.Second),
		WithBreakerClock(clock),
	)

	// Trip to OPEN.
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}

	var wg sync.WaitGroup
	const goroutines = 20

	// Advance past recovery and fire concurrent probes + records.
	advance(6 * time.Second)

	wg.Add(goroutines * 3)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			_ = cb.Allow()
		}()
		go func() {
			defer wg.Done()
			cb.RecordSuccess()
		}()
		go func() {
			defer wg.Done()
			cb.RecordFailure()
		}()
	}

	wg.Wait()

	// No panic, no data race — that is the assertion (run with -race).
	state := cb.State()
	if state != CircuitStateClosed && state != CircuitStateOpen && state != CircuitStateHalfOpen {
		t.Fatalf("unexpected state: %s", state)
	}
}

// ---------------------------------------------------------------------------
// Reset tests
// ---------------------------------------------------------------------------

func TestCircuitBreaker_Reset_FromOpen(t *testing.T) {
	cb := NewCircuitBreaker("test-conn", WithFailureThreshold(1))

	cb.RecordFailure()
	if s := cb.State(); s != CircuitStateOpen {
		t.Fatalf("expected OPEN, got %s", s)
	}

	cb.Reset()
	if s := cb.State(); s != CircuitStateClosed {
		t.Fatalf("expected CLOSED after Reset, got %s", s)
	}

	stats := cb.Stats()
	if stats.FailureCount != 0 {
		t.Fatalf("expected 0 failures after Reset, got %d", stats.FailureCount)
	}
	if stats.SuccessCount != 0 {
		t.Fatalf("expected 0 successes after Reset, got %d", stats.SuccessCount)
	}
	if stats.HalfOpenAttempts != 0 {
		t.Fatalf("expected 0 half-open attempts after Reset, got %d", stats.HalfOpenAttempts)
	}

	// Should allow requests again.
	mustAllow(t, cb)
}

func TestCircuitBreaker_Reset_FromClosed_NoCallback(t *testing.T) {
	callbackCalled := false
	cb := NewCircuitBreaker("test-conn",
		WithStateChangeCallback(func(id string, from, to CircuitState) {
			callbackCalled = true
		}),
	)

	cb.Reset()
	if callbackCalled {
		t.Fatal("callback should not fire when resetting from CLOSED to CLOSED")
	}
}

// ---------------------------------------------------------------------------
// Stats tests
// ---------------------------------------------------------------------------

func TestCircuitBreaker_Stats_Accuracy(t *testing.T) {
	clock, advance := mockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	cb := NewCircuitBreaker("stats-conn",
		WithFailureThreshold(3),
		WithRecoveryTimeout(10*time.Second),
		WithBreakerClock(clock),
	)

	// Record some activity.
	cb.RecordSuccess()
	cb.RecordSuccess()
	advance(1 * time.Second)
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()

	stats := cb.Stats()

	if stats.ConnectorID != "stats-conn" {
		t.Fatalf("expected connector ID 'stats-conn', got %q", stats.ConnectorID)
	}
	if stats.State != CircuitStateOpen {
		t.Fatalf("expected OPEN, got %s", stats.State)
	}
	if stats.FailureCount != 3 {
		t.Fatalf("expected 3 failures, got %d", stats.FailureCount)
	}
	if stats.LastFailureTime.IsZero() {
		t.Fatal("expected non-zero last failure time")
	}
	if stats.LastStateChange.IsZero() {
		t.Fatal("expected non-zero last state change time")
	}
}

// ---------------------------------------------------------------------------
// State change callback tests
// ---------------------------------------------------------------------------

func TestCircuitBreaker_StateChangeCallback_Invoked(t *testing.T) {
	clock, advance := mockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	type transition struct {
		connectorID string
		from        CircuitState
		to          CircuitState
	}
	var transitions []transition
	var mu sync.Mutex

	cb := NewCircuitBreaker("cb-conn",
		WithFailureThreshold(2),
		WithRecoveryTimeout(5*time.Second),
		WithBreakerClock(clock),
		WithStateChangeCallback(func(id string, from, to CircuitState) {
			mu.Lock()
			defer mu.Unlock()
			transitions = append(transitions, transition{id, from, to})
		}),
	)

	// CLOSED → OPEN.
	cb.RecordFailure()
	cb.RecordFailure()

	// OPEN → HALF_OPEN.
	advance(6 * time.Second)
	mustAllow(t, cb)

	// HALF_OPEN → CLOSED.
	cb.RecordSuccess()

	mu.Lock()
	defer mu.Unlock()

	expected := []transition{
		{"cb-conn", CircuitStateClosed, CircuitStateOpen},
		{"cb-conn", CircuitStateOpen, CircuitStateHalfOpen},
		{"cb-conn", CircuitStateHalfOpen, CircuitStateClosed},
	}

	if len(transitions) != len(expected) {
		t.Fatalf("expected %d transitions, got %d: %+v", len(expected), len(transitions), transitions)
	}

	for i, exp := range expected {
		got := transitions[i]
		if got != exp {
			t.Errorf("transition[%d]: expected %+v, got %+v", i, exp, got)
		}
	}
}

func TestCircuitBreaker_StateChangeCallback_HalfOpenToOpen(t *testing.T) {
	clock, advance := mockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	type transition struct {
		from CircuitState
		to   CircuitState
	}
	var transitions []transition

	cb := NewCircuitBreaker("cb-conn",
		WithFailureThreshold(1),
		WithRecoveryTimeout(5*time.Second),
		WithBreakerClock(clock),
		WithStateChangeCallback(func(_ string, from, to CircuitState) {
			transitions = append(transitions, transition{from, to})
		}),
	)

	// CLOSED → OPEN.
	cb.RecordFailure()

	// OPEN → HALF_OPEN.
	advance(6 * time.Second)
	mustAllow(t, cb)

	// HALF_OPEN → OPEN (probe failure).
	cb.RecordFailure()

	expected := []transition{
		{CircuitStateClosed, CircuitStateOpen},
		{CircuitStateOpen, CircuitStateHalfOpen},
		{CircuitStateHalfOpen, CircuitStateOpen},
	}

	if len(transitions) != len(expected) {
		t.Fatalf("expected %d transitions, got %d", len(expected), len(transitions))
	}

	for i, exp := range expected {
		if transitions[i] != exp {
			t.Errorf("transition[%d]: expected %+v, got %+v", i, exp, transitions[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Default configuration tests
// ---------------------------------------------------------------------------

func TestCircuitBreaker_DefaultConfig(t *testing.T) {
	cb := NewCircuitBreaker("default-conn")

	if cb.failureThreshold != CircuitBreakerDefaultFailureThreshold {
		t.Fatalf("expected default failure threshold %d, got %d",
			CircuitBreakerDefaultFailureThreshold, cb.failureThreshold)
	}
	if cb.recoveryTimeout != CircuitBreakerDefaultRecoveryTimeout {
		t.Fatalf("expected default recovery timeout %s, got %s",
			CircuitBreakerDefaultRecoveryTimeout, cb.recoveryTimeout)
	}
	if cb.halfOpenMaxAttempts != CircuitBreakerDefaultHalfOpenMaxAttempts {
		t.Fatalf("expected default half-open max attempts %d, got %d",
			CircuitBreakerDefaultHalfOpenMaxAttempts, cb.halfOpenMaxAttempts)
	}
	if cb.successThreshold != CircuitBreakerDefaultSuccessThreshold {
		t.Fatalf("expected default success threshold %d, got %d",
			CircuitBreakerDefaultSuccessThreshold, cb.successThreshold)
	}
	if cb.state != CircuitStateClosed {
		t.Fatalf("expected initial state CLOSED, got %s", cb.state)
	}
}

// ---------------------------------------------------------------------------
// Custom configuration tests
// ---------------------------------------------------------------------------

func TestCircuitBreaker_CustomConfig(t *testing.T) {
	cb := NewCircuitBreaker("custom-conn",
		WithFailureThreshold(10),
		WithRecoveryTimeout(60*time.Second),
		WithHalfOpenMaxAttempts(5),
		WithSuccessThreshold(3),
	)

	if cb.failureThreshold != 10 {
		t.Fatalf("expected failure threshold 10, got %d", cb.failureThreshold)
	}
	if cb.recoveryTimeout != 60*time.Second {
		t.Fatalf("expected recovery timeout 60s, got %s", cb.recoveryTimeout)
	}
	if cb.halfOpenMaxAttempts != 5 {
		t.Fatalf("expected half-open max attempts 5, got %d", cb.halfOpenMaxAttempts)
	}
	if cb.successThreshold != 3 {
		t.Fatalf("expected success threshold 3, got %d", cb.successThreshold)
	}
}

func TestCircuitBreaker_InvalidOptions_Ignored(t *testing.T) {
	cb := NewCircuitBreaker("test-conn",
		WithFailureThreshold(0),    // Invalid, should keep default.
		WithFailureThreshold(-1),   // Invalid, should keep default.
		WithRecoveryTimeout(0),     // Invalid, should keep default.
		WithRecoveryTimeout(-1),    // Invalid, should keep default.
		WithHalfOpenMaxAttempts(0), // Invalid, should keep default.
		WithSuccessThreshold(0),    // Invalid, should keep default.
		WithBreakerClock(nil),      // Invalid, should keep default.
	)

	if cb.failureThreshold != CircuitBreakerDefaultFailureThreshold {
		t.Fatalf("expected default failure threshold after invalid option, got %d", cb.failureThreshold)
	}
	if cb.recoveryTimeout != CircuitBreakerDefaultRecoveryTimeout {
		t.Fatalf("expected default recovery timeout after invalid option, got %s", cb.recoveryTimeout)
	}
	if cb.halfOpenMaxAttempts != CircuitBreakerDefaultHalfOpenMaxAttempts {
		t.Fatalf("expected default half-open max attempts after invalid option, got %d", cb.halfOpenMaxAttempts)
	}
	if cb.successThreshold != CircuitBreakerDefaultSuccessThreshold {
		t.Fatalf("expected default success threshold after invalid option, got %d", cb.successThreshold)
	}
	if cb.clock == nil {
		t.Fatal("clock should not be nil after nil clock option")
	}
}

// ---------------------------------------------------------------------------
// Error type tests
// ---------------------------------------------------------------------------

func TestErrCircuitOpen_Error(t *testing.T) {
	err := &ErrCircuitOpen{
		ConnectorID:  "my-connector",
		FailureCount: 5,
		LastFailure:  time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		RecoveryAt:   time.Date(2026, 1, 1, 12, 0, 30, 0, time.UTC),
	}

	msg := err.Error()
	if msg == "" {
		t.Fatal("expected non-empty error message")
	}

	// Verify it implements the error interface.
	var e error = err
	if e == nil {
		t.Fatal("ErrCircuitOpen should implement error")
	}
}

func TestErrCircuitOpen_ErrorsAs(t *testing.T) {
	cb := NewCircuitBreaker("test-conn", WithFailureThreshold(1))
	cb.RecordFailure()

	err := cb.Allow()
	if err == nil {
		t.Fatal("expected error from Allow on open circuit")
	}

	var errOpen *ErrCircuitOpen
	if !errors.As(err, &errOpen) {
		t.Fatalf("expected errors.As to match ErrCircuitOpen, got %T", err)
	}

	if errOpen.ConnectorID != "test-conn" {
		t.Fatalf("expected connector ID 'test-conn', got %q", errOpen.ConnectorID)
	}
	if errOpen.FailureCount != 1 {
		t.Fatalf("expected failure count 1, got %d", errOpen.FailureCount)
	}
}

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

func TestCircuitBreakerRegistry_GetOrCreate(t *testing.T) {
	registry := NewCircuitBreakerRegistry(WithFailureThreshold(3))

	cb1 := registry.Get("connector-a")
	cb2 := registry.Get("connector-b")
	cb3 := registry.Get("connector-a")

	// Same connector should return same instance.
	if cb1 != cb3 {
		t.Fatal("expected same CircuitBreaker instance for same connector ID")
	}

	// Different connectors should return different instances.
	if cb1 == cb2 {
		t.Fatal("expected different CircuitBreaker instances for different connector IDs")
	}

	// Defaults should be applied.
	if cb1.failureThreshold != 3 {
		t.Fatalf("expected failure threshold 3 from registry defaults, got %d", cb1.failureThreshold)
	}
}

func TestCircuitBreakerRegistry_AllStats(t *testing.T) {
	registry := NewCircuitBreakerRegistry()

	cb1 := registry.Get("conn-1")
	cb2 := registry.Get("conn-2")

	cb1.RecordFailure()
	cb1.RecordFailure()
	cb2.RecordSuccess()

	stats := registry.AllStats()

	if len(stats) != 2 {
		t.Fatalf("expected 2 entries in AllStats, got %d", len(stats))
	}

	s1, ok := stats["conn-1"]
	if !ok {
		t.Fatal("expected stats for conn-1")
	}
	if s1.FailureCount != 2 {
		t.Fatalf("expected 2 failures for conn-1, got %d", s1.FailureCount)
	}

	s2, ok := stats["conn-2"]
	if !ok {
		t.Fatal("expected stats for conn-2")
	}
	if s2.SuccessCount != 1 {
		t.Fatalf("expected 1 success for conn-2, got %d", s2.SuccessCount)
	}
}

func TestCircuitBreakerRegistry_ResetAll(t *testing.T) {
	registry := NewCircuitBreakerRegistry(WithFailureThreshold(1))

	cb1 := registry.Get("conn-1")
	cb2 := registry.Get("conn-2")

	cb1.RecordFailure()
	cb2.RecordFailure()

	if cb1.State() != CircuitStateOpen || cb2.State() != CircuitStateOpen {
		t.Fatal("expected both breakers to be OPEN before reset")
	}

	registry.ResetAll()

	if cb1.State() != CircuitStateClosed {
		t.Fatalf("expected conn-1 CLOSED after ResetAll, got %s", cb1.State())
	}
	if cb2.State() != CircuitStateClosed {
		t.Fatalf("expected conn-2 CLOSED after ResetAll, got %s", cb2.State())
	}
}

func TestCircuitBreakerRegistry_ConcurrentGet(t *testing.T) {
	registry := NewCircuitBreakerRegistry()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	results := make([]*CircuitBreaker, goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			// All goroutines request the same connector.
			results[i] = registry.Get("shared-conn")
		}()
	}

	wg.Wait()

	// All should return the same instance.
	for i := 1; i < goroutines; i++ {
		if results[i] != results[0] {
			t.Fatalf("goroutine %d got different instance than goroutine 0", i)
		}
	}
}

func TestCircuitBreakerRegistry_ConcurrentGetDifferentConnectors(t *testing.T) {
	registry := NewCircuitBreakerRegistry()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("conn-%d", i%10)
			cb := registry.Get(id)
			_ = cb.Allow()
			cb.RecordSuccess()
		}()
	}

	wg.Wait()

	stats := registry.AllStats()
	if len(stats) != 10 {
		t.Fatalf("expected 10 unique connectors, got %d", len(stats))
	}
}

// ---------------------------------------------------------------------------
// Multiple independent circuit breakers
// ---------------------------------------------------------------------------

func TestCircuitBreaker_PerConnectorIsolation(t *testing.T) {
	clock, advance := mockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	cbA := NewCircuitBreaker("connector-a",
		WithFailureThreshold(2),
		WithRecoveryTimeout(5*time.Second),
		WithBreakerClock(clock),
	)
	cbB := NewCircuitBreaker("connector-b",
		WithFailureThreshold(2),
		WithRecoveryTimeout(5*time.Second),
		WithBreakerClock(clock),
	)

	// Trip connector A.
	cbA.RecordFailure()
	cbA.RecordFailure()

	// Connector A should be OPEN.
	if s := cbA.State(); s != CircuitStateOpen {
		t.Fatalf("expected connector-a OPEN, got %s", s)
	}

	// Connector B should still be CLOSED.
	if s := cbB.State(); s != CircuitStateClosed {
		t.Fatalf("expected connector-b CLOSED, got %s", s)
	}

	// B should allow requests.
	mustAllow(t, cbB)

	// A should deny.
	mustDeny(t, cbA)

	// Advance time and verify A can recover independently.
	advance(6 * time.Second)
	mustAllow(t, cbA)
	cbA.RecordSuccess()

	if s := cbA.State(); s != CircuitStateClosed {
		t.Fatalf("expected connector-a CLOSED after recovery, got %s", s)
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestCircuitBreaker_AllowInClosedState_AlwaysSucceeds(t *testing.T) {
	cb := NewCircuitBreaker("test-conn")

	for i := 0; i < 100; i++ {
		mustAllow(t, cb)
	}
}

func TestCircuitBreaker_RecordSuccess_InOpenState_Ignored(t *testing.T) {
	cb := NewCircuitBreaker("test-conn", WithFailureThreshold(1))

	cb.RecordFailure()
	if s := cb.State(); s != CircuitStateOpen {
		t.Fatalf("expected OPEN, got %s", s)
	}

	// Success while OPEN should not change state.
	cb.RecordSuccess()
	if s := cb.State(); s != CircuitStateOpen {
		t.Fatalf("expected still OPEN after success in OPEN state, got %s", s)
	}
}

func TestCircuitBreaker_MultipleResetsIdempotent(t *testing.T) {
	cb := NewCircuitBreaker("test-conn", WithFailureThreshold(1))

	cb.RecordFailure()
	cb.Reset()
	cb.Reset()
	cb.Reset()

	if s := cb.State(); s != CircuitStateClosed {
		t.Fatalf("expected CLOSED after multiple resets, got %s", s)
	}
	mustAllow(t, cb)
}

func TestCircuitBreaker_RecoveryAt_InError(t *testing.T) {
	clock, _ := mockClock(time.Date(2026, 4, 13, 10, 0, 0, 0, time.UTC))

	cb := NewCircuitBreaker("test-conn",
		WithFailureThreshold(1),
		WithRecoveryTimeout(30*time.Second),
		WithBreakerClock(clock),
	)

	cb.RecordFailure()

	err := cb.Allow()
	if err == nil {
		t.Fatal("expected error")
	}

	var errOpen *ErrCircuitOpen
	if !errors.As(err, &errOpen) {
		t.Fatalf("expected ErrCircuitOpen, got %T", err)
	}

	expectedRecovery := time.Date(2026, 4, 13, 10, 0, 30, 0, time.UTC)
	if !errOpen.RecoveryAt.Equal(expectedRecovery) {
		t.Fatalf("expected recovery at %s, got %s", expectedRecovery, errOpen.RecoveryAt)
	}
}
