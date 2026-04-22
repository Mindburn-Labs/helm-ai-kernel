package effects

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Circuit Breaker Design Invariants
//
// 1. Fail-closed default: a zero-value CircuitBreaker is in CLOSED state
//    (normal operation). Transitions to OPEN only on explicit failure threshold.
// 2. Thread-safe: all state mutations are serialized by sync.RWMutex.
//    Stats reads acquire only a read lock.
// 3. Deterministic in tests: clock injection via WithBreakerClock replaces
//    all time.Now() calls, enabling sub-second test execution.
// 4. Per-connector isolation: each CircuitBreaker instance tracks one
//    connector. CircuitBreakerRegistry manages the connector→breaker map.
// 5. No goroutines: state transitions are synchronous. The caller drives
//    the lifecycle through Allow / RecordSuccess / RecordFailure.
// 6. Recovery probe: OPEN → HALF_OPEN transition happens lazily in Allow()
//    after recoveryTimeout elapses. No background timer.

// CircuitState represents the current operating state of a circuit breaker.
type CircuitState string

const (
	// CircuitStateClosed is the normal operating state. Requests flow through.
	CircuitStateClosed CircuitState = "CLOSED"
	// CircuitStateOpen indicates the circuit is tripped. Requests are rejected fast.
	CircuitStateOpen CircuitState = "OPEN"
	// CircuitStateHalfOpen is the recovery probe state. A limited number of
	// requests are allowed through to test whether the downstream has recovered.
	CircuitStateHalfOpen CircuitState = "HALF_OPEN"
)

// Default circuit breaker configuration values.
const (
	CircuitBreakerDefaultFailureThreshold    = 5
	CircuitBreakerDefaultRecoveryTimeout     = 30 * time.Second
	CircuitBreakerDefaultHalfOpenMaxAttempts = 1
	CircuitBreakerDefaultSuccessThreshold    = 1
)

// ErrCircuitOpen is returned by Allow when the circuit breaker is in OPEN
// state and the recovery timeout has not yet elapsed.
type ErrCircuitOpen struct {
	ConnectorID  string
	FailureCount int
	LastFailure  time.Time
	RecoveryAt   time.Time
}

// Error implements the error interface.
func (e *ErrCircuitOpen) Error() string {
	return fmt.Sprintf(
		"circuit breaker open for connector %q: %d failures, recovery at %s",
		e.ConnectorID, e.FailureCount, e.RecoveryAt.Format(time.RFC3339),
	)
}

// CircuitBreakerStats is a point-in-time snapshot of circuit breaker metrics.
type CircuitBreakerStats struct {
	ConnectorID      string
	State            CircuitState
	FailureCount     int
	SuccessCount     int
	LastFailureTime  time.Time
	LastStateChange  time.Time
	HalfOpenAttempts int
}

// CircuitBreakerOption configures a CircuitBreaker via the functional options pattern.
type CircuitBreakerOption func(*CircuitBreaker)

// CircuitBreaker implements the circuit breaker pattern for the effects gateway.
// It protects connectors from cascading failures by fast-rejecting requests
// when a downstream connector is unhealthy.
//
// State machine:
//
//	CLOSED  ──(failures >= threshold)──▶  OPEN
//	OPEN    ──(recoveryTimeout elapsed)──▶  HALF_OPEN
//	HALF_OPEN ──(successes >= successThreshold)──▶  CLOSED
//	HALF_OPEN ──(any failure)──▶  OPEN
type CircuitBreaker struct {
	mu               sync.RWMutex
	state            CircuitState
	failureCount     int
	successCount     int
	lastFailureTime  time.Time
	lastStateChange  time.Time
	halfOpenAttempts int

	// Configuration
	failureThreshold    int
	recoveryTimeout     time.Duration
	halfOpenMaxAttempts int
	successThreshold    int

	// Observability
	connectorID   string
	clock         func() time.Time
	onStateChange func(connectorID string, from, to CircuitState)
}

// NewCircuitBreaker creates a circuit breaker for the given connector with
// optional configuration overrides. The breaker starts in CLOSED state.
func NewCircuitBreaker(connectorID string, opts ...CircuitBreakerOption) *CircuitBreaker {
	cb := &CircuitBreaker{
		state:               CircuitStateClosed,
		connectorID:         connectorID,
		failureThreshold:    CircuitBreakerDefaultFailureThreshold,
		recoveryTimeout:     CircuitBreakerDefaultRecoveryTimeout,
		halfOpenMaxAttempts: CircuitBreakerDefaultHalfOpenMaxAttempts,
		successThreshold:    CircuitBreakerDefaultSuccessThreshold,
		clock:               time.Now,
	}
	cb.lastStateChange = cb.clock()

	for _, opt := range opts {
		opt(cb)
	}

	return cb
}

// WithFailureThreshold sets the number of consecutive failures required to
// trip the circuit breaker from CLOSED to OPEN.
func WithFailureThreshold(n int) CircuitBreakerOption {
	return func(cb *CircuitBreaker) {
		if n > 0 {
			cb.failureThreshold = n
		}
	}
}

// WithRecoveryTimeout sets the duration the circuit stays OPEN before
// transitioning to HALF_OPEN on the next Allow call.
func WithRecoveryTimeout(d time.Duration) CircuitBreakerOption {
	return func(cb *CircuitBreaker) {
		if d > 0 {
			cb.recoveryTimeout = d
		}
	}
}

// WithHalfOpenMaxAttempts sets the maximum number of probe requests allowed
// through while in HALF_OPEN state.
func WithHalfOpenMaxAttempts(n int) CircuitBreakerOption {
	return func(cb *CircuitBreaker) {
		if n > 0 {
			cb.halfOpenMaxAttempts = n
		}
	}
}

// WithSuccessThreshold sets the number of consecutive successes required in
// HALF_OPEN state to transition back to CLOSED.
func WithSuccessThreshold(n int) CircuitBreakerOption {
	return func(cb *CircuitBreaker) {
		if n > 0 {
			cb.successThreshold = n
		}
	}
}

// WithBreakerClock injects a custom clock function, replacing time.Now for
// deterministic testing.
func WithBreakerClock(clock func() time.Time) CircuitBreakerOption {
	return func(cb *CircuitBreaker) {
		if clock != nil {
			cb.clock = clock
		}
	}
}

// WithStateChangeCallback registers a callback invoked on every state
// transition. The callback receives the connector ID and the previous/new states.
// The callback is invoked while the mutex is held; it MUST NOT call back into
// the circuit breaker.
func WithStateChangeCallback(fn func(connectorID string, from, to CircuitState)) CircuitBreakerOption {
	return func(cb *CircuitBreaker) {
		cb.onStateChange = fn
	}
}

// Allow checks whether a request should be permitted through the circuit breaker.
//
// In CLOSED state, all requests are allowed.
// In OPEN state, requests are rejected with ErrCircuitOpen unless the
// recovery timeout has elapsed, in which case the state transitions to HALF_OPEN.
// In HALF_OPEN state, requests are allowed up to halfOpenMaxAttempts.
func (cb *CircuitBreaker) Allow() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := cb.clock()

	switch cb.state {
	case CircuitStateClosed:
		return nil

	case CircuitStateOpen:
		recoveryAt := cb.lastFailureTime.Add(cb.recoveryTimeout)
		if now.Before(recoveryAt) {
			return &ErrCircuitOpen{
				ConnectorID:  cb.connectorID,
				FailureCount: cb.failureCount,
				LastFailure:  cb.lastFailureTime,
				RecoveryAt:   recoveryAt,
			}
		}
		// Recovery timeout elapsed — transition to HALF_OPEN.
		cb.transition(CircuitStateHalfOpen, now)
		cb.halfOpenAttempts = 1
		cb.successCount = 0
		return nil

	case CircuitStateHalfOpen:
		if cb.halfOpenAttempts >= cb.halfOpenMaxAttempts {
			return &ErrCircuitOpen{
				ConnectorID:  cb.connectorID,
				FailureCount: cb.failureCount,
				LastFailure:  cb.lastFailureTime,
				RecoveryAt:   cb.lastFailureTime.Add(cb.recoveryTimeout),
			}
		}
		cb.halfOpenAttempts++
		return nil

	default:
		// Defensive: unknown state should never occur but fail-closed if it does.
		slog.Error("circuit breaker in unknown state, failing closed",
			"connector_id", cb.connectorID,
			"state", string(cb.state),
		)
		return &ErrCircuitOpen{
			ConnectorID:  cb.connectorID,
			FailureCount: cb.failureCount,
			LastFailure:  cb.lastFailureTime,
			RecoveryAt:   now,
		}
	}
}

// RecordSuccess records a successful effect execution.
//
// In CLOSED state, the failure counter is reset.
// In HALF_OPEN state, the success counter is incremented. If it reaches the
// success threshold, the circuit transitions to CLOSED.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := cb.clock()

	switch cb.state {
	case CircuitStateClosed:
		cb.failureCount = 0
		cb.successCount++

	case CircuitStateHalfOpen:
		cb.successCount++
		if cb.successCount >= cb.successThreshold {
			cb.transition(CircuitStateClosed, now)
			cb.failureCount = 0
			cb.halfOpenAttempts = 0
			slog.Info("circuit breaker recovered",
				"connector_id", cb.connectorID,
			)
		}

	case CircuitStateOpen:
		// Success while OPEN should not happen (Allow rejects), but handle
		// gracefully. Do not change state — let the normal HALF_OPEN probe
		// path handle recovery.
		slog.Warn("circuit breaker received success while OPEN, ignoring",
			"connector_id", cb.connectorID,
		)
	}
}

// RecordFailure records a failed effect execution.
//
// In CLOSED state, the failure counter is incremented. If it reaches the
// failure threshold, the circuit transitions to OPEN.
// In HALF_OPEN state, any failure immediately transitions back to OPEN.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := cb.clock()

	cb.failureCount++
	cb.lastFailureTime = now

	switch cb.state {
	case CircuitStateClosed:
		if cb.failureCount >= cb.failureThreshold {
			cb.transition(CircuitStateOpen, now)
			slog.Warn("circuit breaker tripped",
				"connector_id", cb.connectorID,
				"failure_count", cb.failureCount,
			)
		}

	case CircuitStateHalfOpen:
		// Any failure in HALF_OPEN immediately re-opens the circuit.
		cb.transition(CircuitStateOpen, now)
		cb.halfOpenAttempts = 0
		cb.successCount = 0
		slog.Warn("circuit breaker probe failed, re-opening",
			"connector_id", cb.connectorID,
			"failure_count", cb.failureCount,
		)

	case CircuitStateOpen:
		// Already open — just update failure time for recovery timeout reset.
		slog.Warn("circuit breaker received failure while OPEN",
			"connector_id", cb.connectorID,
			"failure_count", cb.failureCount,
		)
	}
}

// State returns the current circuit breaker state. Thread-safe.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Reset forces the circuit breaker back to CLOSED state, clearing all counters.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := cb.clock()
	from := cb.state

	cb.state = CircuitStateClosed
	cb.failureCount = 0
	cb.successCount = 0
	cb.halfOpenAttempts = 0
	cb.lastStateChange = now

	if from != CircuitStateClosed && cb.onStateChange != nil {
		cb.onStateChange(cb.connectorID, from, CircuitStateClosed)
	}

	slog.Info("circuit breaker reset",
		"connector_id", cb.connectorID,
		"from_state", string(from),
	)
}

// Stats returns a point-in-time snapshot of the circuit breaker metrics.
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return CircuitBreakerStats{
		ConnectorID:      cb.connectorID,
		State:            cb.state,
		FailureCount:     cb.failureCount,
		SuccessCount:     cb.successCount,
		LastFailureTime:  cb.lastFailureTime,
		LastStateChange:  cb.lastStateChange,
		HalfOpenAttempts: cb.halfOpenAttempts,
	}
}

// transition performs a state change, updating the timestamp and invoking
// the state change callback if configured. MUST be called with mu held.
func (cb *CircuitBreaker) transition(to CircuitState, now time.Time) {
	from := cb.state
	cb.state = to
	cb.lastStateChange = now

	if cb.onStateChange != nil {
		cb.onStateChange(cb.connectorID, from, to)
	}
}

// ---------------------------------------------------------------------------
// CircuitBreakerRegistry
// ---------------------------------------------------------------------------

// CircuitBreakerRegistry manages a collection of per-connector circuit breakers.
// It creates breakers lazily on first access and applies default options to
// each new breaker.
type CircuitBreakerRegistry struct {
	mu       sync.RWMutex
	breakers map[string]*CircuitBreaker
	defaults []CircuitBreakerOption
}

// NewCircuitBreakerRegistry creates a registry that applies the given default
// options to every circuit breaker it creates.
func NewCircuitBreakerRegistry(defaults ...CircuitBreakerOption) *CircuitBreakerRegistry {
	return &CircuitBreakerRegistry{
		breakers: make(map[string]*CircuitBreaker),
		defaults: defaults,
	}
}

// Get returns the circuit breaker for the given connector, creating one with
// default options if it does not yet exist.
func (r *CircuitBreakerRegistry) Get(connectorID string) *CircuitBreaker {
	// Fast path: read lock.
	r.mu.RLock()
	cb, ok := r.breakers[connectorID]
	r.mu.RUnlock()
	if ok {
		return cb
	}

	// Slow path: write lock, double-check.
	r.mu.Lock()
	defer r.mu.Unlock()

	cb, ok = r.breakers[connectorID]
	if ok {
		return cb
	}

	cb = NewCircuitBreaker(connectorID, r.defaults...)
	r.breakers[connectorID] = cb
	return cb
}

// AllStats returns a snapshot of stats for every registered circuit breaker.
func (r *CircuitBreakerRegistry) AllStats() map[string]CircuitBreakerStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := make(map[string]CircuitBreakerStats, len(r.breakers))
	for id, cb := range r.breakers {
		stats[id] = cb.Stats()
	}
	return stats
}

// ResetAll forces every registered circuit breaker back to CLOSED state.
func (r *CircuitBreakerRegistry) ResetAll() {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, cb := range r.breakers {
		cb.Reset()
	}
}
