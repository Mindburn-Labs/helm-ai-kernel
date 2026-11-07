package effects

import (
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
