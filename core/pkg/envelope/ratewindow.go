// Package envelope — rate-limit windows.
//
// AutonomyEnvelope.budgets.rate_limits declares ceilings over tumbling UTC
// windows. This file supplies the counting seam the EnvelopeGate reserves
// against, plus the process-local implementation the kernel ships by default.
//
// The seam exists because a window wider than a run cannot be counted inside
// one: a per-day ceiling shared by a fleet of workers has to be counted
// somewhere all of them can see. The kernel does not choose that store — it
// defines the contract and refuses to dial without one.
package envelope

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RateWindow names a tumbling counting window.
type RateWindow string

const (
	// RateWindowMinute resets at the top of each UTC minute.
	RateWindowMinute RateWindow = "minute"
	// RateWindowDay resets at UTC midnight.
	RateWindowDay RateWindow = "day"
)

// RateWindowKey identifies exactly one counter: a resource, inside one
// envelope, inside one occurrence of one window.
type RateWindowKey struct {
	EnvelopeID  string     `json:"envelope_id"`
	Resource    string     `json:"resource"`
	Window      RateWindow `json:"window"`
	WindowStart time.Time  `json:"window_start"` // UTC, truncated to the window
}

// String renders the key as a stable identifier suitable for use as a store
// primary key. WindowStart is rendered in RFC3339 UTC so two callers that
// computed the same window agree byte-for-byte.
func (k RateWindowKey) String() string {
	return fmt.Sprintf("%s|%s|%s|%s",
		k.EnvelopeID, k.Resource, k.Window, k.WindowStart.UTC().Format(time.RFC3339))
}

// RateReservation is one window a single effect must fit inside.
type RateReservation struct {
	Key   RateWindowKey `json:"key"`
	Limit int64         `json:"limit"`
}

// RateReservationOutcome reports an atomic multi-window reservation.
//
// When Granted is false the Denied* fields describe the first window that
// would have been exceeded, so the denial can name a number rather than a
// category.
type RateReservationOutcome struct {
	Granted     bool          `json:"granted"`
	DeniedKey   RateWindowKey `json:"denied_key,omitempty"`
	DeniedCount int64         `json:"denied_count,omitempty"`
	DeniedLimit int64         `json:"denied_limit,omitempty"`
}

// RateWindowStore counts consumption of rate-limited resources.
//
// Implementations must satisfy three properties:
//
//   - Atomic. Reserve either consumes every window in the batch or none of
//     them. Splitting check from consume lets two callers race past the same
//     ceiling; consuming a narrow window for an effect a wider window then
//     denies silently overcounts.
//   - Concurrency-safe. Reserve is called from every goroutine holding the
//     gate.
//   - Fail-closed. A returned error is a denial, never a pass.
//
// The shipped InMemoryRateWindowStore is process-local: it cannot enforce a
// ceiling that spans processes and it loses its counters on restart. That is
// adequate for a ceiling scoped to one run in one process and inadequate for
// anything wider — a deployment enforcing a fleet-wide daily cap must supply a
// durable implementation via EnvelopeGate.WithRateWindowStore.
type RateWindowStore interface {
	Reserve(ctx context.Context, reservations []RateReservation) (RateReservationOutcome, error)
}

// InMemoryRateWindowStore is the default process-local store.
//
// It keeps exactly one counter per (envelope, resource, window): a reservation
// against a newer window start replaces the previous occurrence rather than
// accumulating, so memory is bounded by the number of declared limits and not
// by elapsed time.
type InMemoryRateWindowStore struct {
	mu       sync.Mutex
	counters map[string]*rateWindowCounter
}

type rateWindowCounter struct {
	start time.Time
	count int64
}

// NewInMemoryRateWindowStore creates a process-local rate window store.
func NewInMemoryRateWindowStore() *InMemoryRateWindowStore {
	return &InMemoryRateWindowStore{counters: make(map[string]*rateWindowCounter)}
}

// counterID omits WindowStart: the counter for a given window *kind* is
// singular, and a newer start rolls it over.
func counterID(k RateWindowKey) string {
	return k.EnvelopeID + "\x00" + k.Resource + "\x00" + string(k.Window)
}

// Reserve consumes one unit against every listed window, or none of them.
func (s *InMemoryRateWindowStore) Reserve(ctx context.Context, reservations []RateReservation) (RateReservationOutcome, error) {
	_ = ctx

	if s == nil {
		return RateReservationOutcome{}, fmt.Errorf("rate window store is nil")
	}
	if len(reservations) == 0 {
		return RateReservationOutcome{Granted: true}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.counters == nil {
		s.counters = make(map[string]*rateWindowCounter)
	}

	// Pass 1 — resolve counters and check every window before mutating any.
	type pending struct {
		counter *rateWindowCounter
		res     RateReservation
	}
	batch := make([]pending, 0, len(reservations))

	for _, r := range reservations {
		if r.Limit <= 0 {
			return RateReservationOutcome{}, fmt.Errorf(
				"rate window limit for %s must be positive, got %d", r.Key.String(), r.Limit)
		}

		id := counterID(r.Key)
		start := r.Key.WindowStart.UTC()
		c := s.counters[id]
		if c == nil || c.start.Before(start) {
			c = &rateWindowCounter{start: start}
			s.counters[id] = c
		} else if c.start.After(start) {
			// A reservation for an already-closed window. Time does not run
			// backwards inside a gate, so this is a caller defect; refuse
			// rather than reopen a window that has rolled over.
			return RateReservationOutcome{}, fmt.Errorf(
				"rate window %s is closed: current window started at %s",
				r.Key.String(), c.start.Format(time.RFC3339))
		}

		if c.count+1 > r.Limit {
			return RateReservationOutcome{
				Granted:     false,
				DeniedKey:   r.Key,
				DeniedCount: c.count,
				DeniedLimit: r.Limit,
			}, nil
		}

		batch = append(batch, pending{counter: c, res: r})
	}

	// Pass 2 — every window fits, so consume them together.
	//
	// Two reservations in one batch can share a counter only if they carry the
	// same key, which the gate rejects upstream as a duplicate resource, so a
	// single increment per entry is correct here.
	for _, p := range batch {
		p.counter.count++
	}

	return RateReservationOutcome{Granted: true}, nil
}

// Usage reports the current count for a window, or zero when the window has
// rolled over or was never opened. It is observational only — it must not be
// used to decide admission, because the answer is stale the moment it returns.
func (s *InMemoryRateWindowStore) Usage(key RateWindowKey) int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	c := s.counters[counterID(key)]
	if c == nil || !c.start.Equal(key.WindowStart.UTC()) {
		return 0
	}
	return c.count
}

// windowStart truncates a timestamp to the start of its window in UTC.
func windowStart(t time.Time, w RateWindow) (time.Time, error) {
	utc := t.UTC()
	switch w {
	case RateWindowMinute:
		return utc.Truncate(time.Minute), nil
	case RateWindowDay:
		return time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC), nil
	default:
		return time.Time{}, fmt.Errorf("unknown rate window %q", w)
	}
}
