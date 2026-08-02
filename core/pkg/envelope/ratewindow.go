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
	"strings"
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

// RateWindowKey identifies exactly one counter: a resource — optionally one
// concrete instance of it — inside one envelope, inside one occurrence of one
// window.
type RateWindowKey struct {
	EnvelopeID string `json:"envelope_id"`
	Resource   string `json:"resource"`

	// Instance names which concrete member of a per-instance resource this
	// counter belongs to, and is empty for a pooled resource.
	Instance string `json:"instance,omitempty"`

	Window      RateWindow `json:"window"`
	WindowStart time.Time  `json:"window_start"` // UTC, truncated to the window
}

// String renders the key as a stable identifier suitable for use as a store
// primary key.
//
// Every component is length-prefixed rather than delimiter-joined, because
// resource and envelope identifiers are unconstrained strings: joining
// ("a|b", "c") and ("a", "b|c") on a separator produces one identifier for two
// different counters, silently merging them. WindowStart is rendered in
// RFC3339 UTC so two callers that computed the same window agree byte-for-byte.
func (k RateWindowKey) String() string {
	parts := []string{
		k.EnvelopeID,
		k.Resource,
		k.Instance,
		string(k.Window),
		k.WindowStart.UTC().Format(time.RFC3339),
	}
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteByte('|')
		}
		fmt.Fprintf(&b, "%d:%s", len(p), p)
	}
	return b.String()
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
// durable implementation via EnvelopeGate.SetRateWindowStore.
type RateWindowStore interface {
	Reserve(ctx context.Context, reservations []RateReservation) (RateReservationOutcome, error)
}

// rateWindowRetention is how far behind the newest window a counter may fall
// before it is evicted. Two days clears yesterday's day windows while leaving
// today's untouched even when a batch arrives out of order at a boundary.
const rateWindowRetention = 48 * time.Hour

// rateWindowEvictionThreshold is the counter population above which a
// reservation also sweeps stale entries. Sweeping on every call would make
// each reservation O(counters) for no benefit while the map is small.
const rateWindowEvictionThreshold = 1024

// InMemoryRateWindowStore is the default process-local store.
//
// It keeps one counter per (envelope, resource, instance, window kind): a
// reservation against a newer window start replaces the previous occurrence
// rather than accumulating. Counters belonging to envelopes that are no longer
// reserved against are swept once the population grows past a threshold, so
// memory tracks the active limits rather than every envelope ever bound.
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
// singular, and a newer start rolls it over. Components are length-prefixed
// for the same reason RateWindowKey.String is.
func counterID(k RateWindowKey) string {
	return fmt.Sprintf("%d:%s|%d:%s|%d:%s|%d:%s",
		len(k.EnvelopeID), k.EnvelopeID,
		len(k.Resource), k.Resource,
		len(k.Instance), k.Instance,
		len(k.Window), k.Window)
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
	seen := make(map[string]bool, len(reservations))
	newest := time.Time{}

	for _, r := range reservations {
		if r.Limit <= 0 {
			return RateReservationOutcome{}, fmt.Errorf(
				"rate window limit for %s must be positive, got %d", r.Key.String(), r.Limit)
		}

		// Each window is checked against the count as it stood before the
		// batch, so a repeated key would be checked twice against the same
		// number and then incremented twice — admitting two units against a
		// ceiling of one. Refuse rather than guess whether the caller meant
		// one unit or two.
		keyID := r.Key.String()
		if seen[keyID] {
			return RateReservationOutcome{}, fmt.Errorf(
				"duplicate rate window reservation for %s in one batch", keyID)
		}
		seen[keyID] = true

		if r.Key.WindowStart.UTC().After(newest) {
			newest = r.Key.WindowStart.UTC()
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
	for _, p := range batch {
		p.counter.count++
	}

	s.evictStaleLocked(newest)

	return RateReservationOutcome{Granted: true}, nil
}

// evictStaleLocked drops counters whose window closed long enough ago that
// nothing can reserve against them again.
//
// Without this, a gate that binds a fresh envelope ID per run accumulates one
// permanent counter set per envelope ever seen — the map would track the whole
// history rather than the live limits. Callers hold s.mu.
func (s *InMemoryRateWindowStore) evictStaleLocked(newest time.Time) {
	if newest.IsZero() || len(s.counters) <= rateWindowEvictionThreshold {
		return
	}
	cutoff := newest.Add(-rateWindowRetention)
	for id, c := range s.counters {
		if c.start.Before(cutoff) {
			delete(s.counters, id)
		}
	}
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
