// Package guardian: Temporal Guardian — Graded Response System.
//
// Per JAN_2026_FRONTIER_DIRECTIVES §1 and REGULATION_SPEC §5, the Temporal
// Guardian observes effect frequency over sliding windows and escalates
// through a 5-level graded response: Observe → Throttle → Interrupt →
// Quarantine → FailClosed.
//
// The ControllabilityEnvelope tracks effect rates and compares them against
// EscalationPolicy thresholds to determine the current response level.
package guardian

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ResponseLevel represents the Guardian's graded intervention severity.
type ResponseLevel int

const (
	// ResponseObserve — monitor only; all effects pass. Baseline level.
	ResponseObserve ResponseLevel = iota
	// ResponseThrottle — rate-limit effects; excess effects are delayed.
	ResponseThrottle
	// ResponseInterrupt — pause the current action; require operator ack.
	ResponseInterrupt
	// ResponseQuarantine — isolate the agent/source; block all effects until review.
	ResponseQuarantine
	// ResponseFailClosed — emergency halt; no effects dispatch.
	ResponseFailClosed
)

// String implements fmt.Stringer for ResponseLevel.
func (r ResponseLevel) String() string {
	switch r {
	case ResponseObserve:
		return "OBSERVE"
	case ResponseThrottle:
		return "THROTTLE"
	case ResponseInterrupt:
		return "INTERRUPT"
	case ResponseQuarantine:
		return "QUARANTINE"
	case ResponseFailClosed:
		return "FAIL_CLOSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(r))
	}
}

// GradedResponse is the Temporal Guardian's evaluation result.
type GradedResponse struct {
	Level       ResponseLevel // Current response level
	Reason      string        // Human-readable reason for this level
	Duration    time.Duration // Suggested hold duration (for Throttle/Quarantine)
	AllowEffect bool          // Whether the effect may proceed
	WindowRate  float64       // Current effects/second in the window
}

// EscalationThreshold defines the trigger for one response level.
type EscalationThreshold struct {
	Level         ResponseLevel
	MaxRate       float64       // Max effects per second before escalating to this level
	SustainedFor  time.Duration // Rate must be sustained for this long to trigger
	CooldownAfter time.Duration // Duration of good behavior to de-escalate
}

// EscalationPolicy defines the full escalation ladder.
type EscalationPolicy struct {
	Thresholds []EscalationThreshold // Ordered by Level ascending
	WindowSize time.Duration         // Sliding window size for rate calculation
}

// DefaultEscalationPolicy returns production-default thresholds.
func DefaultEscalationPolicy() EscalationPolicy {
	return EscalationPolicy{
		WindowSize: 60 * time.Second,
		Thresholds: []EscalationThreshold{
			{Level: ResponseThrottle, MaxRate: 10.0, SustainedFor: 5 * time.Second, CooldownAfter: 30 * time.Second},
			{Level: ResponseInterrupt, MaxRate: 50.0, SustainedFor: 3 * time.Second, CooldownAfter: 60 * time.Second},
			{Level: ResponseQuarantine, MaxRate: 100.0, SustainedFor: 2 * time.Second, CooldownAfter: 120 * time.Second},
			{Level: ResponseFailClosed, MaxRate: 200.0, SustainedFor: 1 * time.Second, CooldownAfter: 300 * time.Second},
		},
	}
}

// effectEvent records the timestamp of an observed effect.
type effectEvent struct {
	timestamp time.Time
}

// ControllabilityEnvelope tracks effect frequency in a sliding time window.
// It is the sensory organ of the Temporal Guardian.
type ControllabilityEnvelope struct {
	mu     sync.Mutex
	events []effectEvent
	window time.Duration
	clock  Clock
}

// NewControllabilityEnvelope creates an envelope with the given window and clock.
func NewControllabilityEnvelope(window time.Duration, clock Clock) *ControllabilityEnvelope {
	return &ControllabilityEnvelope{
		events: make([]effectEvent, 0, 256),
		window: window,
		clock:  clock,
	}
}

// Record adds a new effect event to the envelope.
func (e *ControllabilityEnvelope) Record() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, effectEvent{timestamp: e.clock.Now()})
	e.prune()
}

// Rate returns the current effects-per-second within the window.
func (e *ControllabilityEnvelope) Rate() float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.prune()
	if len(e.events) == 0 {
		return 0.0
	}
	windowSecs := e.window.Seconds()
	if windowSecs <= 0 {
		return 0.0
	}
	return float64(len(e.events)) / windowSecs
}

// Count returns the number of events currently in the window.
func (e *ControllabilityEnvelope) Count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.prune()
	return len(e.events)
}

// prune removes events outside the sliding window. Must be called with mu held.
func (e *ControllabilityEnvelope) prune() {
	cutoff := e.clock.Now().Add(-e.window)
	i := 0
	for i < len(e.events) && e.events[i].timestamp.Before(cutoff) {
		i++
	}
	if i > 0 {
		e.events = e.events[i:]
	}
}

// TemporalGuardian evaluates effects against the controllability envelope
// and the escalation policy to produce graded responses.
type TemporalGuardian struct {
	mu           sync.Mutex
	envelope     *ControllabilityEnvelope
	policy       EscalationPolicy
	clock        Clock
	currentLevel ResponseLevel
	levelSince   time.Time                   // When the current level was entered
	sustainStart map[ResponseLevel]time.Time // When rate first exceeded each level's threshold
}

// NewTemporalGuardian creates a Temporal Guardian with the given policy and clock.
func NewTemporalGuardian(policy EscalationPolicy, clock Clock) *TemporalGuardian {
	return &TemporalGuardian{
		envelope:     NewControllabilityEnvelope(policy.WindowSize, clock),
		policy:       policy,
		clock:        clock,
		currentLevel: ResponseObserve,
		levelSince:   clock.Now(),
		sustainStart: make(map[ResponseLevel]time.Time),
	}
}

// Evaluate records an effect and returns the current graded response.
// This is the main entry point called before each effect dispatch.
func (tg *TemporalGuardian) Evaluate(_ context.Context) GradedResponse {
	tg.mu.Lock()
	defer tg.mu.Unlock()

	// Record the effect in the envelope.
	tg.envelope.Record()
	rate := tg.envelope.Rate()
	now := tg.clock.Now()

	// Check for de-escalation first: if rate has dropped below the current
	// level's threshold for the cooldown period, we de-escalate.
	tg.checkDeescalation(rate, now)

	// Then check for escalation: if rate exceeds a higher level's threshold
	// for the sustained duration, escalate.
	tg.checkEscalation(rate, now)

	return GradedResponse{
		Level:       tg.currentLevel,
		Reason:      tg.reason(rate),
		Duration:    tg.holdDuration(),
		AllowEffect: tg.currentLevel <= ResponseThrottle,
		WindowRate:  rate,
	}
}

// CurrentLevel returns the current response level (thread-safe).
func (tg *TemporalGuardian) CurrentLevel() ResponseLevel {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return tg.currentLevel
}

// checkEscalation promotes the level if rate exceeds the threshold for the sustained period.
func (tg *TemporalGuardian) checkEscalation(rate float64, now time.Time) {
	for _, t := range tg.policy.Thresholds {
		if t.Level <= tg.currentLevel {
			continue // Only check levels above current
		}
		if rate >= t.MaxRate {
			start, exists := tg.sustainStart[t.Level]
			if !exists {
				// First time rate exceeded for this level
				tg.sustainStart[t.Level] = now
				continue
			}
			if now.Sub(start) >= t.SustainedFor {
				// Sustained long enough — escalate
				tg.currentLevel = t.Level
				tg.levelSince = now
				// Clear sustain markers for lower levels
				for level := range tg.sustainStart {
					if level <= t.Level {
						delete(tg.sustainStart, level)
					}
				}
			}
		} else {
			// Rate dropped below threshold — reset sustain timer
			delete(tg.sustainStart, t.Level)
		}
	}
}

// checkDeescalation demotes the level if rate has been below the threshold
// for the cooldown period.
func (tg *TemporalGuardian) checkDeescalation(rate float64, now time.Time) {
	if tg.currentLevel == ResponseObserve {
		return // Already at lowest level
	}

	// Find the threshold for the current level.
	for _, t := range tg.policy.Thresholds {
		if t.Level == tg.currentLevel {
			// If rate is below this level's threshold and cooldown has elapsed,
			// de-escalate one level.
			if rate < t.MaxRate && now.Sub(tg.levelSince) >= t.CooldownAfter {
				tg.currentLevel = tg.previousLevel(t.Level)
				tg.levelSince = now
				// Clear all sustain markers at or above the old level.
				for level := range tg.sustainStart {
					if level >= t.Level {
						delete(tg.sustainStart, level)
					}
				}
			}
			return
		}
	}
}

// previousLevel returns the level one step below the given level.
func (tg *TemporalGuardian) previousLevel(level ResponseLevel) ResponseLevel {
	if level <= ResponseObserve {
		return ResponseObserve
	}
	return level - 1
}

// reason generates a human-readable explanation for the current level.
func (tg *TemporalGuardian) reason(rate float64) string {
	switch tg.currentLevel {
	case ResponseObserve:
		return fmt.Sprintf("Normal operation (%.1f effects/s)", rate)
	case ResponseThrottle:
		return fmt.Sprintf("Rate limiting active (%.1f effects/s exceeds threshold)", rate)
	case ResponseInterrupt:
		return fmt.Sprintf("Action paused — operator acknowledgment required (%.1f effects/s)", rate)
	case ResponseQuarantine:
		return fmt.Sprintf("Agent quarantined — all effects blocked pending review (%.1f effects/s)", rate)
	case ResponseFailClosed:
		return fmt.Sprintf("EMERGENCY HALT — fail-closed activated (%.1f effects/s)", rate)
	default:
		return fmt.Sprintf("Unknown level %d (%.1f effects/s)", int(tg.currentLevel), rate)
	}
}

// holdDuration returns the suggested hold time for rate-limiting levels.
func (tg *TemporalGuardian) holdDuration() time.Duration {
	switch tg.currentLevel {
	case ResponseThrottle:
		return 1 * time.Second
	case ResponseInterrupt:
		return 30 * time.Second
	case ResponseQuarantine:
		return 120 * time.Second
	case ResponseFailClosed:
		return 300 * time.Second
	default:
		return 0
	}
}
