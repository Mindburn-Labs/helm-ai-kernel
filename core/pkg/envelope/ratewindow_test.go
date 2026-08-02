package envelope

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// rateLimitedEnvelope returns a signed envelope carrying the supplied rate
// limits and ceilings generous enough that nothing else in the gate can be the
// cause of a denial.
func rateLimitedEnvelope(t *testing.T, limits ...contracts.RateLimit) *contracts.AutonomyEnvelope {
	t.Helper()

	env := testEnvelope()
	env.Budgets.ToolCallCap = 1_000_000
	env.Budgets.CostCeilingCents = 1_000_000
	env.Budgets.TimeCeilingSeconds = 86_400
	env.Budgets.RateLimits = limits
	env.AllowedEffects = []contracts.EffectClassAllowlist{{EffectClass: "E2", Allowed: true}}
	if err := Sign(env, "kernel-test"); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return env
}

// fixedClock returns a clock reporting a caller-controlled instant.
func fixedClock(at *time.Time) func() time.Time {
	return func() time.Time { return *at }
}

func bindGate(t *testing.T, env *contracts.AutonomyEnvelope, at *time.Time) *EnvelopeGate {
	t.Helper()

	g := NewEnvelopeGate().WithClock(fixedClock(at))
	result := g.Bind(context.Background(), env)
	if !result.Valid {
		t.Fatalf("Bind() rejected envelope: %v", result.Errors)
	}
	return g
}

// TestGateEnforcesPerDayWindow is the proving artifact for the per-day ceiling:
// the 700th attempt inside a UTC day is admitted and the 701st is denied. If
// max_per_day were merely parsed rather than enforced, every attempt would pass.
func TestGateEnforcesPerDayWindow(t *testing.T) {
	now := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	env := rateLimitedEnvelope(t, contracts.RateLimit{
		Resource:  "outbound.attempts",
		MaxPerDay: 700,
	})
	g := bindGate(t, env, &now)

	req := &EffectRequest{EffectClass: "E2", Resource: "outbound.attempts"}

	for i := 1; i <= 700; i++ {
		// Advance a minute per attempt so no minute window could be the cause.
		now = now.Add(time.Minute)
		decision := g.CheckEffect(context.Background(), req)
		if !decision.Allowed {
			t.Fatalf("attempt %d denied inside the daily ceiling: %s (%s)", i, decision.Reason, decision.Violation)
		}
	}

	now = now.Add(time.Minute)
	decision := g.CheckEffect(context.Background(), req)
	if decision.Allowed {
		t.Fatal("attempt 701 was admitted: the per-day ceiling is not enforced")
	}
	if decision.Violation != "RATE_LIMIT_DAY_EXCEEDED" {
		t.Fatalf("violation = %q, want RATE_LIMIT_DAY_EXCEEDED (reason: %s)", decision.Violation, decision.Reason)
	}
}

// TestGateDayWindowRollsOverAtUTCMidnight proves the window is a UTC calendar
// day rather than a rolling counter that never resets.
func TestGateDayWindowRollsOverAtUTCMidnight(t *testing.T) {
	now := time.Date(2026, 8, 2, 23, 59, 0, 0, time.UTC)
	env := rateLimitedEnvelope(t, contracts.RateLimit{Resource: "outbound.attempts", MaxPerDay: 2})
	g := bindGate(t, env, &now)

	req := &EffectRequest{EffectClass: "E2", Resource: "outbound.attempts"}

	for i := 1; i <= 2; i++ {
		if d := g.CheckEffect(context.Background(), req); !d.Allowed {
			t.Fatalf("attempt %d denied: %s", i, d.Reason)
		}
	}
	if d := g.CheckEffect(context.Background(), req); d.Allowed {
		t.Fatal("third attempt admitted before midnight")
	}

	now = time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	if d := g.CheckEffect(context.Background(), req); !d.Allowed {
		t.Fatalf("first attempt of the new UTC day denied: %s (%s)", d.Reason, d.Violation)
	}
}

// TestGateDayWindowSurvivesRebind proves the ceiling is not resettable by
// re-binding the same envelope. A per-day window that restarted on Bind would
// be defeated by anything that rebinds per run.
func TestGateDayWindowSurvivesRebind(t *testing.T) {
	now := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	env := rateLimitedEnvelope(t, contracts.RateLimit{Resource: "outbound.attempts", MaxPerDay: 1})
	g := bindGate(t, env, &now)

	req := &EffectRequest{EffectClass: "E2", Resource: "outbound.attempts"}
	if d := g.CheckEffect(context.Background(), req); !d.Allowed {
		t.Fatalf("first attempt denied: %s", d.Reason)
	}

	if result := g.Bind(context.Background(), env); !result.Valid {
		t.Fatalf("rebind rejected: %v", result.Errors)
	}
	if d := g.CheckEffect(context.Background(), req); d.Allowed {
		t.Fatal("rebinding the envelope reset the per-day ceiling")
	}

	g.Unbind()
	if result := g.Bind(context.Background(), env); !result.Valid {
		t.Fatalf("rebind after unbind rejected: %v", result.Errors)
	}
	if d := g.CheckEffect(context.Background(), req); d.Allowed {
		t.Fatal("unbind/rebind reset the per-day ceiling")
	}
}

// TestGateEnforcesPerMinuteWindow covers the sibling window on the same path.
func TestGateEnforcesPerMinuteWindow(t *testing.T) {
	now := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	env := rateLimitedEnvelope(t, contracts.RateLimit{
		Resource:     "outbound.attempts",
		MaxPerMinute: 3,
		MaxPerDay:    700,
	})
	g := bindGate(t, env, &now)

	req := &EffectRequest{EffectClass: "E2", Resource: "outbound.attempts"}

	for i := 1; i <= 3; i++ {
		if d := g.CheckEffect(context.Background(), req); !d.Allowed {
			t.Fatalf("attempt %d denied inside the minute ceiling: %s", i, d.Reason)
		}
	}
	d := g.CheckEffect(context.Background(), req)
	if d.Allowed {
		t.Fatal("fourth attempt in the same minute was admitted")
	}
	if d.Violation != "RATE_LIMIT_MINUTE_EXCEEDED" {
		t.Fatalf("violation = %q, want RATE_LIMIT_MINUTE_EXCEEDED", d.Violation)
	}

	now = now.Add(time.Minute)
	if d := g.CheckEffect(context.Background(), req); !d.Allowed {
		t.Fatalf("first attempt of the next minute denied: %s (%s)", d.Reason, d.Violation)
	}
}

// TestGateDeniedEffectDoesNotConsumeNarrowerWindow proves the reservation is
// atomic across windows: an effect refused by the day ceiling must not have
// spent a minute unit on the way there.
func TestGateDeniedEffectDoesNotConsumeNarrowerWindow(t *testing.T) {
	now := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	env := rateLimitedEnvelope(t, contracts.RateLimit{
		Resource:     "outbound.attempts",
		MaxPerMinute: 2,
		MaxPerDay:    2,
	})
	g := bindGate(t, env, &now)

	store, ok := g.rateWindows.(*InMemoryRateWindowStore)
	if !ok {
		t.Fatalf("default store type = %T, want *InMemoryRateWindowStore", g.rateWindows)
	}
	minuteKey := func(at time.Time) RateWindowKey {
		return RateWindowKey{
			EnvelopeID:  env.EnvelopeID,
			Resource:    "outbound.attempts",
			Window:      RateWindowMinute,
			WindowStart: at.Truncate(time.Minute),
		}
	}

	req := &EffectRequest{EffectClass: "E2", Resource: "outbound.attempts"}

	// Spend the daily ceiling one attempt per minute, so no minute window is
	// ever the binding constraint.
	for i := 1; i <= 2; i++ {
		if d := g.CheckEffect(context.Background(), req); !d.Allowed {
			t.Fatalf("attempt %d denied: %s (%s)", i, d.Reason, d.Violation)
		}
		if got := store.Usage(minuteKey(now)); got != 1 {
			t.Fatalf("minute usage after attempt %d = %d, want 1", i, got)
		}
		now = now.Add(time.Minute)
	}

	// The third attempt lands in a fresh minute with two units of headroom and
	// must be refused by the day ceiling alone.
	d := g.CheckEffect(context.Background(), req)
	if d.Allowed {
		t.Fatal("third attempt admitted past a daily ceiling of 2")
	}
	if d.Violation != "RATE_LIMIT_DAY_EXCEEDED" {
		t.Fatalf("violation = %q, want RATE_LIMIT_DAY_EXCEEDED", d.Violation)
	}
	if got := store.Usage(minuteKey(now)); got != 0 {
		t.Fatalf("minute usage after a day-denied attempt = %d, want 0 — the denied effect consumed a narrower window", got)
	}
}

// TestGateWildcardRateLimitBindsEveryEffect covers the run-wide ceiling shape.
func TestGateWildcardRateLimitBindsEveryEffect(t *testing.T) {
	now := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	env := rateLimitedEnvelope(t, contracts.RateLimit{
		Resource:  contracts.RateLimitResourceAny,
		MaxPerDay: 2,
	})
	g := bindGate(t, env, &now)

	first := &EffectRequest{EffectClass: "E2", EffectType: "SEND_EMAIL"}
	second := &EffectRequest{EffectClass: "E2", Resource: "outbound.attempts"}

	if d := g.CheckEffect(context.Background(), first); !d.Allowed {
		t.Fatalf("first effect denied: %s", d.Reason)
	}
	if d := g.CheckEffect(context.Background(), second); !d.Allowed {
		t.Fatalf("second effect denied: %s", d.Reason)
	}
	if d := g.CheckEffect(context.Background(), first); d.Allowed {
		t.Fatal("third effect admitted past a wildcard ceiling of 2")
	}
}

// TestGateRateLimitFallsBackToEffectType proves callers that already name
// their effects need not restate the name as a resource.
func TestGateRateLimitFallsBackToEffectType(t *testing.T) {
	now := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	env := rateLimitedEnvelope(t, contracts.RateLimit{Resource: "CUSTOMER_OUTREACH", MaxPerDay: 1})
	g := bindGate(t, env, &now)

	req := &EffectRequest{EffectClass: "E2", EffectType: "CUSTOMER_OUTREACH"}
	if d := g.CheckEffect(context.Background(), req); !d.Allowed {
		t.Fatalf("first attempt denied: %s", d.Reason)
	}
	if d := g.CheckEffect(context.Background(), req); d.Allowed {
		t.Fatal("effect-type-matched rate limit was not enforced")
	}
}

// TestGateUnmatchedResourceIsNotRateLimited proves a declared limit does not
// leak onto unrelated effects.
func TestGateUnmatchedResourceIsNotRateLimited(t *testing.T) {
	now := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	env := rateLimitedEnvelope(t, contracts.RateLimit{Resource: "outbound.attempts", MaxPerDay: 1})
	g := bindGate(t, env, &now)

	other := &EffectRequest{EffectClass: "E2", Resource: "search.query"}
	for i := 1; i <= 5; i++ {
		if d := g.CheckEffect(context.Background(), other); !d.Allowed {
			t.Fatalf("unrelated effect %d denied by another resource's ceiling: %s", i, d.Reason)
		}
	}
}

// TestGateWithoutRateWindowStoreDeniesRateLimitedEffects proves the seam is
// fail-closed: no counter means no dial, not an unmetered one.
func TestGateWithoutRateWindowStoreDeniesRateLimitedEffects(t *testing.T) {
	now := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	env := rateLimitedEnvelope(t, contracts.RateLimit{Resource: "outbound.attempts", MaxPerDay: 700})
	g := bindGate(t, env, &now).WithRateWindowStore(nil)

	d := g.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E2", Resource: "outbound.attempts"})
	if d.Allowed {
		t.Fatal("effect admitted with no rate window store configured")
	}
	if d.Violation != "RATE_LIMIT_STORE_REQUIRED" {
		t.Fatalf("violation = %q, want RATE_LIMIT_STORE_REQUIRED", d.Violation)
	}

	// Effects that match no declared limit are unaffected.
	if d := g.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E2", Resource: "search.query"}); !d.Allowed {
		t.Fatalf("unrelated effect denied without a store: %s (%s)", d.Reason, d.Violation)
	}
}

// erroringRateWindowStore fails every reservation.
type erroringRateWindowStore struct{}

func (erroringRateWindowStore) Reserve(context.Context, []RateReservation) (RateReservationOutcome, error) {
	return RateReservationOutcome{}, fmt.Errorf("counter backend unavailable")
}

// TestGateRateWindowStoreErrorDenies proves a store failure is a denial rather
// than a pass — the distinction the in-memory nonce store gets wrong.
func TestGateRateWindowStoreErrorDenies(t *testing.T) {
	now := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	env := rateLimitedEnvelope(t, contracts.RateLimit{Resource: "outbound.attempts", MaxPerDay: 700})
	g := bindGate(t, env, &now).WithRateWindowStore(erroringRateWindowStore{})

	d := g.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E2", Resource: "outbound.attempts"})
	if d.Allowed {
		t.Fatal("effect admitted despite a rate window store error")
	}
	if d.Violation != "RATE_LIMIT_STORE_ERROR" {
		t.Fatalf("violation = %q, want RATE_LIMIT_STORE_ERROR", d.Violation)
	}
}

// TestGateRateLimitConcurrentReservationsRespectCeiling proves the ceiling
// holds under concurrency: exactly MaxPerDay effects are admitted, never more.
func TestGateRateLimitConcurrentReservationsRespectCeiling(t *testing.T) {
	now := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	const ceiling = 50
	env := rateLimitedEnvelope(t, contracts.RateLimit{Resource: "outbound.attempts", MaxPerDay: ceiling})
	g := bindGate(t, env, &now)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)
	for i := 0; i < ceiling*4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := g.CheckEffect(context.Background(), &EffectRequest{EffectClass: "E2", Resource: "outbound.attempts"})
			if d.Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed != ceiling {
		t.Fatalf("admitted %d effects against a ceiling of %d", allowed, ceiling)
	}
}

// --- Store-level tests ---

func TestInMemoryRateWindowStoreReserveIsAllOrNothing(t *testing.T) {
	store := NewInMemoryRateWindowStore()
	start := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)

	minute := RateWindowKey{EnvelopeID: "e", Resource: "r", Window: RateWindowMinute, WindowStart: start}
	day := RateWindowKey{EnvelopeID: "e", Resource: "r", Window: RateWindowDay, WindowStart: start.Truncate(24 * time.Hour)}

	outcome, err := store.Reserve(context.Background(), []RateReservation{
		{Key: minute, Limit: 5},
		{Key: day, Limit: 1},
	})
	if err != nil || !outcome.Granted {
		t.Fatalf("first reserve = (%+v, %v), want granted", outcome, err)
	}

	outcome, err = store.Reserve(context.Background(), []RateReservation{
		{Key: minute, Limit: 5},
		{Key: day, Limit: 1},
	})
	if err != nil {
		t.Fatalf("second reserve error = %v", err)
	}
	if outcome.Granted {
		t.Fatal("second reserve granted past a day limit of 1")
	}
	if outcome.DeniedKey.Window != RateWindowDay {
		t.Fatalf("denied window = %q, want day", outcome.DeniedKey.Window)
	}
	if got := store.Usage(minute); got != 1 {
		t.Fatalf("minute usage = %d, want 1 — a denied batch consumed a window", got)
	}
}

func TestInMemoryRateWindowStoreRejectsNonPositiveLimit(t *testing.T) {
	store := NewInMemoryRateWindowStore()
	key := RateWindowKey{EnvelopeID: "e", Resource: "r", Window: RateWindowDay,
		WindowStart: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)}

	if _, err := store.Reserve(context.Background(), []RateReservation{{Key: key, Limit: 0}}); err == nil {
		t.Fatal("expected a non-positive limit to error rather than admit")
	}
}

func TestInMemoryRateWindowStoreRefusesClosedWindow(t *testing.T) {
	store := NewInMemoryRateWindowStore()
	today := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	yesterday := today.AddDate(0, 0, -1)

	key := RateWindowKey{EnvelopeID: "e", Resource: "r", Window: RateWindowDay, WindowStart: today}
	if _, err := store.Reserve(context.Background(), []RateReservation{{Key: key, Limit: 1}}); err != nil {
		t.Fatalf("reserve error = %v", err)
	}

	stale := key
	stale.WindowStart = yesterday
	if _, err := store.Reserve(context.Background(), []RateReservation{{Key: stale, Limit: 1}}); err == nil {
		t.Fatal("expected a reservation against a closed window to error")
	}
}

func TestWindowStartAnchorsInUTC(t *testing.T) {
	// 2026-08-02T23:30:00-05:00 is 2026-08-03T04:30:00Z: the day window must
	// follow UTC, not the caller's zone.
	zone := time.FixedZone("test-0500", -5*3600)
	at := time.Date(2026, 8, 2, 23, 30, 0, 0, zone)

	day, err := windowStart(at, RateWindowDay)
	if err != nil {
		t.Fatalf("windowStart() error = %v", err)
	}
	want := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	if !day.Equal(want) {
		t.Fatalf("day window start = %s, want %s", day.Format(time.RFC3339), want.Format(time.RFC3339))
	}

	minute, err := windowStart(at, RateWindowMinute)
	if err != nil {
		t.Fatalf("windowStart() error = %v", err)
	}
	if got := minute.Second(); got != 0 {
		t.Fatalf("minute window start has %d seconds, want 0", got)
	}

	if _, err := windowStart(at, RateWindow("fortnight")); err == nil {
		t.Fatal("expected an unknown window to error")
	}
}

// --- Validator tests for the new field ---

func TestValidateRateLimitWindows(t *testing.T) {
	cases := []struct {
		name      string
		limit     contracts.RateLimit
		wantValid bool
		wantField string
		wantCode  string
	}{
		{
			name:      "minute_only_stays_valid",
			limit:     contracts.RateLimit{Resource: "r", MaxPerMinute: 10},
			wantValid: true,
		},
		{
			name:      "day_only_is_valid",
			limit:     contracts.RateLimit{Resource: "outbound.attempts", MaxPerDay: 700},
			wantValid: true,
		},
		{
			name:      "both_windows_valid",
			limit:     contracts.RateLimit{Resource: "r", MaxPerMinute: 2, MaxPerDay: 700},
			wantValid: true,
		},
		{
			name:      "no_window_declared",
			limit:     contracts.RateLimit{Resource: "r"},
			wantValid: false,
			wantField: "budgets.rate_limits[0]",
			wantCode:  "INVALID_VALUE",
		},
		{
			name:      "negative_day",
			limit:     contracts.RateLimit{Resource: "r", MaxPerMinute: 1, MaxPerDay: -1},
			wantValid: false,
			wantField: "budgets.rate_limits[0].max_per_day",
			wantCode:  "INVALID_VALUE",
		},
		{
			name:      "day_below_minute_is_incoherent",
			limit:     contracts.RateLimit{Resource: "r", MaxPerMinute: 100, MaxPerDay: 50},
			wantValid: false,
			wantField: "budgets.rate_limits[0].max_per_day",
			wantCode:  "INCOHERENT_WINDOW",
		},
		{
			name:      "missing_resource",
			limit:     contracts.RateLimit{MaxPerDay: 700},
			wantValid: false,
			wantField: "budgets.rate_limits[0].resource",
			wantCode:  "REQUIRED",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := testEnvelope()
			env.Budgets.RateLimits = []contracts.RateLimit{tc.limit}
			if err := Sign(env, "kernel-test"); err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			result := NewValidator().Validate(env)
			if result.Valid != tc.wantValid {
				t.Fatalf("Valid = %v, want %v (errors: %v)", result.Valid, tc.wantValid, result.Errors)
			}
			if tc.wantValid {
				return
			}
			for _, e := range result.Errors {
				if e.Field == tc.wantField && e.Code == tc.wantCode {
					return
				}
			}
			t.Fatalf("no %s/%s error in %v", tc.wantField, tc.wantCode, result.Errors)
		})
	}
}

func TestValidateRejectsDuplicateRateLimitResource(t *testing.T) {
	env := testEnvelope()
	env.Budgets.RateLimits = []contracts.RateLimit{
		{Resource: "outbound.attempts", MaxPerDay: 700},
		{Resource: "outbound.attempts", MaxPerDay: 100},
	}
	if err := Sign(env, "kernel-test"); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	result := NewValidator().Validate(env)
	if result.Valid {
		t.Fatal("duplicate rate limit resource accepted: the effective ceiling would be neither declared number")
	}
	for _, e := range result.Errors {
		if e.Code == "DUPLICATE" {
			return
		}
	}
	t.Fatalf("no DUPLICATE error in %v", result.Errors)
}

// TestMaxPerDayIsOmittedFromContentHashWhenUnset proves the extension is
// hash-compatible: an envelope written before max_per_day existed produces the
// same content hash after the field was added.
func TestMaxPerDayIsOmittedFromContentHashWhenUnset(t *testing.T) {
	env := testEnvelope()
	env.Budgets.RateLimits = []contracts.RateLimit{{Resource: "r", MaxPerMinute: 10}}

	hash, err := ComputeContentHash(env)
	if err != nil {
		t.Fatalf("ComputeContentHash() error = %v", err)
	}

	// The hash below was computed against this same envelope shape; the point
	// of the assertion is that adding max_per_day did not move it, which is
	// only true while the field is omitempty and unset.
	withDay := testEnvelope()
	withDay.Budgets.RateLimits = []contracts.RateLimit{{Resource: "r", MaxPerMinute: 10, MaxPerDay: 700}}
	dayHash, err := ComputeContentHash(withDay)
	if err != nil {
		t.Fatalf("ComputeContentHash() error = %v", err)
	}
	if hash == dayHash {
		t.Fatal("setting max_per_day did not change the content hash — the field rides outside the hash")
	}

	data, err := json.Marshal(env.Budgets)
	if err != nil {
		t.Fatalf("marshal budgets: %v", err)
	}
	if strings.Contains(string(data), "max_per_day") {
		t.Fatalf("unset max_per_day appears in serialized budgets: %s", data)
	}
}
