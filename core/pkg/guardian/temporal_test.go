package guardian

import (
	"context"
	"testing"
	"time"
)

// fixedClock is a test clock that returns a controllable time.
type fixedClock struct {
	t time.Time
}

func (c *fixedClock) Now() time.Time          { return c.t }
func (c *fixedClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newFixedClock() *fixedClock {
	return &fixedClock{t: time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC)}
}

func TestControllabilityEnvelope_Rate(t *testing.T) {
	clk := newFixedClock()
	env := NewControllabilityEnvelope(10*time.Second, clk)

	// No events → rate 0.
	if r := env.Rate(); r != 0.0 {
		t.Fatalf("expected rate 0, got %f", r)
	}

	// Add 10 events → rate = 10 / 10s = 1.0 effects/s.
	for i := 0; i < 10; i++ {
		env.Record()
	}
	rate := env.Rate()
	if rate != 1.0 {
		t.Fatalf("expected rate 1.0, got %f", rate)
	}

	// Advance past window → events pruned → rate 0.
	clk.Advance(11 * time.Second)
	rate = env.Rate()
	if rate != 0.0 {
		t.Fatalf("expected rate 0 after window expiry, got %f", rate)
	}
}

func TestControllabilityEnvelope_Count(t *testing.T) {
	clk := newFixedClock()
	env := NewControllabilityEnvelope(5*time.Second, clk)

	env.Record()
	env.Record()
	env.Record()
	if c := env.Count(); c != 3 {
		t.Fatalf("expected count 3, got %d", c)
	}

	clk.Advance(6 * time.Second)
	if c := env.Count(); c != 0 {
		t.Fatalf("expected count 0 after expiry, got %d", c)
	}
}

func TestTemporalGuardian_ObserveLevel(t *testing.T) {
	clk := newFixedClock()
	policy := DefaultEscalationPolicy()
	tg := NewTemporalGuardian(policy, clk)

	// Single effect → should stay at Observe.
	resp := tg.Evaluate(context.Background())
	if resp.Level != ResponseObserve {
		t.Fatalf("expected OBSERVE, got %s", resp.Level)
	}
	if !resp.AllowEffect {
		t.Fatal("effect should be allowed at OBSERVE")
	}
}

func TestTemporalGuardian_EscalationToThrottle(t *testing.T) {
	clk := newFixedClock()
	policy := EscalationPolicy{
		WindowSize: 10 * time.Second,
		Thresholds: []EscalationThreshold{
			{Level: ResponseThrottle, MaxRate: 5.0, SustainedFor: 0, CooldownAfter: 5 * time.Second},
			{Level: ResponseInterrupt, MaxRate: 20.0, SustainedFor: 0, CooldownAfter: 10 * time.Second},
		},
	}
	tg := NewTemporalGuardian(policy, clk)

	// Fire 51 effects (rate = 51/10s = 5.1 > 5.0 threshold).
	// SustainedFor is 0, so escalation is immediate once threshold exceeded.
	var resp GradedResponse
	for i := 0; i < 51; i++ {
		resp = tg.Evaluate(context.Background())
	}
	if resp.Level != ResponseThrottle {
		t.Fatalf("expected THROTTLE after high rate, got %s (rate=%.1f)", resp.Level, resp.WindowRate)
	}
	if !resp.AllowEffect {
		t.Fatal("effect should still be allowed at THROTTLE (rate-limited, not blocked)")
	}
}

func TestTemporalGuardian_EscalationToInterrupt(t *testing.T) {
	clk := newFixedClock()
	policy := EscalationPolicy{
		WindowSize: 10 * time.Second,
		Thresholds: []EscalationThreshold{
			{Level: ResponseThrottle, MaxRate: 5.0, SustainedFor: 0, CooldownAfter: 5 * time.Second},
			{Level: ResponseInterrupt, MaxRate: 15.0, SustainedFor: 0, CooldownAfter: 10 * time.Second},
		},
	}
	tg := NewTemporalGuardian(policy, clk)

	// Fire 151 effects → rate = 151/10 = 15.1 > 15.0.
	var resp GradedResponse
	for i := 0; i < 151; i++ {
		resp = tg.Evaluate(context.Background())
	}
	if resp.Level != ResponseInterrupt {
		t.Fatalf("expected INTERRUPT, got %s (rate=%.1f)", resp.Level, resp.WindowRate)
	}
	if resp.AllowEffect {
		t.Fatal("effect should be BLOCKED at INTERRUPT")
	}
}

func TestTemporalGuardian_DeescalationOnCooldown(t *testing.T) {
	clk := newFixedClock()
	policy := EscalationPolicy{
		WindowSize: 10 * time.Second,
		Thresholds: []EscalationThreshold{
			{Level: ResponseThrottle, MaxRate: 5.0, SustainedFor: 0, CooldownAfter: 5 * time.Second},
		},
	}
	tg := NewTemporalGuardian(policy, clk)

	// Escalate to THROTTLE.
	for i := 0; i < 51; i++ {
		tg.Evaluate(context.Background())
	}
	if tg.CurrentLevel() != ResponseThrottle {
		t.Fatalf("expected THROTTLE, got %s", tg.CurrentLevel())
	}

	// Advance past window (events expire) + cooldown.
	clk.Advance(16 * time.Second)

	// Next evaluate should de-escalate to OBSERVE.
	resp := tg.Evaluate(context.Background())
	if resp.Level != ResponseObserve {
		t.Fatalf("expected de-escalation to OBSERVE, got %s", resp.Level)
	}
}

func TestTemporalGuardian_FailClosedLevel(t *testing.T) {
	clk := newFixedClock()
	policy := EscalationPolicy{
		WindowSize: 10 * time.Second,
		Thresholds: []EscalationThreshold{
			{Level: ResponseThrottle, MaxRate: 5.0, SustainedFor: 0, CooldownAfter: 5 * time.Second},
			{Level: ResponseInterrupt, MaxRate: 10.0, SustainedFor: 0, CooldownAfter: 10 * time.Second},
			{Level: ResponseQuarantine, MaxRate: 20.0, SustainedFor: 0, CooldownAfter: 30 * time.Second},
			{Level: ResponseFailClosed, MaxRate: 50.0, SustainedFor: 0, CooldownAfter: 60 * time.Second},
		},
	}
	tg := NewTemporalGuardian(policy, clk)

	// Flood: 501 effects → rate = 50.1 > 50.0.
	var resp GradedResponse
	for i := 0; i < 501; i++ {
		resp = tg.Evaluate(context.Background())
	}
	if resp.Level != ResponseFailClosed {
		t.Fatalf("expected FAIL_CLOSED at extreme rate, got %s (rate=%.1f)", resp.Level, resp.WindowRate)
	}
	if resp.AllowEffect {
		t.Fatal("no effects should be allowed at FAIL_CLOSED")
	}
	if resp.Duration != 300*time.Second {
		t.Fatalf("expected 300s hold at FAIL_CLOSED, got %s", resp.Duration)
	}
}

func TestTemporalGuardian_SustainedForDelay(t *testing.T) {
	clk := newFixedClock()
	policy := EscalationPolicy{
		WindowSize: 10 * time.Second,
		Thresholds: []EscalationThreshold{
			{Level: ResponseThrottle, MaxRate: 5.0, SustainedFor: 3 * time.Second, CooldownAfter: 5 * time.Second},
		},
	}
	tg := NewTemporalGuardian(policy, clk)

	// Exceed threshold but not sustained long enough.
	for i := 0; i < 51; i++ {
		tg.Evaluate(context.Background())
	}
	// Should still be OBSERVE (sustained for only 0s, need 3s).
	if tg.CurrentLevel() != ResponseObserve {
		t.Fatalf("expected OBSERVE (sustained not met), got %s", tg.CurrentLevel())
	}

	// Advance 3 seconds and fire more.
	clk.Advance(3 * time.Second)
	for i := 0; i < 51; i++ {
		tg.Evaluate(context.Background())
	}
	// Now should be THROTTLE (rate still high + sustained 3s).
	if tg.CurrentLevel() != ResponseThrottle {
		t.Fatalf("expected THROTTLE after sustained period, got %s", tg.CurrentLevel())
	}
}

func TestResponseLevel_String(t *testing.T) {
	tests := []struct {
		level ResponseLevel
		want  string
	}{
		{ResponseObserve, "OBSERVE"},
		{ResponseThrottle, "THROTTLE"},
		{ResponseInterrupt, "INTERRUPT"},
		{ResponseQuarantine, "QUARANTINE"},
		{ResponseFailClosed, "FAIL_CLOSED"},
		{ResponseLevel(99), "UNKNOWN(99)"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("ResponseLevel(%d).String() = %q, want %q", int(tt.level), got, tt.want)
		}
	}
}
