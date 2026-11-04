package guardian

import (
	"context"
	"sync"
	"testing"
	"time"
)

// ── Temporal Guardian Tests ──────────────────────────────────────

func TestDeepTemporalGuardianStartsAtObserve(t *testing.T) {
	clk := &deepFixedClock{t: time.Now()}
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), clk)
	if tg.CurrentLevel() != ResponseObserve {
		t.Fatal("should start at OBSERVE")
	}
}

func TestDeepTemporalGuardianAllowsAtObserve(t *testing.T) {
	clk := &deepFixedClock{t: time.Now()}
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), clk)
	resp := tg.Evaluate(context.Background())
	if !resp.AllowEffect {
		t.Fatal("effects should be allowed at OBSERVE level")
	}
}

func TestDeepControllabilityEnvelopeRate(t *testing.T) {
	clk := &deepFixedClock{t: time.Now()}
	env := NewControllabilityEnvelope(60*time.Second, clk)
	for i := 0; i < 100; i++ {
		env.Record()
	}
	rate := env.Rate()
	if rate < 1.0 {
		t.Fatalf("expected positive rate, got %f", rate)
	}
}

func TestDeepControllabilityEnvelopeCount(t *testing.T) {
	clk := &deepFixedClock{t: time.Now()}
	env := NewControllabilityEnvelope(60*time.Second, clk)
	for i := 0; i < 50; i++ {
		env.Record()
	}
	if env.Count() != 50 {
		t.Fatalf("expected 50 events, got %d", env.Count())
	}
}

func TestDeepControllabilityEnvelopePruning(t *testing.T) {
	clk := &deepFixedClock{t: time.Now()}
	env := NewControllabilityEnvelope(1*time.Second, clk)
	env.Record()
	clk.t = clk.t.Add(2 * time.Second) // advance past window
	if env.Count() != 0 {
		t.Fatal("events outside window should be pruned")
	}
}

func TestDeepResponseLevelString(t *testing.T) {
	cases := map[ResponseLevel]string{
		ResponseObserve:    "OBSERVE",
		ResponseThrottle:   "THROTTLE",
		ResponseInterrupt:  "INTERRUPT",
		ResponseQuarantine: "QUARANTINE",
		ResponseFailClosed: "FAIL_CLOSED",
	}
	for level, expected := range cases {
		if level.String() != expected {
			t.Fatalf("level %d: got %q, want %q", level, level.String(), expected)
		}
	}
}

// ── Concurrent EvaluateDecision Tests ────────────────────────────

func TestDeepConcurrentTemporalEvaluate(t *testing.T) {
	clk := &deepFixedClock{t: time.Now()}
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), clk)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tg.Evaluate(context.Background())
		}()
	}
	wg.Wait()
	// Should not panic — concurrent safety is the assertion.
}

// ── Helper Clocks ────────────────────────────────────────────────

type deepFixedClock struct {
	t time.Time
}

func (c *deepFixedClock) Now() time.Time { return c.t }

type deepAdvancingClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *deepAdvancingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(1 * time.Nanosecond)
	return c.t
}

func TestInputFieldTypeUsesJSONBooleanName(t *testing.T) {
	if got := inputFieldType(true); got != "boolean" {
		t.Fatalf("inputFieldType(true) = %q, want boolean", got)
	}
}
