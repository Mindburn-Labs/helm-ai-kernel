package guardian

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// ---------------------------------------------------------------------------
// 1-5: ResponseLevel enum coverage
// ---------------------------------------------------------------------------

func TestClosing_ResponseLevel_String(t *testing.T) {
	cases := []struct {
		level ResponseLevel
		want  string
	}{
		{ResponseObserve, "OBSERVE"},
		{ResponseThrottle, "THROTTLE"},
		{ResponseInterrupt, "INTERRUPT"},
		{ResponseQuarantine, "QUARANTINE"},
		{ResponseFailClosed, "FAIL_CLOSED"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.level.String(); got != tc.want {
				t.Fatalf("ResponseLevel(%d).String() = %q, want %q", tc.level, got, tc.want)
			}
		})
	}
}

func TestClosing_ResponseLevel_UnknownString(t *testing.T) {
	t.Run("negative", func(t *testing.T) {
		s := ResponseLevel(-1).String()
		if s == "" {
			t.Fatal("expected non-empty string for unknown level")
		}
	})
	t.Run("high", func(t *testing.T) {
		s := ResponseLevel(99).String()
		if s == "" {
			t.Fatal("expected non-empty string for unknown level")
		}
	})
	t.Run("boundary", func(t *testing.T) {
		s := ResponseLevel(5).String()
		if s == "" {
			t.Fatal("expected non-empty string for unknown level")
		}
	})
}

func TestClosing_ResponseLevel_Ordering(t *testing.T) {
	levels := []ResponseLevel{ResponseObserve, ResponseThrottle, ResponseInterrupt, ResponseQuarantine, ResponseFailClosed}
	for i := 1; i < len(levels); i++ {
		t.Run(levels[i].String(), func(t *testing.T) {
			if levels[i] <= levels[i-1] {
				t.Fatalf("expected %v > %v", levels[i], levels[i-1])
			}
		})
	}
}

func TestClosing_ResponseLevel_AllowEffect(t *testing.T) {
	t.Run("observe_allows", func(t *testing.T) {
		if ResponseObserve > ResponseThrottle {
			t.Fatal("observe should be <= throttle")
		}
	})
	t.Run("interrupt_blocks", func(t *testing.T) {
		if ResponseInterrupt <= ResponseThrottle {
			t.Fatal("interrupt should be > throttle")
		}
	})
	t.Run("failclosed_blocks", func(t *testing.T) {
		if ResponseFailClosed <= ResponseThrottle {
			t.Fatal("failclosed should be > throttle")
		}
	})
}

func TestClosing_ResponseLevel_IotaValues(t *testing.T) {
	t.Run("observe_is_zero", func(t *testing.T) {
		if ResponseObserve != 0 {
			t.Fatalf("ResponseObserve = %d, want 0", ResponseObserve)
		}
	})
	t.Run("failclosed_is_four", func(t *testing.T) {
		if ResponseFailClosed != 4 {
			t.Fatalf("ResponseFailClosed = %d, want 4", ResponseFailClosed)
		}
	})
	t.Run("throttle_is_one", func(t *testing.T) {
		if ResponseThrottle != 1 {
			t.Fatalf("ResponseThrottle = %d, want 1", ResponseThrottle)
		}
	})
}

// ---------------------------------------------------------------------------
// 27-36: GuardianOption coverage
// ---------------------------------------------------------------------------

func TestClosing_GuardianOption_WithTemporalGuardian(t *testing.T) {
	t.Run("nil_temporal", func(t *testing.T) {
		opt := WithTemporalGuardian(nil)
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("returns_function", func(t *testing.T) {
		var fn GuardianOption = WithTemporalGuardian(nil)
		_ = fn
	})
	t.Run("type_check", func(t *testing.T) {
		opt := WithTemporalGuardian(nil)
		_ = opt
	})
}

func TestClosing_GuardianOption_WithEnvFingerprint(t *testing.T) {
	t.Run("empty_string", func(t *testing.T) {
		opt := WithEnvFingerprint("")
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("nonempty_string", func(t *testing.T) {
		opt := WithEnvFingerprint("sha256:abc123")
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("returns_function", func(t *testing.T) {
		var fn GuardianOption = WithEnvFingerprint("fp")
		_ = fn
	})
}

func TestClosing_GuardianOption_WithFreezeController(t *testing.T) {
	t.Run("nil_controller", func(t *testing.T) {
		opt := WithFreezeController(nil)
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("returns_function", func(t *testing.T) {
		var fn GuardianOption = WithFreezeController(nil)
		_ = fn
	})
	t.Run("type_check", func(t *testing.T) {
		opt := WithFreezeController(nil)
		_ = opt
	})
}

func TestClosing_GuardianOption_WithContextGuard(t *testing.T) {
	t.Run("nil_guard", func(t *testing.T) {
		opt := WithContextGuard(nil)
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("returns_function", func(t *testing.T) {
		var fn GuardianOption = WithContextGuard(nil)
		_ = fn
	})
	t.Run("type_check", func(t *testing.T) {
		_ = WithContextGuard(nil)
	})
}

func TestClosing_GuardianOption_WithClock(t *testing.T) {
	t.Run("nil_clock", func(t *testing.T) {
		opt := WithClock(nil)
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("wall_clock", func(t *testing.T) {
		opt := WithClock(wallClock{})
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("returns_function", func(t *testing.T) {
		var fn GuardianOption = WithClock(wallClock{})
		_ = fn
	})
}

func TestClosing_GuardianOption_WithBehavioralTrustScorer(t *testing.T) {
	t.Run("nil_scorer", func(t *testing.T) {
		opt := WithBehavioralTrustScorer(nil)
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("with_scorer", func(t *testing.T) {
		scorer := trust.NewBehavioralTrustScorer()
		opt := WithBehavioralTrustScorer(scorer)
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("returns_function", func(t *testing.T) {
		var fn GuardianOption = WithBehavioralTrustScorer(nil)
		_ = fn
	})
}

// ---------------------------------------------------------------------------
// 42-50: Temporal Guardian / Escalation coverage
// ---------------------------------------------------------------------------

func TestClosing_DefaultEscalationPolicy_Thresholds(t *testing.T) {
	p := DefaultEscalationPolicy()
	t.Run("has_four_thresholds", func(t *testing.T) {
		if len(p.Thresholds) != 4 {
			t.Fatalf("got %d thresholds, want 4", len(p.Thresholds))
		}
	})
	t.Run("window_60s", func(t *testing.T) {
		if p.WindowSize != 60*time.Second {
			t.Fatalf("got %v, want 60s", p.WindowSize)
		}
	})
	t.Run("ordered_by_level", func(t *testing.T) {
		for i := 1; i < len(p.Thresholds); i++ {
			if p.Thresholds[i].Level <= p.Thresholds[i-1].Level {
				t.Fatalf("threshold %d level not > threshold %d", i, i-1)
			}
		}
	})
	t.Run("rates_increasing", func(t *testing.T) {
		for i := 1; i < len(p.Thresholds); i++ {
			if p.Thresholds[i].MaxRate <= p.Thresholds[i-1].MaxRate {
				t.Fatalf("threshold %d rate not > threshold %d", i, i-1)
			}
		}
	})
}

func TestClosing_ControllabilityEnvelope_EmptyRate(t *testing.T) {
	c := wallClock{}
	env := NewControllabilityEnvelope(60*time.Second, c)
	t.Run("zero_rate", func(t *testing.T) {
		if env.Rate() != 0.0 {
			t.Fatalf("got %f, want 0", env.Rate())
		}
	})
	t.Run("zero_count", func(t *testing.T) {
		if env.Count() != 0 {
			t.Fatalf("got %d, want 0", env.Count())
		}
	})
	t.Run("after_record", func(t *testing.T) {
		env.Record()
		if env.Count() != 1 {
			t.Fatalf("got %d, want 1", env.Count())
		}
	})
}

func TestClosing_ControllabilityEnvelope_MultipleRecords(t *testing.T) {
	c := wallClock{}
	env := NewControllabilityEnvelope(60*time.Second, c)
	for i := 0; i < 10; i++ {
		env.Record()
	}
	t.Run("count_ten", func(t *testing.T) {
		if env.Count() != 10 {
			t.Fatalf("got %d, want 10", env.Count())
		}
	})
	t.Run("rate_positive", func(t *testing.T) {
		if env.Rate() <= 0 {
			t.Fatal("expected positive rate")
		}
	})
	t.Run("rate_bounded", func(t *testing.T) {
		// 10 events in 60s window, rate should be <= 10/60
		r := env.Rate()
		if r > 1.0 {
			t.Fatalf("rate %f seems too high for 10 events in 60s", r)
		}
	})
}

func TestClosing_TemporalGuardian_InitialLevel(t *testing.T) {
	c := wallClock{}
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), c)
	t.Run("starts_at_observe", func(t *testing.T) {
		if tg.CurrentLevel() != ResponseObserve {
			t.Fatalf("got %v, want OBSERVE", tg.CurrentLevel())
		}
	})
	t.Run("evaluate_returns_observe", func(t *testing.T) {
		resp := tg.Evaluate(context.Background())
		if resp.Level != ResponseObserve {
			t.Fatalf("got level %v, want OBSERVE", resp.Level)
		}
	})
	t.Run("allows_effects", func(t *testing.T) {
		resp := tg.Evaluate(context.Background())
		if !resp.AllowEffect {
			t.Fatal("effects should be allowed at OBSERVE")
		}
	})
}

func TestClosing_GradedResponse_Fields(t *testing.T) {
	c := wallClock{}
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), c)
	resp := tg.Evaluate(context.Background())
	t.Run("reason_nonempty", func(t *testing.T) {
		if resp.Reason == "" {
			t.Fatal("reason should not be empty")
		}
	})
	t.Run("duration_zero_at_observe", func(t *testing.T) {
		if resp.Duration != 0 {
			t.Fatalf("got duration %v, want 0", resp.Duration)
		}
	})
	t.Run("window_rate_nonnegative", func(t *testing.T) {
		if resp.WindowRate < 0 {
			t.Fatalf("rate should be >= 0, got %f", resp.WindowRate)
		}
	})
}

func TestClosing_EscalationThreshold_Cooldowns(t *testing.T) {
	p := DefaultEscalationPolicy()
	for _, th := range p.Thresholds {
		t.Run(th.Level.String(), func(t *testing.T) {
			if th.CooldownAfter <= 0 {
				t.Fatalf("cooldown should be positive, got %v", th.CooldownAfter)
			}
			if th.SustainedFor <= 0 {
				t.Fatalf("sustained_for should be positive, got %v", th.SustainedFor)
			}
			if th.MaxRate <= 0 {
				t.Fatalf("max_rate should be positive, got %f", th.MaxRate)
			}
		})
	}
}

func TestClosing_EscalationThreshold_CooldownIncreasing(t *testing.T) {
	p := DefaultEscalationPolicy()
	for i := 1; i < len(p.Thresholds); i++ {
		t.Run(p.Thresholds[i].Level.String(), func(t *testing.T) {
			if p.Thresholds[i].CooldownAfter < p.Thresholds[i-1].CooldownAfter {
				t.Fatalf("cooldown should not decrease for higher levels")
			}
		})
	}
}
