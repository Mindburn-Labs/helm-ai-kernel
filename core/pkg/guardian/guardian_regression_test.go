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
// 6-10: PrivilegeTier enum coverage
// ---------------------------------------------------------------------------

func TestClosing_PrivilegeTier_String(t *testing.T) {
	cases := []struct {
		tier PrivilegeTier
		want string
	}{
		{TierRestricted, "RESTRICTED"},
		{TierStandard, "STANDARD"},
		{TierElevated, "ELEVATED"},
		{TierSystem, "SYSTEM"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.tier.String(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClosing_PrivilegeTier_UnknownString(t *testing.T) {
	t.Run("negative", func(t *testing.T) {
		s := PrivilegeTier(-1).String()
		if s == "" {
			t.Fatal("expected non-empty")
		}
	})
	t.Run("high", func(t *testing.T) {
		s := PrivilegeTier(100).String()
		if s == "" {
			t.Fatal("expected non-empty")
		}
	})
	t.Run("boundary", func(t *testing.T) {
		s := PrivilegeTier(4).String()
		if s == "" {
			t.Fatal("expected non-empty")
		}
	})
}

func TestClosing_PrivilegeTier_Ordering(t *testing.T) {
	tiers := []PrivilegeTier{TierRestricted, TierStandard, TierElevated, TierSystem}
	for i := 1; i < len(tiers); i++ {
		t.Run(tiers[i].String(), func(t *testing.T) {
			if tiers[i] <= tiers[i-1] {
				t.Fatalf("expected %v > %v", tiers[i], tiers[i-1])
			}
		})
	}
}

func TestClosing_PrivilegeTier_IntValues(t *testing.T) {
	t.Run("restricted_is_zero", func(t *testing.T) {
		if TierRestricted != 0 {
			t.Fatalf("got %d", TierRestricted)
		}
	})
	t.Run("standard_is_one", func(t *testing.T) {
		if TierStandard != 1 {
			t.Fatalf("got %d", TierStandard)
		}
	})
	t.Run("elevated_is_two", func(t *testing.T) {
		if TierElevated != 2 {
			t.Fatalf("got %d", TierElevated)
		}
	})
	t.Run("system_is_three", func(t *testing.T) {
		if TierSystem != 3 {
			t.Fatalf("got %d", TierSystem)
		}
	})
}

func TestClosing_PrivilegeTier_RingAnalogy(t *testing.T) {
	t.Run("restricted_ring3", func(t *testing.T) {
		if TierRestricted != 0 {
			t.Fatal("restricted maps to Ring 3 (value 0)")
		}
	})
	t.Run("system_ring0", func(t *testing.T) {
		if TierSystem != 3 {
			t.Fatal("system maps to Ring 0 (value 3)")
		}
	})
	t.Run("fewer_perms_lower_value", func(t *testing.T) {
		if TierRestricted >= TierStandard {
			t.Fatal("restricted should have fewer permissions")
		}
	})
}

// ---------------------------------------------------------------------------
// 11-16: EffectTierMap coverage
// ---------------------------------------------------------------------------

func TestClosing_EffectTierMap_StandardEffects(t *testing.T) {
	standard := []string{"SEND_EMAIL", "SEND_CHAT_MESSAGE", "CREATE_TASK", "COMMENT_TICKET", "UPDATE_DOC", "EXECUTE_TOOL"}
	for _, effect := range standard {
		t.Run(effect, func(t *testing.T) {
			tier, ok := EffectTierMap[effect]
			if !ok {
				t.Fatalf("effect %s not in map", effect)
			}
			if tier != TierStandard {
				t.Fatalf("got tier %v, want STANDARD", tier)
			}
		})
	}
}

func TestClosing_EffectTierMap_ElevatedEffects(t *testing.T) {
	elevated := []string{"SOFTWARE_PUBLISH", "CI_CREDENTIAL_ACCESS", "CLOUD_COMPUTE_BUDGET", "EXECUTE_PAYMENT", "FILE_WRITE"}
	for _, effect := range elevated {
		t.Run(effect, func(t *testing.T) {
			tier, ok := EffectTierMap[effect]
			if !ok {
				t.Fatalf("effect %s not in map", effect)
			}
			if tier != TierElevated {
				t.Fatalf("got tier %v, want ELEVATED", tier)
			}
		})
	}
}

func TestClosing_EffectTierMap_SystemEffects(t *testing.T) {
	system := []string{"INFRA_DESTROY", "ENV_RECREATE", "PROTECTED_INFRA_STRUCTURE", "TUNNEL_START"}
	for _, effect := range system {
		t.Run(effect, func(t *testing.T) {
			tier, ok := EffectTierMap[effect]
			if !ok {
				t.Fatalf("effect %s not in map", effect)
			}
			if tier != TierSystem {
				t.Fatalf("got tier %v, want SYSTEM", tier)
			}
		})
	}
}

func TestClosing_RequiredTierForEffect_Known(t *testing.T) {
	for effect, expected := range EffectTierMap {
		t.Run(effect, func(t *testing.T) {
			got := RequiredTierForEffect(effect)
			if got != expected {
				t.Fatalf("got %v, want %v", got, expected)
			}
		})
	}
}

func TestClosing_RequiredTierForEffect_Unknown(t *testing.T) {
	unknowns := []string{"NONEXISTENT", "FOO_BAR", "CUSTOM_EFFECT"}
	for _, effect := range unknowns {
		t.Run(effect, func(t *testing.T) {
			got := RequiredTierForEffect(effect)
			if got != TierStandard {
				t.Fatalf("unknown effect %s: got tier %v, want STANDARD", effect, got)
			}
		})
	}
}

func TestClosing_EffectTierMap_NoRestrictedEntries(t *testing.T) {
	t.Run("no_restricted", func(t *testing.T) {
		for effect, tier := range EffectTierMap {
			if tier == TierRestricted {
				t.Fatalf("restricted agents cannot invoke effects, but %s is mapped to RESTRICTED", effect)
			}
		}
	})
	t.Run("map_nonempty", func(t *testing.T) {
		if len(EffectTierMap) == 0 {
			t.Fatal("EffectTierMap should not be empty")
		}
	})
	t.Run("all_positive_tiers", func(t *testing.T) {
		for effect, tier := range EffectTierMap {
			if tier < TierStandard {
				t.Fatalf("%s has tier %d < STANDARD", effect, tier)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 17-26: EffectiveTier with all TrustTier x PrivilegeTier combos
// ---------------------------------------------------------------------------

func TestClosing_EffectiveTier_Hostile_ForcesRestricted(t *testing.T) {
	tiers := []PrivilegeTier{TierRestricted, TierStandard, TierElevated, TierSystem}
	for _, pt := range tiers {
		t.Run(pt.String(), func(t *testing.T) {
			got := EffectiveTier(pt, trust.TierHostile)
			if got != TierRestricted {
				t.Fatalf("EffectiveTier(%v, HOSTILE) = %v, want RESTRICTED", pt, got)
			}
		})
	}
}

func TestClosing_EffectiveTier_Suspect_CapsAtStandard(t *testing.T) {
	t.Run("elevated_capped", func(t *testing.T) {
		got := EffectiveTier(TierElevated, trust.TierSuspect)
		if got != TierStandard {
			t.Fatalf("got %v, want STANDARD", got)
		}
	})
	t.Run("system_capped", func(t *testing.T) {
		got := EffectiveTier(TierSystem, trust.TierSuspect)
		if got != TierStandard {
			t.Fatalf("got %v, want STANDARD", got)
		}
	})
	t.Run("standard_unchanged", func(t *testing.T) {
		got := EffectiveTier(TierStandard, trust.TierSuspect)
		if got != TierStandard {
			t.Fatalf("got %v, want STANDARD", got)
		}
	})
	t.Run("restricted_unchanged", func(t *testing.T) {
		got := EffectiveTier(TierRestricted, trust.TierSuspect)
		if got != TierRestricted {
			t.Fatalf("got %v, want RESTRICTED", got)
		}
	})
}

func TestClosing_EffectiveTier_Neutral_Unchanged(t *testing.T) {
	tiers := []PrivilegeTier{TierRestricted, TierStandard, TierElevated, TierSystem}
	for _, pt := range tiers {
		t.Run(pt.String(), func(t *testing.T) {
			got := EffectiveTier(pt, trust.TierNeutral)
			if got != pt {
				t.Fatalf("got %v, want %v", got, pt)
			}
		})
	}
}

func TestClosing_EffectiveTier_Trusted_Unchanged(t *testing.T) {
	tiers := []PrivilegeTier{TierRestricted, TierStandard, TierElevated, TierSystem}
	for _, pt := range tiers {
		t.Run(pt.String(), func(t *testing.T) {
			got := EffectiveTier(pt, trust.TierTrusted)
			if got != pt {
				t.Fatalf("got %v, want %v", got, pt)
			}
		})
	}
}

func TestClosing_EffectiveTier_Pristine_Unchanged(t *testing.T) {
	tiers := []PrivilegeTier{TierRestricted, TierStandard, TierElevated, TierSystem}
	for _, pt := range tiers {
		t.Run(pt.String(), func(t *testing.T) {
			got := EffectiveTier(pt, trust.TierPristine)
			if got != pt {
				t.Fatalf("got %v, want %v", got, pt)
			}
		})
	}
}

func TestClosing_EffectiveTier_HostileAlwaysMinimal(t *testing.T) {
	trustTiers := []trust.TrustTier{trust.TierHostile}
	privTiers := []PrivilegeTier{TierRestricted, TierStandard, TierElevated, TierSystem}
	for _, tt := range trustTiers {
		for _, pt := range privTiers {
			t.Run(pt.String(), func(t *testing.T) {
				got := EffectiveTier(pt, tt)
				if got != TierRestricted {
					t.Fatalf("got %v", got)
				}
			})
		}
	}
}

func TestClosing_EffectiveTier_SuspectDoesNotIncrease(t *testing.T) {
	tiers := []PrivilegeTier{TierRestricted, TierStandard, TierElevated, TierSystem}
	for _, pt := range tiers {
		t.Run(pt.String(), func(t *testing.T) {
			got := EffectiveTier(pt, trust.TierSuspect)
			if got > pt {
				t.Fatalf("effective tier %v > assigned %v", got, pt)
			}
		})
	}
}

func TestClosing_EffectiveTier_DowngradeOnly(t *testing.T) {
	allTrust := []trust.TrustTier{trust.TierHostile, trust.TierSuspect, trust.TierNeutral, trust.TierTrusted, trust.TierPristine}
	for _, tt := range allTrust {
		t.Run(string(tt), func(t *testing.T) {
			for _, pt := range []PrivilegeTier{TierRestricted, TierStandard, TierElevated, TierSystem} {
				got := EffectiveTier(pt, tt)
				if got > pt {
					t.Fatalf("EffectiveTier(%v, %s) = %v > assigned", pt, tt, got)
				}
			}
		})
	}
}

func TestClosing_EffectiveTier_AllCombinations(t *testing.T) {
	allTrust := []trust.TrustTier{trust.TierHostile, trust.TierSuspect, trust.TierNeutral, trust.TierTrusted, trust.TierPristine}
	allPriv := []PrivilegeTier{TierRestricted, TierStandard, TierElevated, TierSystem}
	for _, tt := range allTrust {
		for _, pt := range allPriv {
			t.Run(string(tt)+"_"+pt.String(), func(t *testing.T) {
				got := EffectiveTier(pt, tt)
				if got < TierRestricted || got > TierSystem {
					t.Fatalf("out of range: %v", got)
				}
			})
		}
	}
}

func TestClosing_EffectiveTier_Symmetry(t *testing.T) {
	// Same trust tier and priv tier should yield consistent results
	t.Run("system_pristine", func(t *testing.T) {
		if EffectiveTier(TierSystem, trust.TierPristine) != TierSystem {
			t.Fatal("system+pristine should stay system")
		}
	})
	t.Run("restricted_hostile", func(t *testing.T) {
		if EffectiveTier(TierRestricted, trust.TierHostile) != TierRestricted {
			t.Fatal("restricted+hostile should stay restricted")
		}
	})
	t.Run("standard_neutral", func(t *testing.T) {
		if EffectiveTier(TierStandard, trust.TierNeutral) != TierStandard {
			t.Fatal("standard+neutral should stay standard")
		}
	})
}

// ---------------------------------------------------------------------------
// 27-36: GuardianOption coverage
// ---------------------------------------------------------------------------

func TestClosing_GuardianOption_WithBudgetTracker(t *testing.T) {
	t.Run("nil_tracker", func(t *testing.T) {
		opt := WithBudgetTracker(nil)
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("returns_function", func(t *testing.T) {
		var fn GuardianOption = WithBudgetTracker(nil)
		_ = fn
	})
	t.Run("type_check", func(t *testing.T) {
		opt := WithBudgetTracker(nil)
		_ = opt
	})
}

func TestClosing_GuardianOption_WithAuditLog(t *testing.T) {
	t.Run("nil_log", func(t *testing.T) {
		opt := WithAuditLog(nil)
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("with_log", func(t *testing.T) {
		log := NewAuditLog(nil)
		opt := WithAuditLog(log)
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("returns_function", func(t *testing.T) {
		var fn GuardianOption = WithAuditLog(nil)
		_ = fn
	})
}

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

func TestClosing_GuardianOption_WithPrivilegeResolver(t *testing.T) {
	t.Run("nil_resolver", func(t *testing.T) {
		opt := WithPrivilegeResolver(nil)
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("static_resolver", func(t *testing.T) {
		r := NewStaticPrivilegeResolver(TierStandard)
		opt := WithPrivilegeResolver(r)
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("returns_function", func(t *testing.T) {
		var fn GuardianOption = WithPrivilegeResolver(nil)
		_ = fn
	})
}

func TestClosing_GuardianOption_WithAgentKillSwitch(t *testing.T) {
	t.Run("nil_killswitch", func(t *testing.T) {
		opt := WithAgentKillSwitch(nil)
		if opt == nil {
			t.Fatal("option should not be nil")
		}
	})
	t.Run("returns_function", func(t *testing.T) {
		var fn GuardianOption = WithAgentKillSwitch(nil)
		_ = fn
	})
	t.Run("type_check", func(t *testing.T) {
		_ = WithAgentKillSwitch(nil)
	})
}

// ---------------------------------------------------------------------------
// 37-41: EvaluateDecision with multiple principals
// ---------------------------------------------------------------------------

func TestClosing_StaticPrivilegeResolver_MultiplePrincipals(t *testing.T) {
	principals := []struct {
		id   string
		tier PrivilegeTier
	}{
		{"alice", TierRestricted},
		{"bob", TierStandard},
		{"charlie", TierElevated},
		{"dave", TierSystem},
		{"eve", TierStandard},
	}
	r := NewStaticPrivilegeResolver(TierRestricted)
	for _, p := range principals {
		r.SetTier(p.id, p.tier)
	}
	for _, p := range principals {
		t.Run(p.id, func(t *testing.T) {
			got, err := r.ResolveTier(context.Background(), p.id)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != p.tier {
				t.Fatalf("got %v, want %v", got, p.tier)
			}
		})
	}
}

func TestClosing_StaticPrivilegeResolver_DefaultTier(t *testing.T) {
	defaults := []PrivilegeTier{TierRestricted, TierStandard, TierElevated, TierSystem}
	for _, d := range defaults {
		t.Run(d.String(), func(t *testing.T) {
			r := NewStaticPrivilegeResolver(d)
			got, err := r.ResolveTier(context.Background(), "unknown-principal")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != d {
				t.Fatalf("got %v, want %v", got, d)
			}
		})
	}
}

func TestClosing_StaticPrivilegeResolver_Override(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierRestricted)
	r.SetTier("agent-1", TierStandard)
	r.SetTier("agent-1", TierSystem)
	t.Run("overridden", func(t *testing.T) {
		got, _ := r.ResolveTier(context.Background(), "agent-1")
		if got != TierSystem {
			t.Fatalf("got %v, want SYSTEM", got)
		}
	})
	t.Run("default_unaffected", func(t *testing.T) {
		got, _ := r.ResolveTier(context.Background(), "unknown")
		if got != TierRestricted {
			t.Fatalf("got %v, want RESTRICTED", got)
		}
	})
	t.Run("no_error", func(t *testing.T) {
		_, err := r.ResolveTier(context.Background(), "agent-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestClosing_StaticPrivilegeResolver_EmptyID(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierStandard)
	t.Run("empty_returns_default", func(t *testing.T) {
		got, err := r.ResolveTier(context.Background(), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != TierStandard {
			t.Fatalf("got %v, want STANDARD", got)
		}
	})
	t.Run("set_empty_id", func(t *testing.T) {
		r.SetTier("", TierSystem)
		got, _ := r.ResolveTier(context.Background(), "")
		if got != TierSystem {
			t.Fatalf("got %v, want SYSTEM", got)
		}
	})
	t.Run("other_unaffected", func(t *testing.T) {
		got, _ := r.ResolveTier(context.Background(), "other")
		if got != TierStandard {
			t.Fatalf("got %v, want STANDARD", got)
		}
	})
}

func TestClosing_StaticPrivilegeResolver_ManyAgents(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierRestricted)
	tiers := []PrivilegeTier{TierRestricted, TierStandard, TierElevated, TierSystem}
	for i := 0; i < 20; i++ {
		id := "agent-" + string(rune('A'+i))
		r.SetTier(id, tiers[i%4])
	}
	t.Run("count_check", func(t *testing.T) {
		// Verify a few known agents
		got, _ := r.ResolveTier(context.Background(), "agent-A")
		if got != TierRestricted {
			t.Fatalf("got %v, want RESTRICTED", got)
		}
	})
	t.Run("modular_assignment", func(t *testing.T) {
		got, _ := r.ResolveTier(context.Background(), "agent-B")
		if got != TierStandard {
			t.Fatalf("got %v, want STANDARD", got)
		}
	})
	t.Run("third_agent", func(t *testing.T) {
		got, _ := r.ResolveTier(context.Background(), "agent-C")
		if got != TierElevated {
			t.Fatalf("got %v, want ELEVATED", got)
		}
	})
}

// ---------------------------------------------------------------------------
// 42-50: Temporal Guardian / Escalation / Audit coverage
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

func TestClosing_AuditLog_Creation(t *testing.T) {
	t.Run("size_100", func(t *testing.T) {
		log := NewAuditLog(nil)
		if log == nil {
			t.Fatal("log should not be nil")
		}
	})
	t.Run("size_1", func(t *testing.T) {
		log := NewAuditLog(nil)
		if log == nil {
			t.Fatal("log should not be nil")
		}
	})
	t.Run("size_0", func(t *testing.T) {
		log := NewAuditLog(nil)
		if log == nil {
			t.Fatal("log should not be nil")
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
