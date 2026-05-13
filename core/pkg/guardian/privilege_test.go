package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

func TestPrivilegeTier_String(t *testing.T) {
	tests := []struct {
		tier PrivilegeTier
		want string
	}{
		{TierRestricted, "RESTRICTED"},
		{TierStandard, "STANDARD"},
		{TierElevated, "ELEVATED"},
		{TierSystem, "SYSTEM"},
		{PrivilegeTier(99), "UNKNOWN(99)"},
		{PrivilegeTier(-1), "UNKNOWN(-1)"},
	}
	for _, tt := range tests {
		got := tt.tier.String()
		if got != tt.want {
			t.Errorf("PrivilegeTier(%d).String() = %q, want %q", int(tt.tier), got, tt.want)
		}
	}
}

func TestRequiredTierForEffect(t *testing.T) {
	tests := []struct {
		effect string
		want   PrivilegeTier
	}{
		// Standard effects
		{"SEND_EMAIL", TierStandard},
		{"SEND_CHAT_MESSAGE", TierStandard},
		{"CREATE_TASK", TierStandard},
		{"COMMENT_TICKET", TierStandard},
		{"UPDATE_DOC", TierStandard},
		{"EXECUTE_TOOL", TierStandard},
		// Elevated effects
		{"SOFTWARE_PUBLISH", TierElevated},
		{"CI_CREDENTIAL_ACCESS", TierElevated},
		{"CLOUD_COMPUTE_BUDGET", TierElevated},
		{"EXECUTE_PAYMENT", TierElevated},
		{"FILE_WRITE", TierElevated},
		// System effects
		{"INFRA_DESTROY", TierSystem},
		{"ENV_RECREATE", TierSystem},
		{"PROTECTED_INFRA_STRUCTURE", TierSystem},
		{"TUNNEL_START", TierSystem},
		// Unknown defaults to Standard
		{"SOME_UNKNOWN_EFFECT", TierStandard},
		{"", TierStandard},
	}
	for _, tt := range tests {
		got := RequiredTierForEffect(tt.effect)
		if got != tt.want {
			t.Errorf("RequiredTierForEffect(%q) = %v, want %v", tt.effect, got, tt.want)
		}
	}
}

func TestEffectiveTier(t *testing.T) {
	tests := []struct {
		name     string
		assigned PrivilegeTier
		trust    trust.TrustTier
		want     PrivilegeTier
	}{
		// HOSTILE → always TierRestricted
		{"hostile_forces_restricted_from_system", TierSystem, trust.TierHostile, TierRestricted},
		{"hostile_forces_restricted_from_elevated", TierElevated, trust.TierHostile, TierRestricted},
		{"hostile_forces_restricted_from_standard", TierStandard, trust.TierHostile, TierRestricted},
		{"hostile_forces_restricted_from_restricted", TierRestricted, trust.TierHostile, TierRestricted},
		// SUSPECT → cap at Standard
		{"suspect_caps_system_to_standard", TierSystem, trust.TierSuspect, TierStandard},
		{"suspect_caps_elevated_to_standard", TierElevated, trust.TierSuspect, TierStandard},
		{"suspect_keeps_standard", TierStandard, trust.TierSuspect, TierStandard},
		{"suspect_keeps_restricted", TierRestricted, trust.TierSuspect, TierRestricted},
		// NEUTRAL → no change
		{"neutral_keeps_system", TierSystem, trust.TierNeutral, TierSystem},
		{"neutral_keeps_elevated", TierElevated, trust.TierNeutral, TierElevated},
		{"neutral_keeps_standard", TierStandard, trust.TierNeutral, TierStandard},
		{"neutral_keeps_restricted", TierRestricted, trust.TierNeutral, TierRestricted},
		// TRUSTED → no change
		{"trusted_keeps_system", TierSystem, trust.TierTrusted, TierSystem},
		{"trusted_keeps_elevated", TierElevated, trust.TierTrusted, TierElevated},
		// PRISTINE → no change
		{"pristine_keeps_system", TierSystem, trust.TierPristine, TierSystem},
		{"pristine_keeps_restricted", TierRestricted, trust.TierPristine, TierRestricted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EffectiveTier(tt.assigned, tt.trust)
			if got != tt.want {
				t.Errorf("EffectiveTier(%v, %v) = %v, want %v", tt.assigned, tt.trust, got, tt.want)
			}
		})
	}
}

func TestStaticPrivilegeResolver(t *testing.T) {
	ctx := context.Background()

	t.Run("default_tier_for_unknown_principal", func(t *testing.T) {
		r := NewStaticPrivilegeResolver(TierStandard)
		tier, err := r.ResolveTier(ctx, "unknown-agent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tier != TierStandard {
			t.Errorf("got tier %v, want %v", tier, TierStandard)
		}
	})

	t.Run("set_and_resolve_tier", func(t *testing.T) {
		r := NewStaticPrivilegeResolver(TierRestricted)
		r.SetTier("agent-admin", TierSystem)
		r.SetTier("agent-worker", TierStandard)

		tier, err := r.ResolveTier(ctx, "agent-admin")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tier != TierSystem {
			t.Errorf("got tier %v, want %v", tier, TierSystem)
		}

		tier, err = r.ResolveTier(ctx, "agent-worker")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tier != TierStandard {
			t.Errorf("got tier %v, want %v", tier, TierStandard)
		}

		// Unset principal falls back to default
		tier, err = r.ResolveTier(ctx, "agent-unknown")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tier != TierRestricted {
			t.Errorf("got tier %v for unknown principal, want default %v", tier, TierRestricted)
		}
	})

	t.Run("override_tier", func(t *testing.T) {
		r := NewStaticPrivilegeResolver(TierRestricted)
		r.SetTier("agent-x", TierStandard)
		r.SetTier("agent-x", TierElevated) // override

		tier, err := r.ResolveTier(ctx, "agent-x")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tier != TierElevated {
			t.Errorf("got tier %v after override, want %v", tier, TierElevated)
		}
	})
}

func TestEffectTierMap_Completeness(t *testing.T) {
	// Verify ordering invariant: Standard < Elevated < System
	// Collect all effects by tier
	standardEffects := make([]string, 0)
	elevatedEffects := make([]string, 0)
	systemEffects := make([]string, 0)

	for effect, tier := range EffectTierMap {
		switch tier {
		case TierStandard:
			standardEffects = append(standardEffects, effect)
		case TierElevated:
			elevatedEffects = append(elevatedEffects, effect)
		case TierSystem:
			systemEffects = append(systemEffects, effect)
		case TierRestricted:
			t.Errorf("EffectTierMap should not contain TierRestricted entries (restricted agents have no effects), but found %q", effect)
		default:
			t.Errorf("EffectTierMap contains unknown tier %v for effect %q", tier, effect)
		}
	}

	if len(standardEffects) == 0 {
		t.Error("EffectTierMap has no Standard-tier effects")
	}
	if len(elevatedEffects) == 0 {
		t.Error("EffectTierMap has no Elevated-tier effects")
	}
	if len(systemEffects) == 0 {
		t.Error("EffectTierMap has no System-tier effects")
	}

	// Verify tier ordering: Standard(1) < Elevated(2) < System(3)
	if TierStandard >= TierElevated {
		t.Errorf("TierStandard(%d) should be less than TierElevated(%d)", TierStandard, TierElevated)
	}
	if TierElevated >= TierSystem {
		t.Errorf("TierElevated(%d) should be less than TierSystem(%d)", TierElevated, TierSystem)
	}

	// Verify all mapped effects require at least TierStandard
	for effect, tier := range EffectTierMap {
		if tier < TierStandard {
			t.Errorf("effect %q mapped to tier %v which is below TierStandard", effect, tier)
		}
	}
}
