package guardian

import (
	"context"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
)

// PrivilegeTier defines the static capability level assigned to an agent.
// Analogous to CPU privilege rings (Ring 0-3), where lower tiers have fewer permissions.
type PrivilegeTier int

const (
	TierRestricted PrivilegeTier = 0 // Read-only, no side effects (Ring 3)
	TierStandard   PrivilegeTier = 1 // Business operations: email, tasks, docs (Ring 2)
	TierElevated   PrivilegeTier = 2 // Publish, credentials, compute budget (Ring 1)
	TierSystem     PrivilegeTier = 3 // Infrastructure, destroy, tunnel (Ring 0)
)

// String returns the human-readable tier name.
func (t PrivilegeTier) String() string {
	switch t {
	case TierRestricted:
		return "RESTRICTED"
	case TierStandard:
		return "STANDARD"
	case TierElevated:
		return "ELEVATED"
	case TierSystem:
		return "SYSTEM"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(t))
	}
}

// PrivilegeResolver looks up the assigned privilege tier for a principal.
type PrivilegeResolver interface {
	ResolveTier(ctx context.Context, principalID string) (PrivilegeTier, error)
}

// EffectTierMap maps effect type strings to the minimum privilege tier required.
// Effects not in the map default to TierStandard.
var EffectTierMap = map[string]PrivilegeTier{
	// TierRestricted — observation only, no effects
	// (no entries: restricted agents cannot invoke any effects)

	// TierStandard — business operations
	"SEND_EMAIL":        TierStandard,
	"SEND_CHAT_MESSAGE": TierStandard,
	"CREATE_TASK":       TierStandard,
	"COMMENT_TICKET":    TierStandard,
	"UPDATE_DOC":        TierStandard,
	"EXECUTE_TOOL":      TierStandard,

	// TierElevated — publish, credentials, compute
	"SOFTWARE_PUBLISH":     TierElevated,
	"CI_CREDENTIAL_ACCESS": TierElevated,
	"CLOUD_COMPUTE_BUDGET": TierElevated,
	"EXECUTE_PAYMENT":      TierElevated,
	"FILE_WRITE":           TierElevated,

	// TierSystem — infrastructure
	"INFRA_DESTROY":             TierSystem,
	"ENV_RECREATE":              TierSystem,
	"PROTECTED_INFRA_STRUCTURE": TierSystem,
	"TUNNEL_START":              TierSystem,
}

// RequiredTierForEffect returns the minimum privilege tier needed to execute the given effect type.
// Unknown effects default to TierStandard.
func RequiredTierForEffect(effectType string) PrivilegeTier {
	if tier, ok := EffectTierMap[effectType]; ok {
		return tier
	}
	return TierStandard
}

// EffectiveTier computes the effective privilege tier after applying behavioral trust downgrades.
// When an agent's behavioral trust drops into HOSTILE or SUSPECT tiers, their
// effective privilege is capped regardless of their assigned tier.
//
// Rules:
//   - HOSTILE trust (0-199)   → force TierRestricted
//   - SUSPECT trust (200-399) → cap at TierStandard
//   - All others              → assigned tier unchanged
func EffectiveTier(assigned PrivilegeTier, trustTier trust.TrustTier) PrivilegeTier {
	switch trustTier {
	case trust.TierHostile:
		return TierRestricted
	case trust.TierSuspect:
		if assigned > TierStandard {
			return TierStandard
		}
		return assigned
	default:
		return assigned
	}
}

// StaticPrivilegeResolver is a simple in-memory resolver for testing and configuration.
type StaticPrivilegeResolver struct {
	tiers       map[string]PrivilegeTier
	defaultTier PrivilegeTier
}

// NewStaticPrivilegeResolver creates a resolver with a default tier.
func NewStaticPrivilegeResolver(defaultTier PrivilegeTier) *StaticPrivilegeResolver {
	return &StaticPrivilegeResolver{
		tiers:       make(map[string]PrivilegeTier),
		defaultTier: defaultTier,
	}
}

// SetTier assigns a privilege tier to a principal.
func (r *StaticPrivilegeResolver) SetTier(principalID string, tier PrivilegeTier) {
	r.tiers[principalID] = tier
}

// ResolveTier returns the assigned tier for a principal, or the default tier.
func (r *StaticPrivilegeResolver) ResolveTier(_ context.Context, principalID string) (PrivilegeTier, error) {
	if tier, ok := r.tiers[principalID]; ok {
		return tier, nil
	}
	return r.defaultTier, nil
}
