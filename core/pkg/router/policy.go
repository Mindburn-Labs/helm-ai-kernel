// Package router is the kernel-owned, contract-aware model route engine.
//
// The router turns a route request into a fail-closed verdict (ALLOW / DENY /
// ESCALATE) against a modelcatalog.Catalog. It is the gate that makes
// multi-provider routing explicit and auditable before any spend is claimed:
//
//   - a forbidden provider or model is denied before dispatch;
//   - a stale or invalid provider terms profile blocks the route before
//     dispatch;
//   - an unhealthy provider account denies, and a degraded one escalates;
//   - region and retention participate in route scoring, not just cost/latency.
//
// The router never sees credentials. It selects a provider account and emits a
// RoutePolicyHash that downstream spend-authority objects (RouteQuote,
// BudgetVerdictReceipt) bind to; the gateway resolves the account's opaque
// credential reference at dispatch time, outside agent reach.
package router

import (
	"errors"
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// RouteMode is the optimization/pinning strategy a route policy applies.
type RouteMode string

const (
	// RouteModePinned forces a single provider+model; any deviation is denied.
	RouteModePinned RouteMode = "pinned"
	// RouteModeCostFirst prefers the cheapest compliant candidate.
	RouteModeCostFirst RouteMode = "cost_first"
	// RouteModeLatencyFirst prefers the lowest-latency compliant candidate.
	RouteModeLatencyFirst RouteMode = "latency_first"
	// RouteModeQualityFirst prefers the highest-quality compliant candidate.
	RouteModeQualityFirst RouteMode = "quality_first"
	// RouteModeBalanced blends cost, latency, quality, region, and retention.
	RouteModeBalanced RouteMode = "balanced"
	// RouteModeComplianceFirst prefers the candidate with the strongest
	// compliance posture (shortest retention, matching region/jurisdiction).
	RouteModeComplianceFirst RouteMode = "compliance_first"
	// RouteModeRegionPinned requires the candidate to serve a pinned region.
	RouteModeRegionPinned RouteMode = "region_pinned"
	// RouteModeProviderPinned forces a single provider, any of its models.
	RouteModeProviderPinned RouteMode = "provider_pinned"
	// RouteModeModelPinned forces a single model across any provider that serves it.
	RouteModeModelPinned RouteMode = "model_pinned"
)

// RouteModes returns the full normative route-mode vocabulary.
func RouteModes() []RouteMode {
	return []RouteMode{
		RouteModePinned,
		RouteModeCostFirst,
		RouteModeLatencyFirst,
		RouteModeQualityFirst,
		RouteModeBalanced,
		RouteModeComplianceFirst,
		RouteModeRegionPinned,
		RouteModeProviderPinned,
		RouteModeModelPinned,
	}
}

func (m RouteMode) valid() bool {
	for _, known := range RouteModes() {
		if m == known {
			return true
		}
	}
	return false
}

// ScoreWeights are the per-dimension weights used by RouteModeBalanced. Each
// weight scales a normalized 0..1 sub-score; higher total score wins. Zero
// values fall back to BalancedDefaultWeights so an unset policy is still usable.
type ScoreWeights struct {
	Cost      float64 `json:"cost"`
	Latency   float64 `json:"latency"`
	Quality   float64 `json:"quality"`
	Region    float64 `json:"region"`
	Retention float64 `json:"retention"`
}

// BalancedDefaultWeights is the default blend for RouteModeBalanced.
func BalancedDefaultWeights() ScoreWeights {
	return ScoreWeights{Cost: 0.3, Latency: 0.2, Quality: 0.2, Region: 0.15, Retention: 0.15}
}

func (w ScoreWeights) orDefault() ScoreWeights {
	if w == (ScoreWeights{}) {
		return BalancedDefaultWeights()
	}
	return w
}

// RoutePolicy is the kernel-owned, hashable description of how a route must be
// chosen. Its canonical hash is the RoutePolicyHash that RouteQuote and
// BudgetVerdictReceipt bind to, so a dispatch can be audited back to the exact
// policy that authorized it.
type RoutePolicy struct {
	ID       string    `json:"id"`
	TenantID string    `json:"tenant_id,omitempty"`
	Mode     RouteMode `json:"mode"`

	// PinnedProviderID / PinnedModelID constrain the candidate set for the
	// pinned, provider_pinned, and model_pinned modes.
	PinnedProviderID string `json:"pinned_provider_id,omitempty"`
	PinnedModelID    string `json:"pinned_model_id,omitempty"`

	// RequiredRegion constrains region_pinned and contributes to scoring/
	// compliance. Empty means "no region constraint".
	RequiredRegion string `json:"required_region,omitempty"`

	// MaxDataRetentionDays denies a candidate whose terms profile retains data
	// longer than this. Zero means "no retention ceiling".
	MaxDataRetentionDays int `json:"max_data_retention_days,omitempty"`

	// MaxRiskTier is the highest provider risk tier allowed (LOW<MEDIUM<HIGH<CRITICAL).
	// Empty means "no risk ceiling".
	MaxRiskTier string `json:"max_risk_tier,omitempty"`

	// Weights tunes RouteModeBalanced. Ignored by single-dimension modes.
	Weights ScoreWeights `json:"weights,omitempty"`
}

// Validate ensures the policy is well-formed and that pinning modes carry the
// pin they require. A malformed policy can authorize nothing.
func (p *RoutePolicy) Validate() error {
	if p == nil {
		return errors.New("route_policy: policy is nil")
	}
	if p.ID == "" {
		return errors.New("route_policy: id is required")
	}
	if !p.Mode.valid() {
		return errors.New("route_policy: unknown mode " + string(p.Mode))
	}
	switch p.Mode {
	case RouteModePinned:
		if p.PinnedProviderID == "" || p.PinnedModelID == "" {
			return errors.New("route_policy: pinned mode requires pinned_provider_id and pinned_model_id")
		}
	case RouteModeProviderPinned:
		if p.PinnedProviderID == "" {
			return errors.New("route_policy: provider_pinned mode requires pinned_provider_id")
		}
	case RouteModeModelPinned:
		if p.PinnedModelID == "" {
			return errors.New("route_policy: model_pinned mode requires pinned_model_id")
		}
	case RouteModeRegionPinned:
		if p.RequiredRegion == "" {
			return errors.New("route_policy: region_pinned mode requires required_region")
		}
	}
	if p.MaxDataRetentionDays < 0 {
		return errors.New("route_policy: max_data_retention_days cannot be negative")
	}
	return nil
}

// Hash returns the canonical "sha256:"-prefixed RoutePolicyHash. Weights are
// normalized to the effective blend so two policies that resolve to the same
// behavior hash identically.
func (p *RoutePolicy) Hash() string {
	h, err := canonicalize.CanonicalHash(struct {
		ID                   string       `json:"id"`
		TenantID             string       `json:"tenant_id,omitempty"`
		Mode                 RouteMode    `json:"mode"`
		PinnedProviderID     string       `json:"pinned_provider_id,omitempty"`
		PinnedModelID        string       `json:"pinned_model_id,omitempty"`
		RequiredRegion       string       `json:"required_region,omitempty"`
		MaxDataRetentionDays int          `json:"max_data_retention_days,omitempty"`
		MaxRiskTier          string       `json:"max_risk_tier,omitempty"`
		Weights              ScoreWeights `json:"weights"`
	}{p.ID, p.TenantID, p.Mode, p.PinnedProviderID, p.PinnedModelID, p.RequiredRegion, p.MaxDataRetentionDays, p.MaxRiskTier, p.effectiveWeights()})
	if err != nil {
		return ""
	}
	return "sha256:" + h
}

func (p *RoutePolicy) effectiveWeights() ScoreWeights {
	if p.Mode == RouteModeBalanced {
		return p.Weights.orDefault()
	}
	return p.Weights
}

// riskTierRank ranks provider risk tiers for ceiling comparisons. Unknown tiers
// rank highest (most restrictive to admit) so an unrecognized tier fails closed.
func riskTierRank(tier string) int {
	switch tier {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	default:
		return 99
	}
}

func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

func sortedRegions(regions []string) []string {
	out := append([]string(nil), regions...)
	sort.Strings(out)
	return out
}
