// Package governance — Edge governance and fallback mode.
//
// Per HELM 2030 Spec §6.1.13:
//
//	HELM AI Kernel MUST include an edge governance assistant, fallback
//	governance mode, and offline explanation capabilities.
//
// Resolves: GAP-A25.
package governance

import "time"

// EdgeGovernanceMode defines the operating mode for edge/constrained environments.
type EdgeGovernanceMode string

const (
	// EdgeFull uses the complete PDP with all policies.
	EdgeFull EdgeGovernanceMode = "FULL"
	// EdgeReduced uses a cached subset of policies.
	EdgeReduced EdgeGovernanceMode = "REDUCED"
	// EdgeFallback uses hardcoded deny-by-default with minimal allow rules.
	EdgeFallback EdgeGovernanceMode = "FALLBACK"
	// EdgeOffline operates without any network connectivity.
	EdgeOffline EdgeGovernanceMode = "OFFLINE"
)

// EdgeConfig configures governance for edge/constrained deployments.
type EdgeConfig struct {
	Mode             EdgeGovernanceMode `json:"mode"`
	MaxLatencyMs     int                `json:"max_latency_ms"`
	CacheTTL         time.Duration      `json:"cache_ttl"`
	PolicySubset     []string           `json:"policy_subset,omitempty"`   // which policies to enforce
	AllowedEffects   []string           `json:"allowed_effects,omitempty"` // restrict to these effect types
	SyncInterval     time.Duration      `json:"sync_interval,omitempty"`   // how often to sync with central
	OfflineQueueSize int                `json:"offline_queue_size"`        // max pending actions to queue
}

// FallbackPolicy defines behavior when full PDP is unavailable.
type FallbackPolicy struct {
	PolicyID    string           `json:"policy_id"`
	Strategy    FallbackStrategy `json:"strategy"`
	AllowRules  []FallbackRule   `json:"allow_rules,omitempty"`
	MaxActions  int              `json:"max_actions_before_sync"` // max actions before requiring sync
	GracePeriod time.Duration    `json:"grace_period"`
}

// FallbackStrategy defines the fallback behavior.
type FallbackStrategy string

const (
	// FallbackDenyAll denies all actions when PDP unavailable.
	FallbackDenyAll FallbackStrategy = "DENY_ALL"
	// FallbackCachedAllow uses last known good policy cache.
	FallbackCachedAllow FallbackStrategy = "CACHED_ALLOW"
	// FallbackRingFence allows only low-risk pre-approved actions.
	FallbackRingFence FallbackStrategy = "RING_FENCE"
)

// FallbackRule is a pre-approved action for ring-fence mode.
type FallbackRule struct {
	EffectType string `json:"effect_type"`
	MaxRisk    string `json:"max_risk"` // "LOW", "MEDIUM"
	RequireLog bool   `json:"require_log"`
}

// EdgeAssistant is a lightweight PDP adapter for edge/air-gapped scenarios.
type EdgeAssistant struct {
	Config   EdgeConfig     `json:"config"`
	Fallback FallbackPolicy `json:"fallback"`
}

// ShouldAllow determines if an action should be allowed in edge mode.
// Fail-closed: returns false on any ambiguity.
func (e *EdgeAssistant) ShouldAllow(effectType, riskLevel string) bool {
	switch e.Config.Mode {
	case EdgeFull:
		return true // defer to full PDP
	case EdgeReduced:
		for _, allowed := range e.Config.AllowedEffects {
			if allowed == effectType {
				return true
			}
		}
		return false
	case EdgeFallback, EdgeOffline:
		if e.Fallback.Strategy == FallbackDenyAll {
			return false
		}
		if e.Fallback.Strategy == FallbackRingFence {
			for _, rule := range e.Fallback.AllowRules {
				if rule.EffectType == effectType && isRiskAtOrBelow(riskLevel, rule.MaxRisk) {
					return true
				}
			}
			return false
		}
		// CACHED_ALLOW: check allowed effects
		for _, allowed := range e.Config.AllowedEffects {
			if allowed == effectType {
				return true
			}
		}
		return false
	default:
		return false // fail-closed
	}
}

func isRiskAtOrBelow(actual, max string) bool {
	order := map[string]int{"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
	a, aOK := order[actual]
	m, mOK := order[max]
	if !aOK || !mOK {
		return false // unknown risk = deny
	}
	return a <= m
}
