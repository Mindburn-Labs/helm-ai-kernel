//go:build conformance

package identity

import (
	"net"
	"sync"
	"time"
)

// ── Conditional Access Policy Engine ──────────────────────────

// AccessDecision represents the outcome of a conditional access evaluation.
type AccessDecision string

const (
	AccessAllow           AccessDecision = "ALLOW"
	AccessDeny            AccessDecision = "DENY"
	AccessRequireMFA      AccessDecision = "REQUIRE_MFA"
	AccessRequireApproval AccessDecision = "REQUIRE_APPROVAL"
)

// AccessContext carries the contextual information for policy evaluation.
type AccessContext struct {
	PrincipalID   string
	PrincipalType PrincipalType
	SourceIP      string
	DeviceType    string // "managed", "unmanaged", "mobile"
	Location      string // ISO 3166-1 country code
	RequestTime   time.Time
	Resource      string // target resource or action
	RiskScore     float64
	TenantID      string
	SessionAge    time.Duration
}

// ConditionalPolicy defines context-aware access restrictions.
type ConditionalPolicy struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Priority   int              `json:"priority"` // Lower = higher priority
	Active     bool             `json:"active"`
	Conditions PolicyConditions `json:"conditions"`
	Decision   AccessDecision   `json:"decision"`
	TenantID   string           `json:"tenant_id,omitempty"` // Empty = global
}

// PolicyConditions defines the matching criteria for a policy.
type PolicyConditions struct {
	// Network restrictions
	AllowedIPRanges []string `json:"allowed_ip_ranges,omitempty"`
	DeniedIPRanges  []string `json:"denied_ip_ranges,omitempty"`

	// Device restrictions
	AllowedDeviceTypes []string `json:"allowed_device_types,omitempty"`

	// Location restrictions
	AllowedLocations []string `json:"allowed_locations,omitempty"`
	DeniedLocations  []string `json:"denied_locations,omitempty"`

	// Time restrictions
	AllowedTimeWindows []TimeWindow `json:"allowed_time_windows,omitempty"`

	// Principal restrictions
	PrincipalTypes []PrincipalType `json:"principal_types,omitempty"`

	// Risk threshold
	MaxRiskScore float64 `json:"max_risk_score,omitempty"`
}

// TimeWindow defines an allowed time range.
type TimeWindow struct {
	Weekdays  []time.Weekday `json:"weekdays"`
	StartHour int            `json:"start_hour"` // 0-23
	EndHour   int            `json:"end_hour"`   // 0-23
}

// ── Policy Engine ─────────────────────────────────────────────

// ConditionalAccessEngine evaluates access policies against context.
type ConditionalAccessEngine struct {
	mu       sync.RWMutex
	policies []*ConditionalPolicy
}

// NewConditionalAccessEngine creates a new engine.
func NewConditionalAccessEngine() *ConditionalAccessEngine {
	return &ConditionalAccessEngine{
		policies: make([]*ConditionalPolicy, 0),
	}
}

// AddPolicy registers a conditional access policy. Policies are sorted by priority.
func (e *ConditionalAccessEngine) AddPolicy(p *ConditionalPolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies = append(e.policies, p)
	// Sort by priority (lower = higher priority)
	for i := len(e.policies) - 1; i > 0; i-- {
		if e.policies[i].Priority < e.policies[i-1].Priority {
			e.policies[i], e.policies[i-1] = e.policies[i-1], e.policies[i]
		}
	}
}

// Evaluate checks all active policies against the given context.
// Returns the decision from the first matching policy, or ALLOW if none match.
func (e *ConditionalAccessEngine) Evaluate(ctx AccessContext) AccessDecision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, p := range e.policies {
		if !p.Active {
			continue
		}
		// Tenant scoping
		if p.TenantID != "" && p.TenantID != ctx.TenantID {
			continue
		}
		if e.matchesConditions(p.Conditions, ctx) {
			return p.Decision
		}
	}

	return AccessAllow // Default: allow if no policy matches
}

func (e *ConditionalAccessEngine) matchesConditions(cond PolicyConditions, ctx AccessContext) bool {
	// Check IP restrictions
	if len(cond.DeniedIPRanges) > 0 && matchIP(ctx.SourceIP, cond.DeniedIPRanges) {
		return true
	}
	if len(cond.AllowedIPRanges) > 0 && !matchIP(ctx.SourceIP, cond.AllowedIPRanges) {
		return true
	}

	// Check device type
	if len(cond.AllowedDeviceTypes) > 0 && !contains(cond.AllowedDeviceTypes, ctx.DeviceType) {
		return true
	}

	// Check location
	if len(cond.DeniedLocations) > 0 && contains(cond.DeniedLocations, ctx.Location) {
		return true
	}
	if len(cond.AllowedLocations) > 0 && !contains(cond.AllowedLocations, ctx.Location) {
		return true
	}

	// Check time windows
	if len(cond.AllowedTimeWindows) > 0 && !matchTimeWindow(ctx.RequestTime, cond.AllowedTimeWindows) {
		return true
	}

	// Check principal types
	if len(cond.PrincipalTypes) > 0 && !containsPT(cond.PrincipalTypes, ctx.PrincipalType) {
		return true
	}

	// Check risk score
	if cond.MaxRiskScore > 0 && ctx.RiskScore > cond.MaxRiskScore {
		return true
	}

	return false
}

// ── Helpers ───────────────────────────────────────────────────

func matchIP(ip string, ranges []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as exact IP
			if ip == cidr {
				return true
			}
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func matchTimeWindow(t time.Time, windows []TimeWindow) bool {
	for _, w := range windows {
		for _, wd := range w.Weekdays {
			if t.Weekday() == wd && t.Hour() >= w.StartHour && t.Hour() < w.EndHour {
				return true
			}
		}
	}
	return false
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

func containsPT(slice []PrincipalType, val PrincipalType) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
