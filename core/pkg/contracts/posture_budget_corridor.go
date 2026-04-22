package contracts

import "time"

// ──────────────────────────────────────────────────────────────
// Posture — execution posture enum (session/workflow level)
// ──────────────────────────────────────────────────────────────

// Posture defines the execution mode for a session or workflow.
// Two-level model: Deployment Profile (HUDF) × Posture.
// Posture controls what classes of effects are permitted.
type Posture string

const (
	// PostureObserve is read-only. No ChangeSet commits, no secret access
	// except public configuration, connector reads only if explicitly permitted.
	PostureObserve Posture = "OBSERVE"

	// PostureDraft allows creating/editing ChangeSets, running validators
	// and simulations, requesting approvals. No external side effects.
	// Tools run only in dry-run/sandbox-only mode with egress denied.
	PostureDraft Posture = "DRAFT"

	// PostureTransact allows bounded effects (E1-E3) within budgets.
	// Requires pinned connector contracts, corridor allowlists, receipts on.
	// Approval required for escalations beyond posture caps.
	PostureTransact Posture = "TRANSACT"

	// PostureSovereign allows approving exceptions, modifying P0 ceilings,
	// irreversible effects (E4), rotating sensitive secrets, changing core
	// governance. Always produces high-grade evidence.
	PostureSovereign Posture = "SOVEREIGN"
)

// AllPostures returns the ordered list of postures from least to most privileged.
func AllPostures() []Posture {
	return []Posture{PostureObserve, PostureDraft, PostureTransact, PostureSovereign}
}

// CanEscalateTo returns true if the current posture can escalate to the target.
func (p Posture) CanEscalateTo(target Posture) bool {
	return postureRank(p) < postureRank(target)
}

func postureRank(p Posture) int {
	switch p {
	case PostureObserve:
		return 0
	case PostureDraft:
		return 1
	case PostureTransact:
		return 2
	case PostureSovereign:
		return 3
	default:
		return -1
	}
}

// ──────────────────────────────────────────────────────────────
// Budget — execution budget envelope
// ──────────────────────────────────────────────────────────────

// Budget is the resource/cost envelope for an execution context.
// Budgets are immutable once bound to an execution; overruns fail-close.
type Budget struct {
	// ID uniquely identifies this budget allocation.
	ID string `json:"id"`

	// MaxTokens is the LLM token ceiling for this execution.
	MaxTokens int64 `json:"max_tokens"`

	// MaxCostCents is the monetary ceiling in cents (USD).
	MaxCostCents int64 `json:"max_cost_cents"`

	// MaxEffects is the ceiling on total effects (across all classes).
	MaxEffects int64 `json:"max_effects"`

	// MaxDuration is the wall-clock time ceiling.
	MaxDuration time.Duration `json:"max_duration"`

	// PerEffectClassLimits constrains individual effect classes.
	// Key is the effect class string (E0-E4).
	PerEffectClassLimits map[string]int64 `json:"per_effect_class_limits,omitempty"`

	// ConsumedTokens tracks current usage (mutable during execution).
	ConsumedTokens int64 `json:"consumed_tokens"`

	// ConsumedCostCents tracks current cost (mutable during execution).
	ConsumedCostCents int64 `json:"consumed_cost_cents"`

	// ConsumedEffects tracks current effect count (mutable during execution).
	ConsumedEffects int64 `json:"consumed_effects"`
}

// Exhausted returns true if any budget dimension has been exceeded.
func (b *Budget) Exhausted() bool {
	if b.MaxTokens > 0 && b.ConsumedTokens >= b.MaxTokens {
		return true
	}
	if b.MaxCostCents > 0 && b.ConsumedCostCents >= b.MaxCostCents {
		return true
	}
	if b.MaxEffects > 0 && b.ConsumedEffects >= b.MaxEffects {
		return true
	}
	return false
}

// RemainingTokens returns the number of tokens remaining, or 0 if exhausted.
func (b *Budget) RemainingTokens() int64 {
	if b.MaxTokens <= 0 {
		return 0
	}
	remaining := b.MaxTokens - b.ConsumedTokens
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ──────────────────────────────────────────────────────────────
// CorridorPolicy — network boundary authority
// ──────────────────────────────────────────────────────────────

// CorridorPolicy defines the network boundary authority for an execution.
// Corridors are the ONLY mechanism for external network access.
// SSRF protection is a property of corridor enforcement, not a separate layer.
type CorridorPolicy struct {
	// ID uniquely identifies this corridor.
	ID string `json:"id"`

	// Name is a human-readable corridor name (e.g., "stripe-api-v1").
	Name string `json:"name"`

	// AllowedHosts is the explicit URL allowlist. Only these hosts may be contacted.
	// Wildcard subdomains (*.example.com) are NOT permitted — every host is explicit.
	AllowedHosts []string `json:"allowed_hosts"`

	// BlockedIPRanges blocks specific IP ranges (RFC 1918, link-local, loopback, metadata).
	// Default: all private ranges + cloud provider metadata endpoints.
	BlockedIPRanges []string `json:"blocked_ip_ranges"`

	// DNSResolutionPolicy controls DNS behavior.
	DNSResolutionPolicy DNSPolicy `json:"dns_resolution_policy"`

	// RedirectPolicy controls HTTP redirect following.
	RedirectPolicy RedirectPolicy `json:"redirect_policy"`

	// RequestShaping controls request-level constraints.
	RequestShaping RequestShaping `json:"request_shaping"`

	// MetadataEndpointBlock blocks cloud provider metadata endpoints
	// (169.254.169.254, fd00:ec2::254, metadata.google.internal, etc).
	MetadataEndpointBlock bool `json:"metadata_endpoint_block"`

	// RequiredPosture is the minimum posture required to use this corridor.
	RequiredPosture Posture `json:"required_posture"`
}

// DNSPolicy controls DNS resolution behavior within a corridor.
type DNSPolicy struct {
	// PinResolution requires DNS results to be pinned and verified.
	PinResolution bool `json:"pin_resolution"`

	// MaxTTLSeconds is the maximum DNS cache TTL.
	MaxTTLSeconds int `json:"max_ttl_seconds"`

	// RejectPrivateIPs rejects DNS results that resolve to private IP ranges.
	RejectPrivateIPs bool `json:"reject_private_ips"`
}

// RedirectPolicy controls HTTP redirect behavior within a corridor.
type RedirectPolicy struct {
	// MaxRedirects is the maximum number of redirects to follow (0 = none).
	MaxRedirects int `json:"max_redirects"`

	// AllowCrossOrigin allows redirects to different origins.
	AllowCrossOrigin bool `json:"allow_cross_origin"`

	// AllowHTTPDowngrade allows redirects from HTTPS to HTTP.
	AllowHTTPDowngrade bool `json:"allow_http_downgrade"`
}

// RequestShaping controls request-level constraints within a corridor.
type RequestShaping struct {
	// MaxRequestBytes is the maximum request body size.
	MaxRequestBytes int64 `json:"max_request_bytes"`

	// MaxResponseBytes is the maximum response body size.
	MaxResponseBytes int64 `json:"max_response_bytes"`

	// TimeoutSeconds is the per-request timeout.
	TimeoutSeconds int `json:"timeout_seconds"`

	// MaxRetries is the maximum number of retries.
	MaxRetries int `json:"max_retries"`

	// RequiredHeaders are headers that must be present on every request.
	RequiredHeaders map[string]string `json:"required_headers,omitempty"`

	// ForbiddenHeaders are headers that must NOT be present.
	ForbiddenHeaders []string `json:"forbidden_headers,omitempty"`
}
