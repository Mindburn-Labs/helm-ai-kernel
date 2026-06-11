package boundary

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// PolicyVersion is the current schema version.
const PolicyVersion = "1.0.0"

// Enforcement modes
const (
	ModeEnforce  = "enforce"
	ModeAudit    = "audit"
	ModeDisabled = "disabled"
)

// Fail actions
const (
	ActionDeny       = "deny"
	ActionQuarantine = "quarantine"
	ActionAlert      = "alert"
)

// Perimeter errors.
var (
	ErrAccessDenied      = errors.New("access denied by perimeter policy")
	ErrNetworkDenied     = errors.New("network access denied")
	ErrToolDenied        = errors.New("tool execution denied")
	ErrDataDenied        = errors.New("data access denied")
	ErrTemporalDenied    = errors.New("operation denied by temporal constraints")
	ErrInvalidPolicy     = errors.New("invalid perimeter policy")
	ErrAttestationNeeded = errors.New("tool attestation required")
)

// PerimeterPolicy defines autonomy perimeter constraints.
type PerimeterPolicy struct {
	Version     string      `json:"version"`
	PolicyID    string      `json:"policy_id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Constraints Constraints `json:"constraints"`
	Enforcement Enforcement `json:"enforcement"`
	Metadata    Metadata    `json:"metadata,omitempty"`
	LastUpdated time.Time   `json:"-"`
}

// Constraints grouped by domain.
type Constraints struct {
	Network  *NetworkConstraints  `json:"network,omitempty"`
	Tools    *ToolConstraints     `json:"tools,omitempty"`
	Data     *DataConstraints     `json:"data,omitempty"`
	Temporal *TemporalConstraints `json:"temporal,omitempty"`
}

// NetworkConstraints defines egress rules.
type NetworkConstraints struct {
	AllowedHosts      []string `json:"allowed_hosts,omitempty"`
	DeniedHosts       []string `json:"denied_hosts,omitempty"`
	AllowedPorts      []int    `json:"allowed_ports,omitempty"`
	MaxRequestsPerMin int      `json:"max_requests_per_minute,omitempty"`
	MaxBandwidthBytes int64    `json:"max_bandwidth_bytes,omitempty"`
	RequireTLS        bool     `json:"require_tls"`
}

// ToolConstraints defines tool execution rules.
type ToolConstraints struct {
	AllowedTools       []string `json:"allowed_tools,omitempty"`
	DeniedTools        []string `json:"denied_tools,omitempty"`
	RequireAttestation bool     `json:"require_attestation"`
	MaxConcurrentCalls int      `json:"max_concurrent_calls,omitempty"`
	TimeoutSeconds     int      `json:"timeout_seconds,omitempty"`
}

// DataConstraints defines data flow rules.
type DataConstraints struct {
	AllowedClasses    []string `json:"allowed_data_classes,omitempty"`
	DeniedClasses     []string `json:"denied_data_classes,omitempty"`
	MaxContextTokens  int      `json:"max_context_tokens,omitempty"`
	MaxResponseTokens int      `json:"max_response_tokens,omitempty"`
	RedactPatterns    []string `json:"redact_patterns,omitempty"`
}

// TemporalConstraints defines time-based rules.
type TemporalConstraints struct {
	AllowedHours        *TimeRange `json:"allowed_hours,omitempty"`
	AllowedDays         []string   `json:"allowed_days,omitempty"`
	MaxExecutionSeconds int        `json:"max_execution_seconds,omitempty"`
	CooldownSeconds     int        `json:"cooldown_seconds,omitempty"`
}

// TimeRange defines a time window.
type TimeRange struct {
	Start    string `json:"start"`
	End      string `json:"end"`
	Timezone string `json:"timezone"`
}

// Enforcement defines policy enforcement settings.
type Enforcement struct {
	Mode       string `json:"mode"`
	FailAction string `json:"fail_action"`
	AuditAll   bool   `json:"audit_all"`
}

type Metadata struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy string    `json:"created_by,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
}

// ViolationHandler is a callback function for perimeter violations.
type ViolationHandler func(ctx context.Context, err error, reason string, policyID string)

// PerimeterEnforcer enforces the policy.
type PerimeterEnforcer struct {
	mu           sync.RWMutex
	policy       *PerimeterPolicy
	compiledHost []*regexp.Regexp // Compiled regex for wildcard hosts
	onViolation  ViolationHandler
}

// SetViolationHandler sets the callback for policy violations.
func (pe *PerimeterEnforcer) SetViolationHandler(handler ViolationHandler) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.onViolation = handler
}

// NewPerimeterEnforcer creates a new enforcer.
func NewPerimeterEnforcer(policy *PerimeterPolicy) (*PerimeterEnforcer, error) {
	pe := &PerimeterEnforcer{}
	if policy != nil {
		if err := pe.LoadPolicy(policy); err != nil {
			return nil, err
		}
	}
	return pe, nil
}

// LoadPolicy updates the active policy.
func (pe *PerimeterEnforcer) LoadPolicy(policy *PerimeterPolicy) error {
	if policy.Version != PolicyVersion {
		return fmt.Errorf("unsupported version: %s", policy.Version)
	}
	if err := rejectUnsupportedConstraints(policy); err != nil {
		return err
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()

	pe.policy = policy
	pe.compiledHost = nil

	// Compile allowed host patterns
	if policy.Constraints.Network != nil {
		for _, host := range policy.Constraints.Network.AllowedHosts {
			// Convert glob-like pattern to regex (simple implementation)
			// e.g. *.example.com -> ^.*\.example\.com$
			// example.com -> ^example\.com$
			pattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(host), "\\*", ".*") + "$"
			re, err := regexp.Compile(pattern)
			if err == nil {
				pe.compiledHost = append(pe.compiledHost, re)
			}
		}
	}

	return nil
}

func rejectUnsupportedConstraints(policy *PerimeterPolicy) error {
	if policy == nil {
		return nil
	}
	nc := policy.Constraints.Network
	if nc != nil {
		if nc.MaxRequestsPerMin != 0 {
			return unsupportedConstraint("network.max_requests_per_minute")
		}
		if nc.MaxBandwidthBytes != 0 {
			return unsupportedConstraint("network.max_bandwidth_bytes")
		}
	}
	tc := policy.Constraints.Tools
	if tc != nil {
		if tc.MaxConcurrentCalls != 0 {
			return unsupportedConstraint("tools.max_concurrent_calls")
		}
		if tc.TimeoutSeconds != 0 {
			return unsupportedConstraint("tools.timeout_seconds")
		}
	}
	dc := policy.Constraints.Data
	if dc != nil {
		if dc.MaxContextTokens != 0 {
			return unsupportedConstraint("data.max_context_tokens")
		}
		if dc.MaxResponseTokens != 0 {
			return unsupportedConstraint("data.max_response_tokens")
		}
		if len(dc.RedactPatterns) != 0 {
			return unsupportedConstraint("data.redact_patterns")
		}
	}
	if policy.Constraints.Temporal != nil {
		return unsupportedConstraint("temporal")
	}
	return nil
}

func unsupportedConstraint(field string) error {
	return fmt.Errorf("%w: unsupported perimeter policy field %s cannot be accepted without enforcement", ErrInvalidPolicy, field)
}

// CheckNetwork verifies network access.
//
//nolint:gocognit // network constraint checking requires comprehensive checks
func (pe *PerimeterEnforcer) CheckNetwork(ctx context.Context, targetURL string) error {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	if pe.policy == nil || pe.policy.Enforcement.Mode == ModeDisabled {
		return nil
	}

	nc := pe.policy.Constraints.Network
	if nc == nil {
		return nil
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}

	host := u.Hostname()
	port := u.Port()

	// 1. Check TLS
	if nc.RequireTLS && u.Scheme != "https" {
		return pe.enforce(ctx, ErrNetworkDenied, "TLS required")
	}

	// 2. Check explicitly denied hosts
	for _, denied := range nc.DeniedHosts {
		if matchHost(denied, host) {
			return pe.enforce(ctx, ErrNetworkDenied, "host explicitly denied: "+host)
		}
	}

	// 3. Check allowed hosts (allowlist model if list is present)
	if len(nc.AllowedHosts) > 0 {
		allowed := false
		for _, re := range pe.compiledHost {
			if re.MatchString(host) {
				allowed = true
				break
			}
		}
		if !allowed {
			return pe.enforce(ctx, ErrNetworkDenied, "host not in allowlist: "+host)
		}
	}

	// 4. Check ports
	if len(nc.AllowedPorts) > 0 && port != "" {
		portInt := 0
		_, _ = fmt.Sscanf(port, "%d", &portInt) //nolint:errcheck // best-effort port parsing
		allowed := false
		for _, p := range nc.AllowedPorts {
			if p == portInt {
				allowed = true
				break
			}
		}
		if !allowed {
			return pe.enforce(ctx, ErrNetworkDenied, "port not allowed: "+port)
		}
	}

	return nil
}

// CheckTool verifies tool execution.
func (pe *PerimeterEnforcer) CheckTool(ctx context.Context, toolID string, attested bool) error {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	if pe.policy == nil || pe.policy.Enforcement.Mode == ModeDisabled {
		return nil
	}

	tc := pe.policy.Constraints.Tools
	if tc == nil {
		return nil
	}

	// 1. Check attestation
	if tc.RequireAttestation && !attested {
		return pe.enforce(ctx, ErrAttestationNeeded, "tool not attested: "+toolID)
	}

	// 2. Check denied tools
	for _, denied := range tc.DeniedTools {
		if denied == toolID {
			return pe.enforce(ctx, ErrToolDenied, "tool explicitly denied: "+toolID)
		}
	}

	// 3. Check allowed tools
	if len(tc.AllowedTools) > 0 {
		allowed := false
		for _, allowedID := range tc.AllowedTools {
			if allowedID == toolID {
				allowed = true
				break
			}
		}
		if !allowed {
			return pe.enforce(ctx, ErrToolDenied, "tool not in allowlist: "+toolID)
		}
	}

	return nil
}

// CheckData verifies data classification.
func (pe *PerimeterEnforcer) CheckData(ctx context.Context, dataClass string) error {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	if pe.policy == nil || pe.policy.Enforcement.Mode == ModeDisabled {
		return nil
	}

	dc := pe.policy.Constraints.Data
	if dc == nil {
		return nil
	}

	// 1. Check denied classes
	for _, denied := range dc.DeniedClasses {
		if denied == dataClass {
			return pe.enforce(ctx, ErrDataDenied, "data class denied: "+dataClass)
		}
	}

	// 2. Check allowed classes
	if len(dc.AllowedClasses) > 0 {
		allowed := false
		for _, allowedClass := range dc.AllowedClasses {
			if allowedClass == dataClass {
				allowed = true
				break
			}
		}
		if !allowed {
			return pe.enforce(ctx, ErrDataDenied, "data class not allowed: "+dataClass)
		}
	}

	return nil
}

// CheckTemporal removed - was dead code

func (pe *PerimeterEnforcer) enforce(ctx context.Context, err error, reason string) error {
	pe.mu.RLock()
	handler := pe.onViolation
	policyID := ""
	mode := ModeEnforce
	if pe.policy != nil {
		policyID = pe.policy.PolicyID
		mode = pe.policy.Enforcement.Mode
	}
	pe.mu.RUnlock()

	if handler != nil {
		// Non-blocking invocation for telemetry / audit log writes with panic recovery
		go func() {
			defer func() {
				_ = recover() // Isolate panic to protect main kernel thread
			}()
			handler(ctx, err, reason, policyID)
		}()
	}

	if mode == ModeAudit {
		return nil
	}
	return fmt.Errorf("%w: %s", err, reason)
}

// Helper to check wildcard host matches (simple implementation)
func matchHost(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		domain := pattern[2:]
		return strings.HasSuffix(host, domain) || host == domain
	}
	return pattern == host
}
