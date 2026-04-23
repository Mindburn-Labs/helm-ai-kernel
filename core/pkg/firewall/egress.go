package firewall

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// EgressPolicy defines the network egress rules for data transmission.
// It operates on a fail-closed model: any destination not explicitly
// allowed is denied with DATA_EGRESS_BLOCKED.
//
// Design invariants:
//   - Empty AllowedDomains + empty AllowedCIDRs = deny-all (fail-closed)
//   - DeniedDomains takes precedence over AllowedDomains
//   - AllowedProtocols restricts which protocols may be used
//   - MaxPayloadBytes = 0 means no payload size limit
type EgressPolicy struct {
	AllowedDomains   []string `json:"allowed_domains"`   // Exact domain matches
	DeniedDomains    []string `json:"denied_domains"`    // Explicit denylist (takes precedence)
	AllowedCIDRs     []string `json:"allowed_cidrs"`     // CIDR blocks for IP-based access
	AllowedProtocols []string `json:"allowed_protocols"` // e.g., ["https", "grpc"]
	MaxPayloadBytes  int64    `json:"max_payload_bytes"` // 0 = unlimited
}

// EgressDecision captures the result of an egress check.
type EgressDecision struct {
	Allowed      bool      `json:"allowed"`
	ReasonCode   string    `json:"reason_code"`
	Destination  string    `json:"destination"`
	PayloadBytes int64     `json:"payload_bytes"`
	CheckedAt    time.Time `json:"checked_at"`
}

// EgressChecker enforces egress policy on outbound data transmissions.
type EgressChecker struct {
	mu     sync.RWMutex
	policy *EgressPolicy
	stats  egressStats
	clock  func() time.Time

	// Pre-computed for fast lookups
	allowedSet  map[string]bool
	deniedSet   map[string]bool
	protoSet    map[string]bool
	parsedCIDRs []*net.IPNet
}

type egressStats struct {
	totalChecks int64
	denied      int64
	allowed     int64
}

// NewEgressChecker creates an EgressChecker with the given policy.
// A nil policy results in a deny-all checker (fail-closed).
func NewEgressChecker(policy *EgressPolicy) *EgressChecker {
	ec := &EgressChecker{
		clock: time.Now,
	}

	if policy == nil {
		policy = &EgressPolicy{} // empty = deny-all
	}
	ec.policy = policy

	// Pre-compute lookup sets
	ec.allowedSet = make(map[string]bool)
	for _, d := range policy.AllowedDomains {
		ec.allowedSet[strings.ToLower(d)] = true
	}

	ec.deniedSet = make(map[string]bool)
	for _, d := range policy.DeniedDomains {
		ec.deniedSet[strings.ToLower(d)] = true
	}

	ec.protoSet = make(map[string]bool)
	for _, p := range policy.AllowedProtocols {
		ec.protoSet[strings.ToLower(p)] = true
	}

	for _, cidr := range policy.AllowedCIDRs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			ec.parsedCIDRs = append(ec.parsedCIDRs, ipNet)
		}
	}

	return ec
}

// WithClock overrides the clock for deterministic testing.
func (ec *EgressChecker) WithClock(clock func() time.Time) *EgressChecker {
	ec.clock = clock
	return ec
}

// CheckEgress validates whether data may be transmitted to the given destination.
//
// Parameters:
//   - destination: domain name or IP address of the target
//   - protocol: protocol being used (e.g., "https", "grpc", "ssh")
//   - payloadBytes: size of the data being transmitted
//
// Returns an EgressDecision indicating whether the transmission is allowed.
func (ec *EgressChecker) CheckEgress(destination, protocol string, payloadBytes int64) *EgressDecision {
	ec.mu.Lock()
	ec.stats.totalChecks++
	ec.mu.Unlock()

	now := ec.clock()
	dest := strings.ToLower(destination)
	proto := strings.ToLower(protocol)

	decision := &EgressDecision{
		Destination:  destination,
		PayloadBytes: payloadBytes,
		CheckedAt:    now,
	}

	// Check 1: Explicit deny list (highest priority)
	if ec.deniedSet[dest] {
		decision.Allowed = false
		decision.ReasonCode = "DATA_EGRESS_BLOCKED"
		ec.mu.Lock()
		ec.stats.denied++
		ec.mu.Unlock()
		return decision
	}

	// Check 2: Protocol restriction
	if len(ec.protoSet) > 0 && !ec.protoSet[proto] {
		decision.Allowed = false
		decision.ReasonCode = "DATA_EGRESS_BLOCKED"
		ec.mu.Lock()
		ec.stats.denied++
		ec.mu.Unlock()
		return decision
	}

	// Check 3: Payload size limit
	if ec.policy.MaxPayloadBytes > 0 && payloadBytes > ec.policy.MaxPayloadBytes {
		decision.Allowed = false
		decision.ReasonCode = "DATA_EGRESS_BLOCKED"
		ec.mu.Lock()
		ec.stats.denied++
		ec.mu.Unlock()
		return decision
	}

	// Check 4: Domain allowlist
	if ec.allowedSet[dest] {
		decision.Allowed = true
		decision.ReasonCode = ""
		ec.mu.Lock()
		ec.stats.allowed++
		ec.mu.Unlock()
		return decision
	}

	// Check 5: CIDR allowlist (for IP-based destinations)
	if ip := net.ParseIP(destination); ip != nil {
		for _, cidr := range ec.parsedCIDRs {
			if cidr.Contains(ip) {
				decision.Allowed = true
				decision.ReasonCode = ""
				ec.mu.Lock()
				ec.stats.allowed++
				ec.mu.Unlock()
				return decision
			}
		}
	}

	// Fail-closed: not in allowlist → deny
	decision.Allowed = false
	decision.ReasonCode = "DATA_EGRESS_BLOCKED"
	ec.mu.Lock()
	ec.stats.denied++
	ec.mu.Unlock()
	return decision
}

// Stats returns egress check statistics.
func (ec *EgressChecker) Stats() (total, allowed, denied int64) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.stats.totalChecks, ec.stats.allowed, ec.stats.denied
}

// String returns a human-readable summary of the egress policy.
func (ec *EgressChecker) String() string {
	return fmt.Sprintf("EgressChecker{allowed=%d denied=%d cidrs=%d protocols=%d}",
		len(ec.allowedSet), len(ec.deniedSet), len(ec.parsedCIDRs), len(ec.protoSet))
}
