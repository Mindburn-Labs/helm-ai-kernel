// Package sandbox — Sandbox Security Policy Enforcement
//
// Per HELM 2030 Spec — Sandboxed Execution:
//   - Real FS/network allowlists enforced on every operation
//   - Capability-based filtering restricts sandbox operations
//   - All sandbox operations are audited
package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SandboxPolicy defines the security boundary for a sandbox.
type SandboxPolicy struct {
	PolicyID         string   `json:"policy_id"`
	FSAllowlist      []string `json:"fs_allowlist"`      // Allowed filesystem paths (prefixes)
	FSDenylist       []string `json:"fs_denylist"`       // Denied paths (checked first)
	NetworkAllowlist []string `json:"network_allowlist"` // Allowed hosts/CIDRs
	NetworkDenyAll   bool     `json:"network_deny_all"`  // If true, block all network
	MaxMemoryBytes   int64    `json:"max_memory_bytes"`
	MaxCPUSeconds    int64    `json:"max_cpu_seconds"`
	Capabilities     []string `json:"capabilities"` // Allowed capabilities
	MaxOpenFiles     int      `json:"max_open_files"`
	ReadOnly         bool     `json:"read_only"` // FS is read-only
}

// DefaultPolicy returns a restrictive default sandbox policy.
func DefaultPolicy() *SandboxPolicy {
	return &SandboxPolicy{
		PolicyID:       "default",
		FSAllowlist:    []string{"/tmp/sandbox"},
		FSDenylist:     []string{"/etc/passwd", "/etc/shadow", "/root"},
		NetworkDenyAll: true,
		MaxMemoryBytes: 256 * 1024 * 1024, // 256MB
		MaxCPUSeconds:  30,
		Capabilities:   []string{"read", "write", "execute"},
		MaxOpenFiles:   64,
		ReadOnly:       false,
	}
}

// PolicyViolation records a sandbox boundary crossing attempt.
type PolicyViolation struct {
	ViolationType string    `json:"violation_type"`
	Detail        string    `json:"detail"`
	Timestamp     time.Time `json:"timestamp"`
	Blocked       bool      `json:"blocked"`
}

// PolicyEnforcer checks operations against sandbox policy.
type PolicyEnforcer struct {
	mu         sync.RWMutex
	policy     *SandboxPolicy
	violations []PolicyViolation
	clock      func() time.Time
}

// NewPolicyEnforcer creates a new enforcer with a sandbox policy.
func NewPolicyEnforcer(policy *SandboxPolicy) *PolicyEnforcer {
	if policy == nil {
		policy = DefaultPolicy()
	}
	return &PolicyEnforcer{
		policy:     policy,
		violations: make([]PolicyViolation, 0),
		clock:      time.Now,
	}
}

// WithClock overrides clock for testing.
func (e *PolicyEnforcer) WithClock(clock func() time.Time) *PolicyEnforcer {
	e.clock = clock
	return e
}

// CheckResult carries the enforcement decision.
type CheckResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// CheckFS verifies a filesystem path against the policy.
func (e *PolicyEnforcer) CheckFS(path string, write bool) CheckResult {
	e.mu.Lock()
	defer e.mu.Unlock()

	cleanPath := filepath.Clean(path)

	// Denylist checked first (fail-closed)
	for _, deny := range e.policy.FSDenylist {
		if strings.HasPrefix(cleanPath, deny) {
			v := PolicyViolation{
				ViolationType: "FS_DENY",
				Detail:        fmt.Sprintf("path %s matches denylist entry %s", cleanPath, deny),
				Timestamp:     e.clock(),
				Blocked:       true,
			}
			e.violations = append(e.violations, v)
			return CheckResult{Allowed: false, Reason: v.Detail}
		}
	}

	// Read-only check
	if write && e.policy.ReadOnly {
		v := PolicyViolation{
			ViolationType: "FS_READONLY",
			Detail:        fmt.Sprintf("write to %s denied: sandbox is read-only", cleanPath),
			Timestamp:     e.clock(),
			Blocked:       true,
		}
		e.violations = append(e.violations, v)
		return CheckResult{Allowed: false, Reason: v.Detail}
	}

	// Allowlist check
	allowed := false
	for _, allow := range e.policy.FSAllowlist {
		if strings.HasPrefix(cleanPath, allow) {
			allowed = true
			break
		}
	}

	if !allowed {
		v := PolicyViolation{
			ViolationType: "FS_NOT_ALLOWED",
			Detail:        fmt.Sprintf("path %s not in allowlist", cleanPath),
			Timestamp:     e.clock(),
			Blocked:       true,
		}
		e.violations = append(e.violations, v)
		return CheckResult{Allowed: false, Reason: v.Detail}
	}

	return CheckResult{Allowed: true, Reason: "within filesystem allowlist"}
}

// CheckNetwork verifies a network host against the policy.
func (e *PolicyEnforcer) CheckNetwork(host string) CheckResult {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.policy.NetworkDenyAll {
		v := PolicyViolation{
			ViolationType: "NETWORK_DENY_ALL",
			Detail:        fmt.Sprintf("all network access denied, attempted: %s", host),
			Timestamp:     e.clock(),
			Blocked:       true,
		}
		e.violations = append(e.violations, v)
		return CheckResult{Allowed: false, Reason: v.Detail}
	}

	allowed := false
	for _, allow := range e.policy.NetworkAllowlist {
		if allow == host || strings.HasSuffix(host, "."+allow) {
			allowed = true
			break
		}
	}

	if !allowed {
		v := PolicyViolation{
			ViolationType: "NETWORK_NOT_ALLOWED",
			Detail:        fmt.Sprintf("host %s not in network allowlist", host),
			Timestamp:     e.clock(),
			Blocked:       true,
		}
		e.violations = append(e.violations, v)
		return CheckResult{Allowed: false, Reason: v.Detail}
	}

	return CheckResult{Allowed: true, Reason: "within network allowlist"}
}

// CheckCapability verifies a capability request.
func (e *PolicyEnforcer) CheckCapability(capability string) CheckResult {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, cap := range e.policy.Capabilities {
		if cap == capability {
			return CheckResult{Allowed: true, Reason: "capability granted"}
		}
	}

	v := PolicyViolation{
		ViolationType: "CAPABILITY_DENIED",
		Detail:        fmt.Sprintf("capability %s not granted", capability),
		Timestamp:     e.clock(),
		Blocked:       true,
	}
	e.violations = append(e.violations, v)
	return CheckResult{Allowed: false, Reason: v.Detail}
}

// CheckMemory verifies memory usage against policy limits.
func (e *PolicyEnforcer) CheckMemory(bytes int64) CheckResult {
	if bytes > e.policy.MaxMemoryBytes {
		return CheckResult{
			Allowed: false,
			Reason:  fmt.Sprintf("memory %d exceeds limit %d", bytes, e.policy.MaxMemoryBytes),
		}
	}
	return CheckResult{Allowed: true, Reason: "within memory limit"}
}

// GetViolations returns all recorded violations.
func (e *PolicyEnforcer) GetViolations() []PolicyViolation {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]PolicyViolation, len(e.violations))
	copy(result, e.violations)
	return result
}
