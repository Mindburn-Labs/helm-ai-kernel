// Package verify provides policy verification using formal methods.
// Per arXiv 2512.09758, LLMs can automate TLA+ proof generation.
//
// This package provides interface definitions and a lightweight static analysis verifier.
//
// Design invariants:
//   - Policies must satisfy safety properties before deployment
//   - Verification is deterministic given the same policy and properties
//   - Fail-closed: unverifiable policies are rejected
package verify

import (
	"encoding/json"
	"fmt"
	"time"
)

// PolicyVerificationResult represents the outcome of formal policy verification.
type PolicyVerificationResult struct {
	PolicyID   string   `json:"policy_id"`
	Verified   bool     `json:"verified"`
	Properties []string `json:"properties_checked"` // e.g., "no_escalation_loop", "deny_terminates"
	Violations []string `json:"violations,omitempty"`
	Method     string   `json:"method"` // "tla+", "model_check", "static_analysis"
	VerifiedAt time.Time `json:"verified_at"`
}

// PolicyVerifier checks that policies satisfy safety properties.
type PolicyVerifier interface {
	// Verify checks that the policy identified by policyID, with the given
	// rules (JSON-encoded), satisfies the specified safety properties.
	Verify(policyID string, policyRules []byte, properties []string) (*PolicyVerificationResult, error)
}

// policyRule is the internal representation of a single policy rule for
// static analysis purposes.
type policyRule struct {
	ID       string `json:"id"`
	Priority int    `json:"priority"`
	Action   string `json:"action"`       // "ALLOW" or "DENY"
	Resource string `json:"resource"`
	DependsOn string `json:"depends_on,omitempty"` // ID of another rule
}

// StaticAnalysisVerifier performs lightweight static checks on policies.
// It verifies basic structural properties without requiring a full model
// checker or TLA+ runtime.
//
// Supported properties:
//   - "no_circular_deps" — No circular dependencies between rules
//   - "no_shadowed_deny" — DENY rules are reachable (not shadowed by higher-priority ALLOW)
//   - "no_escalation_loop" — No infinite escalation loops (detected via depends_on cycles)
//   - "deny_terminates" — At least one DENY rule exists (ensures fail-closed)
type StaticAnalysisVerifier struct {
	clock func() time.Time
}

// StaticAnalysisOption configures optional StaticAnalysisVerifier settings.
type StaticAnalysisOption func(*StaticAnalysisVerifier)

// WithVerifyClock sets a custom clock function (primarily for testing).
func WithVerifyClock(clock func() time.Time) StaticAnalysisOption {
	return func(v *StaticAnalysisVerifier) {
		v.clock = clock
	}
}

// NewStaticAnalysisVerifier creates a new static analysis verifier.
func NewStaticAnalysisVerifier(opts ...StaticAnalysisOption) *StaticAnalysisVerifier {
	v := &StaticAnalysisVerifier{clock: time.Now}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Verify performs static analysis on the given policy rules and checks
// the specified properties. Returns a PolicyVerificationResult with any
// violations found.
func (v *StaticAnalysisVerifier) Verify(policyID string, policyRules []byte, properties []string) (*PolicyVerificationResult, error) {
	if policyID == "" {
		return nil, fmt.Errorf("verify: policy ID is required")
	}
	if len(policyRules) == 0 {
		return nil, fmt.Errorf("verify: policy rules are required")
	}
	if len(properties) == 0 {
		return nil, fmt.Errorf("verify: at least one property is required")
	}

	var rules []policyRule
	if err := json.Unmarshal(policyRules, &rules); err != nil {
		return nil, fmt.Errorf("verify: failed to parse policy rules: %w", err)
	}

	result := &PolicyVerificationResult{
		PolicyID:   policyID,
		Verified:   true,
		Properties: make([]string, len(properties)),
		Method:     "static_analysis",
		VerifiedAt: v.clock(),
	}
	copy(result.Properties, properties)

	for _, prop := range properties {
		violations := v.checkProperty(prop, rules)
		if len(violations) > 0 {
			result.Verified = false
			result.Violations = append(result.Violations, violations...)
		}
	}

	return result, nil
}

// checkProperty dispatches a property check to the appropriate analysis function.
func (v *StaticAnalysisVerifier) checkProperty(property string, rules []policyRule) []string {
	switch property {
	case "no_circular_deps":
		return v.checkCircularDeps(rules)
	case "no_shadowed_deny":
		return v.checkShadowedDeny(rules)
	case "no_escalation_loop":
		return v.checkEscalationLoop(rules)
	case "deny_terminates":
		return v.checkDenyTerminates(rules)
	default:
		return []string{fmt.Sprintf("unknown property: %q", property)}
	}
}

// checkCircularDeps detects circular dependencies in rule depends_on chains.
func (v *StaticAnalysisVerifier) checkCircularDeps(rules []policyRule) []string {
	// Build dependency graph: ruleID -> depends_on ruleID.
	deps := make(map[string]string)
	for _, r := range rules {
		if r.DependsOn != "" {
			deps[r.ID] = r.DependsOn
		}
	}

	var violations []string
	visited := make(map[string]bool)

	for id := range deps {
		if visited[id] {
			continue
		}

		// Walk the chain, detecting cycles via tortoise-and-hare style.
		path := make(map[string]bool)
		current := id
		for current != "" {
			if path[current] {
				violations = append(violations,
					fmt.Sprintf("circular dependency detected involving rule %q", current))
				break
			}
			path[current] = true
			visited[current] = true
			current = deps[current]
		}
	}

	return violations
}

// checkShadowedDeny detects DENY rules that are shadowed by higher-priority ALLOW rules
// on the same resource.
func (v *StaticAnalysisVerifier) checkShadowedDeny(rules []policyRule) []string {
	// Group by resource, sort by priority (higher = evaluated first).
	type ruleEntry struct {
		id       string
		priority int
		action   string
	}
	byResource := make(map[string][]ruleEntry)
	for _, r := range rules {
		byResource[r.Resource] = append(byResource[r.Resource], ruleEntry{
			id:       r.ID,
			priority: r.Priority,
			action:   r.Action,
		})
	}

	var violations []string
	for resource, entries := range byResource {
		for _, deny := range entries {
			if deny.action != "DENY" {
				continue
			}
			for _, allow := range entries {
				if allow.action != "ALLOW" {
					continue
				}
				if allow.priority > deny.priority {
					violations = append(violations,
						fmt.Sprintf("DENY rule %q on resource %q is shadowed by higher-priority ALLOW rule %q",
							deny.id, resource, allow.id))
				}
			}
		}
	}

	return violations
}

// checkEscalationLoop detects infinite escalation loops via depends_on cycles.
// This is similar to circular deps but focused on escalation semantics.
func (v *StaticAnalysisVerifier) checkEscalationLoop(rules []policyRule) []string {
	// Re-use circular dependency detection — escalation loops manifest as cycles.
	return v.checkCircularDeps(rules)
}

// checkDenyTerminates verifies that at least one DENY rule exists in the policy,
// ensuring the policy can fail-closed.
func (v *StaticAnalysisVerifier) checkDenyTerminates(rules []policyRule) []string {
	for _, r := range rules {
		if r.Action == "DENY" {
			return nil
		}
	}
	return []string{"no DENY rule found: policy cannot fail-closed"}
}
