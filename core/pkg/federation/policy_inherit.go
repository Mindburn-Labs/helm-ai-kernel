package federation

import (
	"fmt"
	"sort"
	"sync"
)

// PolicyInheritor computes effective policies for federated organizations.
// All operations are thread-safe.
type PolicyInheritor struct {
	mu       sync.RWMutex
	policies map[string]*FederationPolicy // childOrgID -> policy
}

// NewPolicyInheritor creates an empty policy inheritor.
func NewPolicyInheritor() *PolicyInheritor {
	return &PolicyInheritor{
		policies: make(map[string]*FederationPolicy),
	}
}

// SetPolicy registers or updates a federation policy for a child org.
// Returns an error if the policy is invalid.
func (pi *PolicyInheritor) SetPolicy(policy FederationPolicy) error {
	if policy.PolicyID == "" {
		return fmt.Errorf("federation: policy_id must not be empty")
	}
	if policy.ParentOrgID == "" {
		return fmt.Errorf("federation: parent_org_id must not be empty")
	}
	if policy.ChildOrgID == "" {
		return fmt.Errorf("federation: child_org_id must not be empty")
	}
	if policy.ParentOrgID == policy.ChildOrgID {
		return fmt.Errorf("federation: parent and child org_id must differ")
	}

	pi.mu.Lock()
	defer pi.mu.Unlock()

	copied := policy
	pi.policies[policy.ChildOrgID] = &copied
	return nil
}

// EffectiveCapabilities computes what a child org can do given the parent's capabilities.
//
// Rule: child_effective = (parentCaps intersect inherited_caps) minus denied_caps
//
// If no policy is set for the child, no capabilities are granted (fail-closed).
func (pi *PolicyInheritor) EffectiveCapabilities(childOrgID string, parentCaps []string) []string {
	pi.mu.RLock()
	defer pi.mu.RUnlock()

	policy, ok := pi.policies[childOrgID]
	if !ok {
		return nil // fail-closed: no policy = no capabilities
	}

	// Build lookup sets.
	inherited := toSet(policy.InheritedCaps)
	denied := toSet(policy.DeniedCaps)

	// Intersection of parentCaps and inherited, minus denied.
	var effective []string
	for _, cap := range parentCaps {
		if inherited[cap] && !denied[cap] {
			effective = append(effective, cap)
		}
	}

	sort.Strings(effective)
	return effective
}

// ValidateNarrowing checks that requestedCaps are a subset of parentCaps.
// Returns an error listing any capabilities that would expand beyond the parent's authority.
func (pi *PolicyInheritor) ValidateNarrowing(childOrgID string, requestedCaps []string, parentCaps []string) error {
	pi.mu.RLock()
	defer pi.mu.RUnlock()

	policy, ok := pi.policies[childOrgID]
	if !ok {
		return fmt.Errorf("federation: no policy found for child org %s", childOrgID)
	}

	if !policy.NarrowingOnly {
		return nil // expansion allowed by policy
	}

	parentSet := toSet(parentCaps)
	var violations []string
	for _, cap := range requestedCaps {
		if !parentSet[cap] {
			violations = append(violations, cap)
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		return fmt.Errorf("federation: narrowing violation for child %s: capabilities %v exceed parent authority",
			childOrgID, violations)
	}
	return nil
}

// toSet converts a string slice to a set (map[string]bool).
func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[item] = true
	}
	return s
}
