package pdp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

const BackendCedar Backend = "cedar"

// CedarPDP implements PolicyDecisionPoint using Cedar policy evaluation.
//
// Cedar is Amazon's authorization policy language. This adapter maps
// HELM's DecisionRequest to Cedar's entity model:
//   - Principal → Cedar principal entity
//   - Action    → Cedar action entity
//   - Resource  → Cedar resource entity
//   - Context   → Cedar context record
//
// Fail-closed: any evaluation error returns DENY.
type CedarPDP struct {
	policies    []CedarPolicy
	policyRef   string
	policyCache string
}

// CedarPolicy is a parsed Cedar policy.
type CedarPolicy struct {
	ID     string `json:"id"`
	Effect string `json:"effect"` // "permit" or "forbid"

	PrincipalMatch string   `json:"principal_match,omitempty"` // e.g., "Agent::\"agent-001\""
	ActionMatch    []string `json:"action_match,omitempty"`    // e.g., ["Action::\"read_file\""]
	ResourceMatch  string   `json:"resource_match,omitempty"`  // e.g., "Resource::\"filesystem\""

	// Conditions on context fields
	ContextConditions map[string]string `json:"context_conditions,omitempty"`
}

// CedarConfig configures the Cedar PDP backend.
type CedarConfig struct {
	// Policies is the set of Cedar policies to evaluate.
	Policies []CedarPolicy `json:"policies"`

	// PolicyRef is a stable reference to the active policy version.
	PolicyRef string `json:"policy_ref"`
}

// NewCedarPDP creates a Cedar-backed PDP.
func NewCedarPDP(cfg CedarConfig) (*CedarPDP, error) {
	if len(cfg.Policies) == 0 {
		return nil, fmt.Errorf("pdp/cedar: at least one policy is required")
	}

	pdp := &CedarPDP{
		policies:  cfg.Policies,
		policyRef: cfg.PolicyRef,
	}
	pdp.policyCache = pdp.computePolicyHash()
	return pdp, nil
}

// Evaluate implements PolicyDecisionPoint.
//
// Cedar evaluation order:
//  1. If ANY forbid policy matches → DENY (forbid overrides permit)
//  2. If NO permit policy matches → DENY (default deny)
//  3. Otherwise → ALLOW
func (c *CedarPDP) Evaluate(ctx context.Context, req *DecisionRequest) (*DecisionResponse, error) {
	if req == nil {
		return c.denyResponse(string(contracts.ReasonSchemaViolation)), nil
	}

	select {
	case <-ctx.Done():
		return c.denyResponse(string(contracts.ReasonPDPError)), nil
	default:
	}

	// Evaluate all policies (Cedar semantics: explicit deny overrides).
	hasPermit := false
	for _, policy := range c.policies {
		match := c.matchPolicy(policy, req)
		if !match {
			continue
		}

		if policy.Effect == "forbid" {
			// Explicit deny — return immediately (Cedar semantics).
			return c.denyResponse(string(contracts.ReasonPDPDeny)), nil
		}

		if policy.Effect == "permit" {
			hasPermit = true
		}
	}

	if !hasPermit {
		// No permit matched → default deny.
		return c.denyResponse(string(contracts.ReasonPDPDeny)), nil
	}

	resp := &DecisionResponse{
		Allow:      true,
		ReasonCode: "",
		PolicyRef:  fmt.Sprintf("cedar:%s", c.policyRef),
	}

	hash, err := ComputeDecisionHash(resp)
	if err != nil {
		return c.denyResponse(string(contracts.ReasonPDPError)), nil
	}
	resp.DecisionHash = hash

	return resp, nil
}

// matchPolicy checks if a single Cedar policy matches the request.
func (c *CedarPDP) matchPolicy(p CedarPolicy, req *DecisionRequest) bool {
	// Principal matching.
	if p.PrincipalMatch != "" {
		expected := extractEntityID(p.PrincipalMatch)
		if expected != "" && expected != req.Principal && p.PrincipalMatch != "?principal" {
			return false
		}
	}

	// Action matching.
	if len(p.ActionMatch) > 0 {
		actionFound := false
		for _, a := range p.ActionMatch {
			expected := extractEntityID(a)
			if expected == req.Action {
				actionFound = true
				break
			}
		}
		if !actionFound {
			return false
		}
	}

	// Resource matching.
	if p.ResourceMatch != "" {
		expected := extractEntityID(p.ResourceMatch)
		if expected != "" && expected != req.Resource && p.ResourceMatch != "?resource" {
			return false
		}
	}

	// Context conditions.
	for key, expected := range p.ContextConditions {
		if actual, ok := req.Context[key]; ok {
			if fmt.Sprintf("%v", actual) != expected {
				return false
			}
		} else {
			return false
		}
	}

	return true
}

// extractEntityID extracts the ID from a Cedar entity reference.
// e.g., `Agent::"agent-001"` → "agent-001"
func extractEntityID(entity string) string {
	parts := strings.SplitN(entity, "::\"", 2)
	if len(parts) == 2 {
		return strings.TrimSuffix(parts[1], "\"")
	}
	// Fallback: return as-is for simple strings
	return entity
}

// Backend implements PolicyDecisionPoint.
func (c *CedarPDP) Backend() Backend { return BackendCedar }

// PolicyHash implements PolicyDecisionPoint.
func (c *CedarPDP) PolicyHash() string { return c.policyCache }

func (c *CedarPDP) denyResponse(reasonCode string) *DecisionResponse {
	resp := &DecisionResponse{
		Allow:      false,
		ReasonCode: reasonCode,
		PolicyRef:  fmt.Sprintf("cedar:%s", c.policyRef),
	}
	resp.DecisionHash, _ = ComputeDecisionHash(resp)
	return resp
}

func (c *CedarPDP) computePolicyHash() string {
	// Sort policies by ID for determinism.
	sorted := make([]CedarPolicy, len(c.policies))
	copy(sorted, c.policies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	input := struct {
		Backend   string        `json:"backend"`
		PolicyRef string        `json:"policy_ref"`
		Policies  []CedarPolicy `json:"policies"`
	}{
		Backend:   "cedar",
		PolicyRef: c.policyRef,
		Policies:  sorted,
	}
	data, err := canonicalize.JCS(input)
	if err != nil {
		return "sha256:unknown"
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
