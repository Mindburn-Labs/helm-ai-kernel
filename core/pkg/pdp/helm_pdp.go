package pdp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// HelmPDP is the default policy decision point using HELM's built-in
// Proof Requirement Graph (PRG) evaluation. This wraps the existing
// Guardian logic behind the PDP interface for backward compatibility.
type HelmPDP struct {
	policyVersion string
	policyHash    string
	// rules is a placeholder for PRG-based evaluation.
	// In the full implementation, this wraps guardian.EvaluateDecision.
	rules map[string]bool // resource → allowed
}

// NewHelmPDP creates a default HELM PDP.
// policyVersion identifies the active policy set (e.g., git commit, semver).
func NewHelmPDP(policyVersion string, rules map[string]bool) *HelmPDP {
	h := &HelmPDP{
		policyVersion: policyVersion,
		rules:         rules,
	}
	h.policyHash = h.computePolicyHash()
	return h
}

// Evaluate implements PolicyDecisionPoint.
func (h *HelmPDP) Evaluate(ctx context.Context, req *DecisionRequest) (*DecisionResponse, error) {
	if req == nil {
		return &DecisionResponse{
			Allow:      false,
			ReasonCode: string(contracts.ReasonSchemaViolation),
			PolicyRef:  fmt.Sprintf("helm:%s", h.policyVersion),
		}, nil
	}

	// Check context deadline (fail-closed on timeout)
	select {
	case <-ctx.Done():
		return &DecisionResponse{
			Allow:      false,
			ReasonCode: string(contracts.ReasonPDPError),
			PolicyRef:  fmt.Sprintf("helm:%s", h.policyVersion),
		}, nil
	default:
	}

	allowed := true
	reasonCode := ""

	if h.rules != nil {
		if v, exists := h.rules[req.Resource]; exists {
			allowed = v
			if !allowed {
				reasonCode = string(contracts.ReasonPDPDeny)
			}
		}
	}

	resp := &DecisionResponse{
		Allow:      allowed,
		ReasonCode: reasonCode,
		PolicyRef:  fmt.Sprintf("helm:%s", h.policyVersion),
	}

	hash, err := ComputeDecisionHash(resp)
	if err != nil {
		return &DecisionResponse{
			Allow:      false,
			ReasonCode: string(contracts.ReasonPDPError),
			PolicyRef:  fmt.Sprintf("helm:%s", h.policyVersion),
		}, nil
	}
	resp.DecisionHash = hash

	return resp, nil
}

// Backend implements PolicyDecisionPoint.
func (h *HelmPDP) Backend() Backend { return BackendHELM }

// PolicyHash implements PolicyDecisionPoint.
func (h *HelmPDP) PolicyHash() string { return h.policyHash }

func (h *HelmPDP) computePolicyHash() string {
	input := struct {
		Version string          `json:"version"`
		Rules   map[string]bool `json:"rules"`
	}{
		Version: h.policyVersion,
		Rules:   h.rules,
	}
	data, err := canonicalize.JCS(input)
	if err != nil {
		return "sha256:unknown"
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
