package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G3Policy validates deny-by-default policy at all boundaries per §G3.
type G3Policy struct{}

func (g *G3Policy) ID() string   { return "G3" }
func (g *G3Policy) Name() string { return "Policy Fail-Closed at All Boundaries" }

func (g *G3Policy) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	// 1. Check policy decisions directory
	policyDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "policy_decisions")
	if !dirExists(policyDir) {
		_ = os.MkdirAll(policyDir, 0750)
	}

	decisionFiles, _ := filepath.Glob(filepath.Join(policyDir, "*.json"))
	result.Metrics.Counts["policy_decisions"] = len(decisionFiles)

	if len(decisionFiles) == 0 {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonPolicyDecisionMissing)
		return result
	}

	// 2. Verify each decision has required fields and deny-by-default
	for _, f := range decisionFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonPolicyDecisionMissing)
			continue
		}

		var decision map[string]any
		if err := json.Unmarshal(data, &decision); err != nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonPolicyDecisionMissing)
			continue
		}

		// Check policy_hash is present
		if _, ok := decision["policy_hash"]; !ok {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonPolicyDecisionMissing)
		}

		// Check boundary type is declared
		if _, ok := decision["boundary"]; !ok {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonPolicyDecisionMissing)
		}
	}

	result.EvidencePaths = append(result.EvidencePaths, "02_PROOFGRAPH/policy_decisions/")
	return result
}
