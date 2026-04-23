package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G6Taint validates taint tracking and lineage per §G6.
type G6Taint struct{}

func (g *G6Taint) ID() string   { return "G6" }
func (g *G6Taint) Name() string { return "Taint Tracking and Data Lineage" }

func (g *G6Taint) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	// 1. Check lineage artifacts
	taintDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "taint")
	lineagePath := filepath.Join(taintDir, "lineage.json")

	if !fileExists(lineagePath) {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonTaintFlowViolation)
		return result
	}

	// 2. Verify lineage structure
	data, err := os.ReadFile(lineagePath)
	if err != nil {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonTaintFlowViolation)
		return result
	}

	var lineage map[string]any
	if json.Unmarshal(data, &lineage) != nil {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonTaintFlowViolation)
		return result
	}

	// Check node count
	if nodes, ok := lineage["nodes"].([]any); ok {
		result.Metrics.Counts["taint_nodes"] = len(nodes)
		for _, n := range nodes {
			if node, ok := n.(map[string]any); ok {
				if _, hasHash := node["lineage_hash"]; !hasHash {
					result.Pass = false
					result.Reasons = append(result.Reasons, conform.ReasonTaintFlowViolation)
				}
			}
		}
	}

	// Check violations
	if violations, ok := lineage["violations"].([]any); ok && len(violations) > 0 {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonTaintFlowViolation)
		result.Metrics.Counts["taint_violations"] = len(violations)
	}

	result.EvidencePaths = append(result.EvidencePaths, "02_PROOFGRAPH/taint/lineage.json")
	return result
}
