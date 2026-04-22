package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G8HITL validates human-in-the-loop controls per §G8.
type G8HITL struct{}

func (g *G8HITL) ID() string   { return "G8" }
func (g *G8HITL) Name() string { return "Human-in-the-Loop Controls" }

func (g *G8HITL) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	// Check operator receipts
	receiptsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts")
	if !dirExists(receiptsDir) {
		result.Pass = false
		result.Reasons = append(result.Reasons, "HITL_RECEIPTS_MISSING")
		return result
	}

	files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))
	operatorActionFound := false
	for _, f := range files {
		data, _ := os.ReadFile(f)
		var receipt map[string]any
		if json.Unmarshal(data, &receipt) == nil {
			if actor, ok := receipt["actor"].(string); ok && actor == "operator" {
				operatorActionFound = true
				result.Metrics.Counts["operator_actions"]++
			}
		}
	}

	if !operatorActionFound {
		result.Pass = false
		result.Reasons = append(result.Reasons, "HITL_RECEIPTS_MISSING")
	}

	return result
}
