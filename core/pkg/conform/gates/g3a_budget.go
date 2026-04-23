package gates

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G3ABudget validates deny-by-budget enforcement and physical severing per §G3A.
type G3ABudget struct{}

func (g *G3ABudget) ID() string   { return "G3A" }
func (g *G3ABudget) Name() string { return "Deny-by-Budget and Physical Severing" }

func (g *G3ABudget) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	// 1. Check budget metrics
	metricsPath := filepath.Join(ctx.EvidenceDir, "03_TELEMETRY", "budget_metrics.json")
	if !fileExists(metricsPath) {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonBudgetExhausted)
		return result
	}
	result.EvidencePaths = append(result.EvidencePaths, "03_TELEMETRY/budget_metrics.json")

	// 2. Check BudgetExhausted receipts exist
	receiptsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts")
	receiptFiles, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))
	budgetExhaustedFound := false
	for _, f := range receiptFiles {
		if strings.Contains(filepath.Base(f), "BudgetExhausted") {
			budgetExhaustedFound = true
			result.EvidencePaths = append(result.EvidencePaths, "02_PROOFGRAPH/receipts/"+filepath.Base(f))
			break
		}
		// Also check content
		data, _ := os.ReadFile(f)
		if strings.Contains(string(data), "BudgetExhausted") {
			budgetExhaustedFound = true
			break
		}
	}

	if !budgetExhaustedFound {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonBudgetExhausted)
	}

	// 3. Check budget metrics content
	data, err := os.ReadFile(metricsPath)
	if err == nil {
		var metrics map[string]any
		if json.Unmarshal(data, &metrics) == nil {
			// Verify budget types are tracked
			for _, budgetType := range []string{"time", "tokens", "tool_calls", "spend", "recursion"} {
				if _, ok := metrics[budgetType]; ok {
					result.Metrics.Counts[budgetType+"_tracked"] = 1
				}
			}
		}
	}

	// 4. Check THROTTLE containment was triggered (links to G7)
	if containmentReq, ok := ctx.ExtraConfig["containment_triggered"]; ok {
		if triggered, ok := containmentReq.(bool); ok && !triggered {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonContainmentNotTriggered)
		}
	}

	return result
}
