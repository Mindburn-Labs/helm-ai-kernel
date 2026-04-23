package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G11Operability validates operability minimum viable enterprise per §G11.
type G11Operability struct{}

func (g *G11Operability) ID() string   { return "G11" }
func (g *G11Operability) Name() string { return "Operability (Minimum Viable Enterprise)" }

func (g *G11Operability) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	// 1. Check SLO definitions
	sloPath := filepath.Join(ctx.EvidenceDir, "03_TELEMETRY", "slo.json")
	if fileExists(sloPath) {
		data, _ := os.ReadFile(sloPath)
		var slos []map[string]any
		if json.Unmarshal(data, &slos) == nil {
			result.Metrics.Counts["slo_definitions"] = len(slos)
			requiredSLOs := []string{
				"scheduler_latency",
				"policy_decision_latency",
				"receipt_verification_latency",
				"connector_error_rate",
				"escalation_queue_latency",
			}
			definedSLOs := make(map[string]bool)
			for _, slo := range slos {
				if name, ok := slo["name"].(string); ok {
					definedSLOs[name] = true
				}
			}
			for _, req := range requiredSLOs {
				if !definedSLOs[req] {
					result.Pass = false
					result.Reasons = append(result.Reasons, "SLO_MISSING:"+req)
				}
			}
		}
		result.EvidencePaths = append(result.EvidencePaths, "03_TELEMETRY/slo.json")
	} else {
		result.Pass = false
		result.Reasons = append(result.Reasons, "SLO_DEFINITIONS_MISSING")
	}

	// 2. Check dashboard snapshot
	reportsDir := filepath.Join(ctx.EvidenceDir, "12_REPORTS")
	dashFiles, _ := filepath.Glob(filepath.Join(reportsDir, "ops_dashboard_snapshot.*"))
	if len(dashFiles) > 0 {
		result.Metrics.Counts["dashboard_snapshots"] = len(dashFiles)
		result.EvidencePaths = append(result.EvidencePaths, "12_REPORTS/ops_dashboard_snapshot.*")
	} else {
		result.Pass = false
		result.Reasons = append(result.Reasons, "DASHBOARD_MISSING")
	}

	// 3. Check runbooks
	runbooksPath := filepath.Join(ctx.ProjectRoot, "docs", "runbooks", "index.json")
	if fileExists(runbooksPath) {
		result.Metrics.Counts["runbooks"] = 1
	} else {
		result.Pass = false
		result.Reasons = append(result.Reasons, "RUNBOOKS_MISSING")
	}

	return result
}
