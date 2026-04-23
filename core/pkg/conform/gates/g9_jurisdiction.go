package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G9Jurisdiction validates jurisdiction compilation per §G9.
type G9Jurisdiction struct{}

func (g *G9Jurisdiction) ID() string   { return "G9" }
func (g *G9Jurisdiction) Name() string { return "Jurisdiction Compilation" }

func (g *G9Jurisdiction) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	jurisdictionsDir := filepath.Join(ctx.EvidenceDir, "04_EXPORTS", "jurisdictions")

	// 1. Check at least 2 jurisdiction packs
	if !dirExists(jurisdictionsDir) {
		result.Pass = false
		result.Reasons = append(result.Reasons, "JURISDICTION_PACKS_MISSING")
		return result
	}

	entries, _ := os.ReadDir(jurisdictionsDir)
	packDirs := 0
	for _, e := range entries {
		if e.IsDir() {
			packDirs++
			// Check each pack has required outputs
			packDir := filepath.Join(jurisdictionsDir, e.Name())
			requiredFiles := []string{"policy_bundle.json", "evidence_requirements.json", "retention_rules.json"}
			for _, reqFile := range requiredFiles {
				if !fileExists(filepath.Join(packDir, reqFile)) {
					result.Pass = false
					result.Reasons = append(result.Reasons, "JURISDICTION_PACK_INCOMPLETE:"+e.Name())
				}
			}
			// Check test suite
			suiteFiles, _ := filepath.Glob(filepath.Join(packDir, "test_suite", "*.json"))
			result.Metrics.Counts["jurisdiction_tests"] += len(suiteFiles)
		}
	}

	result.Metrics.Counts["jurisdiction_packs"] = packDirs
	if packDirs < 2 {
		result.Pass = false
		result.Reasons = append(result.Reasons, "JURISDICTION_PACKS_INSUFFICIENT")
	}

	// 2. Check jurisdiction-specific conformance reports
	for _, e := range entries {
		if e.IsDir() {
			reportPath := filepath.Join(jurisdictionsDir, e.Name(), "conformance_report.json")
			if fileExists(reportPath) {
				data, _ := os.ReadFile(reportPath)
				var report map[string]any
				if json.Unmarshal(data, &report) == nil {
					if pass, ok := report["pass"].(bool); ok && !pass {
						result.Pass = false
						result.Reasons = append(result.Reasons, "JURISDICTION_CONFORMANCE_FAILED:"+e.Name())
					}
				}
			}
		}
	}

	result.EvidencePaths = append(result.EvidencePaths, "04_EXPORTS/jurisdictions/")
	return result
}
