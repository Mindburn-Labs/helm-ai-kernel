package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G7Incident validates incident response and containment per §G7.
type G7Incident struct{}

func (g *G7Incident) ID() string   { return "G7" }
func (g *G7Incident) Name() string { return "Incident Response and Containment" }

func (g *G7Incident) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	incidentsDir := filepath.Join(ctx.EvidenceDir, "04_EXPORTS", "incidents")

	// Check incident export capability
	if dirExists(incidentsDir) {
		files, _ := filepath.Glob(filepath.Join(incidentsDir, "*"))
		result.Metrics.Counts["incident_exports"] = len(files)
		result.EvidencePaths = append(result.EvidencePaths, "04_EXPORTS/incidents/")
	}

	// Check containment mode configuration
	receiptsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts")
	if dirExists(receiptsDir) {
		files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))
		containmentFound := false
		for _, f := range files {
			data, _ := os.ReadFile(f)
			var receipt map[string]any
			if json.Unmarshal(data, &receipt) == nil {
				if at, ok := receipt["action_type"].(string); ok {
					if at == "FREEZE" || at == "THROTTLE" || at == "EMERGENCY" {
						containmentFound = true
						result.Metrics.Counts["containment_transitions"]++
					}
				}
			}
		}
		if !containmentFound {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonContainmentNotTriggered)
		}
	} else {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonContainmentNotTriggered)
	}

	return result
}
