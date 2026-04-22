package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G2ASchemaFirst validates schema-first determinism for tool I/O per §G2A.
type G2ASchemaFirst struct{}

func (g *G2ASchemaFirst) ID() string   { return "G2A" }
func (g *G2ASchemaFirst) Name() string { return "Schema-First Determinism (Tool I/O)" }

func (g *G2ASchemaFirst) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	// 1. Check tool I/O schemas exist
	schemasDir := filepath.Join(ctx.EvidenceDir, "09_SCHEMAS", "tool_io")
	if !dirExists(schemasDir) {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonSchemaValidationFailed)
		return result
	}

	schemaFiles, _ := filepath.Glob(filepath.Join(schemasDir, "*.json"))
	result.Metrics.Counts["schemas"] = len(schemaFiles)

	if len(schemaFiles) == 0 {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonSchemaValidationFailed)
		return result
	}

	// 2. Check tool I/O commitments
	commitmentsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "tool_io_commitments")
	if dirExists(commitmentsDir) {
		commitFiles, _ := filepath.Glob(filepath.Join(commitmentsDir, "*.json"))
		result.Metrics.Counts["commitments"] = len(commitFiles)
		result.EvidencePaths = append(result.EvidencePaths, "02_PROOFGRAPH/tool_io_commitments/")
	}

	// 3. Check per-tool schema checks in score
	scorePath := filepath.Join(ctx.EvidenceDir, "01_SCORE.json")
	if fileExists(scorePath) {
		data, _ := os.ReadFile(scorePath)
		var score map[string]any
		if json.Unmarshal(data, &score) == nil {
			result.EvidencePaths = append(result.EvidencePaths, "01_SCORE.json")
		}
	}

	result.EvidencePaths = append(result.EvidencePaths, "09_SCHEMAS/tool_io/")
	return result
}

