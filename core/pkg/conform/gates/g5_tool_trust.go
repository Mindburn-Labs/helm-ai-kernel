package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G5ToolTrust validates tool boundary zero trust per §G5.
type G5ToolTrust struct{}

func (g *G5ToolTrust) ID() string   { return "G5" }
func (g *G5ToolTrust) Name() string { return "Tool Boundary Zero Trust" }

func (g *G5ToolTrust) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	// 1. Check tool manifests
	manifestsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "tool_manifests")
	if !dirExists(manifestsDir) {
		result.Pass = false
		result.Reasons = append(result.Reasons, "TOOL_MANIFEST_MISSING")
		return result
	}

	files, _ := filepath.Glob(filepath.Join(manifestsDir, "*.json"))
	result.Metrics.Counts["tool_manifests"] = len(files)

	if len(files) == 0 {
		result.Pass = false
		result.Reasons = append(result.Reasons, "TOOL_MANIFEST_MISSING")
		return result
	}

	// 2. Verify each manifest has required fields per §4.2
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var manifest map[string]any
		if json.Unmarshal(data, &manifest) != nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, "TOOL_MANIFEST_INVALID")
			continue
		}
		// Check all §4.2 required fields
		requiredFields := []string{
			"tool_id", "version", "capabilities",
			"side_effect_classes", "data_classes_in", "data_classes_out",
			"network_scopes", "fs_scopes", "required_approvals",
			"schemas", "signatures",
		}
		for _, field := range requiredFields {
			if _, ok := manifest[field]; !ok {
				result.Pass = false
				result.Reasons = append(result.Reasons, "TOOL_MANIFEST_INVALID")
			}
		}
	}

	result.EvidencePaths = append(result.EvidencePaths, "02_PROOFGRAPH/tool_manifests/")
	return result
}
