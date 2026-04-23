package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G12SupplyChain validates supply chain and pack trust per §G12.
type G12SupplyChain struct{}

func (g *G12SupplyChain) ID() string   { return "G12" }
func (g *G12SupplyChain) Name() string { return "Supply Chain and Pack Trust" }

func (g *G12SupplyChain) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	// 1. Check pack signatures
	packsDir := filepath.Join(ctx.ProjectRoot, "packs")
	if !dirExists(packsDir) {
		result.Pass = false
		result.Reasons = append(result.Reasons, "PACKS_DIR_MISSING")
		return result
	}

	entries, _ := os.ReadDir(packsDir)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		packDir := filepath.Join(packsDir, e.Name())
		sigPath := filepath.Join(packDir, "signature.json")
		if !fileExists(sigPath) {
			result.Pass = false
			result.Reasons = append(result.Reasons, "PACK_UNSIGNED:"+e.Name())
			continue
		}

		// Verify signature structure
		data, _ := os.ReadFile(sigPath)
		var sig map[string]any
		if json.Unmarshal(data, &sig) != nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, "PACK_SIG_INVALID:"+e.Name())
		}

		result.Metrics.Counts["packs_verified"]++
	}

	// 2. Check trusted roots
	rootsPath := filepath.Join(ctx.ProjectRoot, "packs", "trusted_roots.json")
	if fileExists(rootsPath) {
		result.Metrics.Counts["trusted_roots"] = 1
	} else {
		result.Pass = false
		result.Reasons = append(result.Reasons, "TRUSTED_ROOTS_MISSING")
	}

	// 3. Check pack install/upgrade receipts
	receiptsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts")
	if dirExists(receiptsDir) {
		files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))
		for _, f := range files {
			data, _ := os.ReadFile(f)
			var receipt map[string]any
			if json.Unmarshal(data, &receipt) == nil {
				if at, ok := receipt["action_type"].(string); ok {
					if at == "pack_install" || at == "pack_upgrade" || at == "pack_rollback" {
						result.Metrics.Counts["pack_receipts"]++
					}
				}
			}
		}
	}

	return result
}
