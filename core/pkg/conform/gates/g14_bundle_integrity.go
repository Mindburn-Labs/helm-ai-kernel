package gates

import (
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/bundles"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G14BundleIntegrity validates policy bundle integrity per L3 §G14.
// PASS requires: all bundles in the evidence directory can be loaded
// and their content hashes are deterministic and valid.
type G14BundleIntegrity struct{}

func (g *G14BundleIntegrity) ID() string   { return "G14" }
func (g *G14BundleIntegrity) Name() string { return "Policy Bundle Integrity" }

func (g *G14BundleIntegrity) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	bundleDir := filepath.Join(ctx.EvidenceDir, "bundles")
	if !dirExists(bundleDir) {
		// No bundles directory — L3 requires at least one bundle
		result.Pass = false
		result.Reasons = append(result.Reasons, "No bundles directory found in evidence")
		return result
	}

	files, _ := filepath.Glob(filepath.Join(bundleDir, "*.yaml"))
	ymlFiles, _ := filepath.Glob(filepath.Join(bundleDir, "*.yml"))
	files = append(files, ymlFiles...)

	if len(files) == 0 {
		result.Pass = false
		result.Reasons = append(result.Reasons, "No policy bundle files found")
		return result
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, "Cannot read bundle: "+filepath.Base(f))
			continue
		}

		bundle, err := bundles.LoadFromBytes(data)
		if err != nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, "Invalid bundle: "+filepath.Base(f)+": "+err.Error())
			continue
		}

		// Verify hash is deterministic (load twice, compare)
		bundle2, _ := bundles.LoadFromBytes(data)
		if bundle.Metadata.Hash != bundle2.Metadata.Hash {
			result.Pass = false
			result.Reasons = append(result.Reasons, "Bundle hash not deterministic: "+filepath.Base(f))
			continue
		}

		result.Metrics.Counts["bundles_verified"]++
		result.EvidencePaths = append(result.EvidencePaths, "bundles/"+filepath.Base(f))
	}

	return result
}
