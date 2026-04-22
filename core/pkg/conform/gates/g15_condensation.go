package gates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph/condensation"
)

// G15Condensation validates proof condensation checkpoints per L3 §G15.
// PASS requires: condensation engine can create checkpoints with valid
// Merkle roots, or existing checkpoint files in evidence are valid.
type G15Condensation struct{}

func (g *G15Condensation) ID() string   { return "G15" }
func (g *G15Condensation) Name() string { return "Proof Condensation Checkpoint" }

func (g *G15Condensation) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	checkpointDir := filepath.Join(ctx.EvidenceDir, "condensation")
	if !dirExists(checkpointDir) {
		// No evidence directory — verify engine works with a probe
		engine := condensation.NewEngine()
		h := sha256.Sum256([]byte("probe-receipt-content"))
		engine.Accumulate(condensation.Receipt{
			ID:       "probe-receipt",
			Hash:     hex.EncodeToString(h[:]),
			RiskTier: condensation.RiskLow,
		})

		cp, err := engine.CreateCheckpoint(0, 1)
		if err != nil || cp == nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, "Condensation engine failed to create checkpoint")
			return result
		}

		if cp.MerkleRoot == "" {
			result.Pass = false
			result.Reasons = append(result.Reasons, "Condensation engine produced empty Merkle root")
			return result
		}

		result.Metrics.Counts["engine_probe"] = 1
		result.EvidencePaths = append(result.EvidencePaths, "G15_CONDENSATION/engine_probe")
		return result
	}

	// Validate checkpoint files from evidence
	files, _ := filepath.Glob(filepath.Join(checkpointDir, "*.json"))
	if len(files) == 0 {
		result.Pass = false
		result.Reasons = append(result.Reasons, "No checkpoint files found in condensation directory")
		return result
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, "Cannot read checkpoint: "+filepath.Base(f))
			continue
		}

		var cp condensation.Checkpoint
		if err := json.Unmarshal(data, &cp); err != nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, "Invalid checkpoint format: "+filepath.Base(f))
			continue
		}

		if cp.MerkleRoot == "" {
			result.Pass = false
			result.Reasons = append(result.Reasons, "Empty Merkle root in checkpoint: "+filepath.Base(f))
			continue
		}

		result.Metrics.Counts["checkpoints_verified"]++
		result.EvidencePaths = append(result.EvidencePaths, "condensation/"+filepath.Base(f))
	}

	return result
}
