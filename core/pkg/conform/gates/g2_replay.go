package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G2Replay validates deterministic replay with VCR Tape per §G2.
type G2Replay struct{}

func (g *G2Replay) ID() string   { return "G2" }
func (g *G2Replay) Name() string { return "Deterministic Replay with VCR Tape" }

func (g *G2Replay) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	tapesDir := filepath.Join(ctx.EvidenceDir, "08_TAPES")
	diffsDir := filepath.Join(ctx.EvidenceDir, "05_DIFFS")

	// 1. Check tape_manifest.json exists
	manifestPath := filepath.Join(tapesDir, "tape_manifest.json")
	if !fileExists(manifestPath) {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonReplayTapeMiss)
		return result
	}
	result.EvidencePaths = append(result.EvidencePaths, "08_TAPES/tape_manifest.json")

	// 2. Check diffs directory — empty on PASS
	diffEntries, err := os.ReadDir(diffsDir)
	if err == nil && len(diffEntries) > 0 {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonReplayHashDivergence)
		result.EvidencePaths = append(result.EvidencePaths, "05_DIFFS/")
	}

	// 3. Check determinism_manifest.json
	detManifestPath := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "determinism_manifest.json")
	if fileExists(detManifestPath) {
		result.EvidencePaths = append(result.EvidencePaths, "02_PROOFGRAPH/determinism_manifest.json")

		data, err := os.ReadFile(detManifestPath)
		if err == nil {
			var dm map[string]any
			if json.Unmarshal(data, &dm) == nil {
				if liveHash, ok := dm["live_hash"].(string); ok {
					if replayHash, ok := dm["replay_hash"].(string); ok {
						if liveHash != replayHash {
							result.Pass = false
							result.Reasons = append(result.Reasons, conform.ReasonReplayHashDivergence)
						}
						result.Metrics.Counts["hash_comparisons"] = 1
					}
				}
			}
		}
	}

	// 4. Lamport clock monotonicity check (P0.3 enhancement)
	receiptsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts")
	if dirExists(receiptsDir) {
		receiptFiles, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))
		result.Metrics.Counts["receipt_files"] = len(receiptFiles)

		if len(receiptFiles) > 0 {
			var lastLamport float64
			monotonic := true
			for _, rf := range receiptFiles {
				data, err := os.ReadFile(rf)
				if err != nil {
					continue
				}
				var receipt map[string]any
				if json.Unmarshal(data, &receipt) != nil {
					continue
				}
				if lc, ok := receipt["lamport_clock"].(float64); ok {
					if lc < lastLamport {
						monotonic = false
					}
					lastLamport = lc
				}
			}
			if !monotonic {
				result.Pass = false
				result.Reasons = append(result.Reasons, "LAMPORT_NOT_MONOTONIC")
			}
			result.EvidencePaths = append(result.EvidencePaths, "02_PROOFGRAPH/receipts/")
		}
	}

	// 5. Policy decision hash cross-reference (P0.3 enhancement)
	decisionsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "decisions")
	if dirExists(decisionsDir) {
		decisionFiles, _ := filepath.Glob(filepath.Join(decisionsDir, "*.json"))
		result.Metrics.Counts["decision_records"] = len(decisionFiles)

		missingHashes := 0
		for _, df := range decisionFiles {
			data, err := os.ReadFile(df)
			if err != nil {
				continue
			}
			var dec map[string]any
			if json.Unmarshal(data, &dec) != nil {
				continue
			}
			// If a policy backend is specified, decision hash must be present
			if _, hasBE := dec["policy_backend"]; hasBE {
				if _, hasDH := dec["policy_decision_hash"]; !hasDH {
					missingHashes++
				}
			}
		}
		if missingHashes > 0 {
			result.Pass = false
			result.Reasons = append(result.Reasons, "POLICY_DECISION_HASH_MISSING")
			result.Metrics.Counts["missing_decision_hashes"] = missingHashes
		}
		result.EvidencePaths = append(result.EvidencePaths, "02_PROOFGRAPH/decisions/")
	}

	return result
}
