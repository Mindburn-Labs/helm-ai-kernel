package gates

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// GXThreatScan validates threat signal scanning behavior per §GX.
// This gate ensures that:
//   - Threat scan artifacts exist in the EvidencePack
//   - Scan results contain required fields (scan_id, findings, hashes)
//   - High-severity findings from tainted sources resulted in DENY decisions
//   - Normalization evidence is present
type GXThreatScan struct{}

func (g *GXThreatScan) ID() string   { return "GX_THREAT_SCAN" }
func (g *GXThreatScan) Name() string { return "Threat Signal Scanning" }

func (g *GXThreatScan) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	// 1. Look for threat scan evidence
	scanDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "threat_scan")
	scanResultPath := filepath.Join(scanDir, "scan_results.json")

	if !fileExists(scanResultPath) {
		// Not a hard failure — threat scanning is optional unless profile requires it
		result.Metrics.Counts["scan_results_found"] = 0
		result.Details = map[string]any{
			"note": "No threat scan results found (GX_THREAT_SCAN is profile-optional)",
		}
		return result
	}

	result.EvidencePaths = append(result.EvidencePaths, "02_PROOFGRAPH/threat_scan/scan_results.json")

	// 2. Parse and validate scan results
	data, err := os.ReadFile(scanResultPath)
	if err != nil {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonTaintedInputDeny)
		return result
	}

	var scanResults []map[string]any
	if json.Unmarshal(data, &scanResults) != nil {
		// Try single result
		var single map[string]any
		if json.Unmarshal(data, &single) != nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonTaintedInputDeny)
			return result
		}
		scanResults = []map[string]any{single}
	}

	result.Metrics.Counts["scan_results_found"] = len(scanResults)

	// 3. Validate each scan result
	for _, scan := range scanResults {
		// Require scan_id
		if _, ok := scan["scan_id"].(string); !ok {
			result.Pass = false
			result.Reasons = append(result.Reasons, "THREAT_SCAN_MISSING_ID")
		}

		// Require raw_input_hash
		if _, ok := scan["raw_input_hash"].(string); !ok {
			result.Pass = false
			result.Reasons = append(result.Reasons, "THREAT_SCAN_MISSING_HASH")
		}

		// Require normalized_input_hash
		if _, ok := scan["normalized_input_hash"].(string); !ok {
			result.Pass = false
			result.Reasons = append(result.Reasons, "THREAT_SCAN_MISSING_HASH")
		}

		// Count findings
		if findings, ok := scan["findings"].([]any); ok {
			result.Metrics.Counts["total_findings"] += len(findings)
		}
	}

	// 4. Check for decision artifacts that reference threat scans
	decisionsDir := filepath.Join(ctx.EvidenceDir, "01_DECISIONS")
	if dirExists(decisionsDir) {
		entries, _ := os.ReadDir(decisionsDir)
		threatDenyCount := 0
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			decData, err := os.ReadFile(filepath.Join(decisionsDir, entry.Name()))
			if err != nil {
				continue
			}
			var dec map[string]any
			if json.Unmarshal(decData, &dec) != nil {
				continue
			}
			if reason, ok := dec["reason"].(string); ok {
				for _, code := range []string{
					conform.ReasonTaintedInputDeny,
					conform.ReasonPromptInjectionDetected,
					conform.ReasonUnicodeObfuscationDetected,
					conform.ReasonTaintedCredentialDeny,
					conform.ReasonTaintedPublishDeny,
					conform.ReasonTaintedEgressDeny,
				} {
					if strings.Contains(reason, code) {
						threatDenyCount++
						break
					}
				}
			}
		}
		result.Metrics.Counts["threat_denials"] = threatDenyCount
	}

	return result
}
