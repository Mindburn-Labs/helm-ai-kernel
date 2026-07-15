package adversarial

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// CoverageResult proves that the supplied EvidencePack contains enough
// positive-control artifacts to exercise every mandatory detector. It is
// separate from suite pass/fail: a missing artifact is incomplete coverage,
// never a successful adversarial result.
type CoverageResult struct {
	Pass          bool            `json:"pass"`
	CoveredSuites int             `json:"covered_suites"`
	MissingSuites int             `json:"missing_suites"`
	Checks        []CoverageCheck `json:"checks"`
}

// CoverageCheck records the source-owned minimum evidence for one suite.
type CoverageCheck struct {
	SuiteID       string `json:"suite_id"`
	Covered       bool   `json:"covered"`
	EvidenceCount int    `json:"evidence_count"`
	Reason        string `json:"reason"`
}

// EvaluateCoverage checks for positive controls before the adversarial
// detectors run. The canonical EvidencePack verifier is responsible for
// proving that these files are indexed, hashed, and sealed.
func EvaluateCoverage(evidenceDir string) CoverageResult {
	receiptFiles, _ := filepath.Glob(filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts", "*.json"))
	receipts := make([]map[string]interface{}, 0, len(receiptFiles))
	for _, path := range receiptFiles {
		receipts = append(receipts, loadReceipt(path))
	}

	checks := []CoverageCheck{
		receiptSequenceCoverage(receipts),
		policyDecisionCoverage(receipts),
		proofGraphParentCoverage(receipts),
		budgetBoundaryCoverage(receipts),
		envelopeBindingCoverage(receipts),
		tapeCoverage(evidenceDir),
		tenantCoverage(receipts),
		toolManifestCoverage(evidenceDir),
		panicBoundaryCoverage(evidenceDir),
		highFinalityApprovalCoverage(receipts),
	}
	result := CoverageResult{Pass: true, Checks: checks}
	for _, check := range checks {
		if check.Covered {
			result.CoveredSuites++
			continue
		}
		result.Pass = false
		result.MissingSuites++
	}
	return result
}

func receiptSequenceCoverage(receipts []map[string]interface{}) CoverageCheck {
	count := 0
	for _, receipt := range receipts {
		if _, ok := receipt["seq"].(float64); ok {
			count++
		}
	}
	return coverageCheck("ADV-01", count >= 2, count, "requires at least two sequenced receipts")
}

func policyDecisionCoverage(receipts []map[string]interface{}) CoverageCheck {
	count := 0
	for _, receipt := range receipts {
		if receipt["action_type"] != "effect_attempt" {
			continue
		}
		decisionID, _ := receipt["decision_id"].(string)
		if decisionID != "" && hasPolicyReceipt(receipts, decisionID) {
			count++
		}
	}
	return coverageCheck("ADV-02", count > 0, count, "requires an effect_attempt with a matching policy_decision")
}

func proofGraphParentCoverage(receipts []map[string]interface{}) CoverageCheck {
	count := 0
	for _, receipt := range receipts {
		parents, _ := receipt["parent_receipt_hashes"].([]interface{})
		for _, rawParent := range parents {
			parent, _ := rawParent.(string)
			if parent != "" && parent != "genesis" {
				count++
			}
		}
	}
	return coverageCheck("ADV-03", count > 0, count, "requires at least one non-genesis parent edge")
}

func budgetBoundaryCoverage(receipts []map[string]interface{}) CoverageCheck {
	var exhaustedAt float64
	for _, receipt := range receipts {
		if receipt["action_type"] != "budget_exhausted" {
			continue
		}
		seq, ok := receipt["seq"].(float64)
		if ok && (exhaustedAt == 0 || seq < exhaustedAt) {
			exhaustedAt = seq
		}
	}
	count := 0
	if exhaustedAt > 0 {
		for _, receipt := range receipts {
			seq, ok := receipt["seq"].(float64)
			if ok && seq < exhaustedAt && receipt["action_type"] == "budget_decrement" {
				count++
			}
		}
	}
	return coverageCheck("ADV-04", count > 0, count, "requires budget_decrement followed by budget_exhausted")
}

func envelopeBindingCoverage(receipts []map[string]interface{}) CoverageCheck {
	count := 0
	for _, receipt := range receipts {
		action, _ := receipt["action_type"].(string)
		if action != "effect_attempt" && action != "tool_call" && action != "connector_call" {
			continue
		}
		envelopeID, _ := receipt["envelope_id"].(string)
		envelopeHash, _ := receipt["envelope_hash"].(string)
		if envelopeID != "" && envelopeHash != "" {
			count++
		}
	}
	return coverageCheck("ADV-05", count > 0, count, "requires at least one envelope-bound effect")
}

func tapeCoverage(evidenceDir string) CoverageCheck {
	files, _ := filepath.Glob(filepath.Join(evidenceDir, "08_TAPES", "entry_*.json"))
	count := 0
	for _, path := range files {
		var entry map[string]interface{}
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &entry) != nil {
			continue
		}
		valueHash, _ := entry["value_hash"].(string)
		dataClass, _ := entry["data_class"].(string)
		if valueHash != "" && dataClass != "" {
			count++
		}
	}
	return coverageCheck("ADV-06", count > 0, count, "requires at least one valid replay tape entry")
}

func tenantCoverage(receipts []map[string]interface{}) CoverageCheck {
	count := 0
	for _, receipt := range receipts {
		if tenantID, _ := receipt["tenant_id"].(string); tenantID != "" {
			count++
		}
	}
	return coverageCheck("ADV-07", count > 0, count, "requires tenant-bound receipts")
}

func toolManifestCoverage(evidenceDir string) CoverageCheck {
	files := toolManifestFiles(evidenceDir)
	count := 0
	for _, path := range files {
		var manifest map[string]interface{}
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &manifest) != nil {
			continue
		}
		switch signatures := manifest["signatures"].(type) {
		case []interface{}:
			if len(signatures) > 0 {
				count++
			}
		case string:
			if signatures != "" {
				count++
			}
		}
	}
	return coverageCheck("ADV-08", count > 0, count, "requires a tool manifest with a non-empty signatures field")
}

func panicBoundaryCoverage(evidenceDir string) CoverageCheck {
	data, err := os.ReadFile(panicEvidencePath(evidenceDir))
	if err != nil {
		return coverageCheck("ADV-09", false, 0, "requires a readable panic boundary record")
	}
	var panicRecord map[string]interface{}
	if json.Unmarshal(data, &panicRecord) != nil {
		return coverageCheck("ADV-09", false, 0, "requires a readable panic boundary record")
	}
	_, ok := panicRecord["last_good_seq"].(float64)
	return coverageCheck("ADV-09", ok, boolCount(ok), "requires a readable panic boundary record")
}

func highFinalityApprovalCoverage(receipts []map[string]interface{}) CoverageCheck {
	count := 0
	for _, receipt := range receipts {
		action, _ := receipt["action_type"].(string)
		effectClass, _ := receipt["effect_class"].(string)
		if !isHighFinality(effectClass, action) {
			continue
		}
		decisionID, _ := receipt["decision_id"].(string)
		if decisionID != "" && hasApprovalReceipt(receipts, decisionID) {
			count++
		}
	}
	return coverageCheck("ADV-10", count > 0, count, "requires a high-finality action with a matching approval_action")
}

func hasPolicyReceipt(receipts []map[string]interface{}, decisionID string) bool {
	for _, receipt := range receipts {
		if receipt["action_type"] == "policy_decision" && receipt["decision_id"] == decisionID {
			return true
		}
	}
	return false
}

func hasApprovalReceipt(receipts []map[string]interface{}, decisionID string) bool {
	for _, receipt := range receipts {
		if receipt["action_type"] == "approval_action" && receipt["decision_id"] == decisionID {
			return true
		}
	}
	return false
}

func coverageCheck(suiteID string, covered bool, count int, requirement string) CoverageCheck {
	reason := "covered: " + requirement
	if !covered {
		reason = "missing: " + requirement
	}
	return CoverageCheck{SuiteID: suiteID, Covered: covered, EvidenceCount: count, Reason: reason}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}
