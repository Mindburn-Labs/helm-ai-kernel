package adversarial

// quantum_posture: campaign authorization uses classical Ed25519 verification;
// no post-quantum assurance is claimed.

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// CoverageResult proves both that the supplied EvidencePack contains a valid
// positive control and that every mandatory detector rejects its deterministic
// negative mutation. It is separate from suite pass/fail: a missing control or
// an accepted mutation is incomplete coverage, never a successful result.
type CoverageResult struct {
	Pass          bool            `json:"pass"`
	CoveredSuites int             `json:"covered_suites"`
	MissingSuites int             `json:"missing_suites"`
	Checks        []CoverageCheck `json:"checks"`
}

// CoverageCheck records the source-owned minimum evidence for one suite.
type CoverageCheck struct {
	SuiteID          string `json:"suite_id"`
	Covered          bool   `json:"covered"`
	EvidenceCount    int    `json:"evidence_count"`
	MutationID       string `json:"mutation_id"`
	MutationApplied  bool   `json:"mutation_applied"`
	MutationRejected bool   `json:"mutation_rejected"`
	Reason           string `json:"reason"`
}

// EvaluateCoverage checks positive controls and detector-rejection mutations.
// The canonical EvidencePack verifier is responsible for proving that the
// source files are indexed, hashed, and sealed before this function is called.
func EvaluateCoverage(evidenceDir string, opts VerificationOptions) CoverageResult {
	return EvaluateCoverageWithOptions(evidenceDir, opts)
}

// EvaluateCoverageWithOptions proves positive controls using externally rooted
// cryptographic evidence, then copies and mutates the pack so each detector's
// negative path is exercised without modifying the source EvidencePack.
func EvaluateCoverageWithOptions(evidenceDir string, opts VerificationOptions) CoverageResult {
	receiptFiles, _ := filepath.Glob(filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts", "*.json"))
	receipts := make([]map[string]interface{}, 0, len(receiptFiles))
	for _, path := range receiptFiles {
		receipts = append(receipts, loadReceipt(path))
	}

	checks := []CoverageCheck{
		receiptSequenceCoverage(receipts),
		policyDecisionCoverage(receipts, opts),
		proofGraphParentCoverage(receipts),
		budgetBoundaryCoverage(receipts),
		envelopeBindingCoverage(receipts),
		tapeCoverage(evidenceDir),
		tenantCoverage(receipts),
		toolManifestCoverage(evidenceDir, opts),
		panicBoundaryCoverage(evidenceDir),
		highFinalityApprovalCoverage(receipts, opts),
	}
	suites := AllSuitesWithOptions(opts)
	suitesByID := make(map[string]*Suite, len(suites))
	for _, suite := range suites {
		suitesByID[suite.ID] = suite
	}
	mutations := mandatoryCoverageMutations()
	for index := range checks {
		check := &checks[index]
		mutation, mutationExists := mutations[check.SuiteID]
		check.MutationID = mutation.ID
		if !check.Covered {
			continue
		}
		suite, suiteExists := suitesByID[check.SuiteID]
		if !mutationExists || !suiteExists {
			check.Covered = false
			check.Reason = "missing: mandatory detector mutation is not registered"
			continue
		}
		check.MutationApplied, check.MutationRejected = runCoverageMutation(evidenceDir, suite, mutation)
		switch {
		case !check.MutationApplied:
			check.Covered = false
			check.Reason = "missing: deterministic mutation could not be applied to the positive control"
		case !check.MutationRejected:
			check.Covered = false
			check.Reason = "missing: detector accepted deterministic mutation " + mutation.ID
		default:
			check.Reason += "; detector rejected mutation " + mutation.ID
		}
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
		if _, ok := receiptSequence(receipt); ok {
			count++
		}
	}
	return coverageCheck("ADV-01", count >= 2, count, "requires at least two sequenced receipts")
}

func policyDecisionCoverage(receipts []map[string]interface{}, opts VerificationOptions) CoverageCheck {
	count := 0
	for _, receipt := range receipts {
		action, _ := receipt["action_type"].(string)
		if !isEffectAction(action) {
			continue
		}
		decisionID, _ := receipt["decision_id"].(string)
		if decisionID != "" && hasBoundAuthorization(receipts, receipt, "policy_decision", opts) {
			count++
		}
	}
	return coverageCheck("ADV-02", count > 0, count, "requires an effect action with a preceding, ancestor-linked, envelope-bound, trusted policy_decision")
}

func proofGraphParentCoverage(receipts []map[string]interface{}) CoverageCheck {
	analysis := analyzeReceiptProofGraph(receipts, nil)
	covered := analysis.causalEdges > 0 && analysis.forks == 0 && analysis.invalidParents == 0 && analysis.genesisClaims == 1 && analysis.cycles == 0
	return coverageCheck("ADV-03", covered, analysis.causalEdges, "requires a valid single-root connected proof graph with at least one causal non-genesis edge")
}

func budgetBoundaryCoverage(receipts []map[string]interface{}) CoverageCheck {
	exhaustedAt := make(map[string][]float64)
	for _, receipt := range receipts {
		if receipt["action_type"] != "budget_exhausted" {
			continue
		}
		scope := budgetScope(receipt)
		seq, ok := receiptSequence(receipt)
		if scope != "" && ok {
			exhaustedAt[scope] = append(exhaustedAt[scope], seq)
		}
	}
	count := 0
	for _, receipt := range receipts {
		if receipt["action_type"] != "budget_decrement" {
			continue
		}
		scope := budgetScope(receipt)
		seq, ok := receiptSequence(receipt)
		if scope == "" || !ok {
			continue
		}
		for _, boundary := range exhaustedAt[scope] {
			if seq < boundary {
				count++
				break
			}
		}
	}
	return coverageCheck("ADV-04", count > 0, count, "requires budget_decrement followed by budget_exhausted for the same explicit budget scope")
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
		if validTapeEntry(entry) {
			count++
		}
	}
	return coverageCheck("ADV-06", count > 0, count, "requires a replay tape entry whose value_hash matches its decoded value")
}

func tenantCoverage(receipts []map[string]interface{}) CoverageCheck {
	count := 0
	for _, receipt := range receipts {
		if tenantID, _ := receipt["tenant_id"].(string); tenantID != "" {
			count++
		}
	}
	return coverageCheck("ADV-07", count >= 2, count, "requires at least two tenant-bound receipts")
}

func toolManifestCoverage(evidenceDir string, opts VerificationOptions) CoverageCheck {
	files := toolManifestFiles(evidenceDir)
	count := 0
	for _, path := range files {
		var manifest map[string]interface{}
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &manifest) != nil {
			continue
		}
		if campaignBindingMatches(manifest, opts) && verifyCampaignSignatures(manifest, "signatures", campaignToolManifestSignatureDomain, opts.CampaignPublicKeyHex) {
			count++
		}
	}
	return coverageCheck("ADV-08", count > 0, count, "requires a canonical tool manifest signed by the external campaign trust root")
}

func panicBoundaryCoverage(evidenceDir string) CoverageCheck {
	files := panicEvidenceFiles(evidenceDir)
	if len(files) == 0 {
		return coverageCheck("ADV-09", false, 0, "requires a readable panic boundary record")
	}
	count := 0
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return coverageCheck("ADV-09", false, count, "requires every present panic boundary record to be readable")
		}
		var panicRecord map[string]interface{}
		if json.Unmarshal(data, &panicRecord) != nil {
			return coverageCheck("ADV-09", false, count, "requires every present panic boundary record to be readable")
		}
		if _, ok := receiptSequence(map[string]interface{}{"seq": panicRecord["last_good_seq"]}); !ok {
			return coverageCheck("ADV-09", false, count, "requires every present panic boundary record to contain last_good_seq")
		}
		count++
	}
	return coverageCheck("ADV-09", true, count, "requires every present panic boundary record to be readable")
}

func highFinalityApprovalCoverage(receipts []map[string]interface{}, opts VerificationOptions) CoverageCheck {
	count := 0
	for _, receipt := range receipts {
		action, _ := receipt["action_type"].(string)
		effectClass, _ := receipt["effect_class"].(string)
		if !isHighFinality(effectClass, action) {
			continue
		}
		decisionID, _ := receipt["decision_id"].(string)
		if decisionID != "" && hasBoundAuthorization(receipts, receipt, "approval_action", opts) {
			count++
		}
	}
	return coverageCheck("ADV-10", count > 0, count, "requires a high-finality action with a preceding, ancestor-linked, envelope-bound, trusted approval_action")
}

func coverageCheck(suiteID string, covered bool, count int, requirement string) CoverageCheck {
	reason := "covered: " + requirement
	if !covered {
		reason = "missing: " + requirement
	}
	return CoverageCheck{SuiteID: suiteID, Covered: covered, EvidenceCount: count, Reason: reason}
}
