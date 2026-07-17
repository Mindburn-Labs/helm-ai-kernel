package adversarial

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type coverageMutation struct {
	ID             string
	ExpectedTestID string
	Apply          func(string) bool
}

func mandatoryCoverageMutations() map[string]coverageMutation {
	return map[string]coverageMutation{
		"ADV-01": {ID: "receipt-sequence-gap/v1", ExpectedTestID: "ADV-01-T1", Apply: mutateReceiptSequenceGap},
		"ADV-02": {ID: "policy-decision-bypass/v1", ExpectedTestID: "ADV-02-T1", Apply: mutatePolicyBinding},
		"ADV-03": {ID: "proofgraph-dangling-parent/v1", ExpectedTestID: "ADV-03-T1", Apply: mutateProofGraphParent},
		"ADV-04": {ID: "budget-overdraft/v1", ExpectedTestID: "ADV-04-T1", Apply: mutateBudgetBoundary},
		"ADV-05": {ID: "envelope-binding-removal/v1", ExpectedTestID: "ADV-05-T1", Apply: mutateEnvelopeBinding},
		"ADV-06": {ID: "tape-value-hash-tamper/v1", ExpectedTestID: "ADV-06-T1", Apply: mutateTapeHash},
		"ADV-07": {ID: "cross-tenant-replay/v1", ExpectedTestID: "ADV-07-T1", Apply: mutateTenantBinding},
		"ADV-08": {ID: "unsigned-tool-manifest/v1", ExpectedTestID: "ADV-08-T1", Apply: mutateToolSignature},
		"ADV-09": {ID: "post-panic-receipt/v1", ExpectedTestID: "ADV-09-T1", Apply: mutatePanicBoundary},
		"ADV-10": {ID: "high-finality-approval-bypass/v1", ExpectedTestID: "ADV-10-T1", Apply: mutateApprovalBinding},
	}
}

func runCoverageMutation(evidenceDir string, suite *Suite, mutation coverageMutation) (bool, bool) {
	tempDir, err := os.MkdirTemp("", "helm-adversarial-mutation-*")
	if err != nil {
		return false, false
	}
	defer os.RemoveAll(tempDir) //nolint:errcheck

	mutantDir := filepath.Join(tempDir, "evidence-pack")
	if err := os.CopyFS(mutantDir, os.DirFS(evidenceDir)); err != nil {
		return false, false
	}
	if mutation.Apply == nil || mutation.ExpectedTestID == "" || !mutation.Apply(mutantDir) {
		return false, false
	}
	result := suite.Run(mutantDir)
	if result == nil || result.Pass {
		return true, false
	}
	for _, test := range result.TestResults {
		if test.TestID == mutation.ExpectedTestID && !test.Pass {
			return true, true
		}
	}
	return true, false
}

func mutateReceiptSequenceGap(evidenceDir string) bool {
	files := receiptFiles(evidenceDir)
	var targetPath string
	var target map[string]interface{}
	var maxSequence float64 = -1
	validSequences := 0
	for _, path := range files {
		receipt := loadReceipt(path)
		sequence, ok := receiptSequence(receipt)
		if !ok {
			continue
		}
		validSequences++
		if sequence > maxSequence {
			maxSequence = sequence
			targetPath = path
			target = receipt
		}
	}
	if validSequences < 2 || target == nil {
		return false
	}
	const maxExactJSONInteger = 1<<53 - 1
	if maxSequence < maxExactJSONInteger {
		target["seq"] = maxSequence + 1
	} else {
		target["seq"] = float64(0)
	}
	return writeMutationJSON(targetPath, target)
}

func mutatePolicyBinding(evidenceDir string) bool {
	return mutateFirstReceipt(evidenceDir, func(receipt map[string]interface{}) bool {
		action, _ := receipt["action_type"].(string)
		return isEffectAction(action)
	}, mutateDecisionID)
}

func mutateProofGraphParent(evidenceDir string) bool {
	return mutateFirstReceipt(evidenceDir, func(receipt map[string]interface{}) bool {
		sequence, ok := receiptSequence(receipt)
		return ok && sequence > 1
	}, func(receipt map[string]interface{}) {
		receipt["parent_receipt_hashes"] = []string{"sha256:helm-mutation-missing-parent"}
	})
}

func mutateBudgetBoundary(evidenceDir string) bool {
	type exhaustion struct {
		scope    string
		sequence float64
	}
	files := receiptFiles(evidenceDir)
	exhaustions := make([]exhaustion, 0)
	for _, path := range files {
		receipt := loadReceipt(path)
		if receipt["action_type"] != "budget_exhausted" {
			continue
		}
		sequence, ok := receiptSequence(receipt)
		if scope := budgetScope(receipt); ok && scope != "" {
			exhaustions = append(exhaustions, exhaustion{scope: scope, sequence: sequence})
		}
	}
	for _, path := range files {
		receipt := loadReceipt(path)
		if receipt["action_type"] != "budget_decrement" {
			continue
		}
		sequence, ok := receiptSequence(receipt)
		scope := budgetScope(receipt)
		if !ok || scope == "" {
			continue
		}
		for _, boundary := range exhaustions {
			if boundary.scope == scope && sequence < boundary.sequence {
				receipt["seq"] = boundary.sequence
				return writeMutationJSON(path, receipt)
			}
		}
	}
	return false
}

func mutateEnvelopeBinding(evidenceDir string) bool {
	return mutateFirstReceipt(evidenceDir, func(receipt map[string]interface{}) bool {
		action, _ := receipt["action_type"].(string)
		return isEffectAction(action)
	}, func(receipt map[string]interface{}) {
		delete(receipt, "envelope_hash")
	})
}

func mutateTapeHash(evidenceDir string) bool {
	files, _ := filepath.Glob(filepath.Join(evidenceDir, "08_TAPES", "entry_*.json"))
	for _, path := range files {
		entry := loadMutationJSON(path)
		if entry == nil || !validTapeEntry(entry) {
			continue
		}
		current, _ := entry["value_hash"].(string)
		entry["value_hash"] = differentMutationValue(current)
		return writeMutationJSON(path, entry)
	}
	return false
}

func mutateTenantBinding(evidenceDir string) bool {
	seenTenant := ""
	seenReceipts := 0
	return mutateFirstReceipt(evidenceDir, func(receipt map[string]interface{}) bool {
		tenant, _ := receipt["tenant_id"].(string)
		tenant = strings.TrimSpace(tenant)
		if tenant == "" {
			return false
		}
		seenReceipts++
		if seenTenant == "" {
			seenTenant = tenant
			return false
		}
		return seenReceipts >= 2
	}, func(receipt map[string]interface{}) {
		receipt["tenant_id"] = differentMutationValue(seenTenant)
	})
}

func mutateToolSignature(evidenceDir string) bool {
	for _, path := range toolManifestFiles(evidenceDir) {
		manifest := loadMutationJSON(path)
		if manifest == nil {
			continue
		}
		delete(manifest, "signatures")
		return writeMutationJSON(path, manifest)
	}
	return false
}

func mutatePanicBoundary(evidenceDir string) bool {
	maxSequence := float64(-1)
	for _, path := range receiptFiles(evidenceDir) {
		if sequence, ok := receiptSequence(loadReceipt(path)); ok && sequence > maxSequence {
			maxSequence = sequence
		}
	}
	if maxSequence < 1 {
		return false
	}
	for _, path := range panicEvidenceFiles(evidenceDir) {
		panicRecord := loadMutationJSON(path)
		if panicRecord == nil {
			continue
		}
		panicRecord["last_good_seq"] = maxSequence - 1
		return writeMutationJSON(path, panicRecord)
	}
	return false
}

func mutateApprovalBinding(evidenceDir string) bool {
	return mutateFirstReceipt(evidenceDir, func(receipt map[string]interface{}) bool {
		action, _ := receipt["action_type"].(string)
		effectClass, _ := receipt["effect_class"].(string)
		return isHighFinality(effectClass, action)
	}, mutateDecisionID)
}

func mutateDecisionID(receipt map[string]interface{}) {
	current, _ := receipt["decision_id"].(string)
	receipt["decision_id"] = differentMutationValue(current)
}

func mutateFirstReceipt(evidenceDir string, match func(map[string]interface{}) bool, mutate func(map[string]interface{})) bool {
	for _, path := range receiptFiles(evidenceDir) {
		receipt := loadReceipt(path)
		if receipt == nil || !match(receipt) {
			continue
		}
		mutate(receipt)
		return writeMutationJSON(path, receipt)
	}
	return false
}

func receiptFiles(evidenceDir string) []string {
	files, _ := filepath.Glob(filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts", "*.json"))
	return files
}

func loadMutationJSON(path string) map[string]interface{} {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var value map[string]interface{}
	if json.Unmarshal(data, &value) != nil {
		return nil
	}
	return value
}

func writeMutationJSON(path string, value map[string]interface{}) bool {
	data, err := json.Marshal(value)
	if err != nil {
		return false
	}
	return os.WriteFile(path, data, 0o600) == nil
}

func differentMutationValue(current string) string {
	return current + ":helm-mutation"
}
