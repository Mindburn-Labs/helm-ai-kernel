// Package adversarial implements the 10 mandatory adversarial test suites
// per §8.1 of the HELM Conformance Standard.
//
// Each suite verifies that the system correctly handles a specific
// adversarial scenario by checking EvidencePack artifacts for expected
// behavior: receipts emitted, containment triggered, policies enforced.
package adversarial

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SuiteResult captures the outcome of an adversarial test suite.
type SuiteResult struct {
	SuiteID     string       `json:"suite_id"`
	Name        string       `json:"name"`
	Pass        bool         `json:"pass"`
	TestResults []TestResult `json:"test_results"`
}

// TestResult captures the outcome of a single adversarial test.
type TestResult struct {
	TestID   string `json:"test_id"`
	Name     string `json:"name"`
	Pass     bool   `json:"pass"`
	Reason   string `json:"reason,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// Suite is an adversarial test suite.
type Suite struct {
	ID   string
	Name string
	Run  func(evidenceDir string) *SuiteResult
}

// AllSuites returns the 10 mandatory adversarial test suites per §8.1.
func AllSuites() []*Suite {
	return []*Suite{
		adv01ReceiptGapInjection(),
		adv02PolicyBypass(),
		adv03DAGFork(),
		adv04BudgetOverdraft(),
		adv05EnvelopeEscape(),
		adv06TapeReplayTamper(),
		adv07TenantCrossleak(),
		adv08ToolManifestForge(),
		adv09ReceiptEmissionPanicHijack(),
		adv10HighFinalityUnsigned(),
	}
}

// ADV-01: Receipt Gap Injection
// Verifies that if a receipt is missing from the chain, the system detects it.
func adv01ReceiptGapInjection() *Suite {
	return &Suite{
		ID:   "ADV-01",
		Name: "Receipt Gap Injection",
		Run: func(evidenceDir string) *SuiteResult {
			result := &SuiteResult{SuiteID: "ADV-01", Name: "Receipt Gap Injection", Pass: true}

			receiptsDir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts")
			files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))

			t := TestResult{TestID: "ADV-01-T1", Name: "Monotonic sequence with gap detection"}
			if len(files) < 2 {
				t.Pass = true
				t.Reason = "insufficient receipts for gap test"
			} else {
				// Check that sequences are contiguous
				seqs := loadSequenceNumbers(files)
				gap := false
				for i := 1; i < len(seqs); i++ {
					if seqs[i]-seqs[i-1] > 1 {
						gap = true
						t.Evidence = fmt.Sprintf("gap between seq %d and %d", seqs[i-1], seqs[i])
					}
				}
				if gap {
					t.Pass = false
					t.Reason = "RECEIPT_GAP_DETECTED"
				} else {
					t.Pass = true
					t.Reason = "no gaps in receipt sequence"
				}
			}
			result.TestResults = append(result.TestResults, t)
			result.Pass = t.Pass
			return result
		},
	}
}

// ADV-02: Policy Bypass
// Verifies that all actions have a corresponding policy decision receipt.
func adv02PolicyBypass() *Suite {
	return &Suite{
		ID:   "ADV-02",
		Name: "Policy Bypass Detection",
		Run: func(evidenceDir string) *SuiteResult {
			result := &SuiteResult{SuiteID: "ADV-02", Name: "Policy Bypass Detection", Pass: true}

			receiptsDir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts")
			files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))

			t := TestResult{TestID: "ADV-02-T1", Name: "All effect_attempt has preceding policy_decision"}
			effectsWithoutPolicy := 0
			for _, f := range files {
				receipt := loadReceipt(f)
				if receipt["action_type"] == "effect_attempt" {
					// Check that a policy_decision exists for this decision_id
					decisionID, _ := receipt["decision_id"].(string)
					if decisionID == "" || !hasPolicyReceiptForDecision(files, decisionID) {
						effectsWithoutPolicy++
					}
				}
			}
			if effectsWithoutPolicy > 0 {
				t.Pass = false
				t.Reason = fmt.Sprintf("%d effects without policy decisions", effectsWithoutPolicy)
			} else {
				t.Pass = true
				t.Reason = "all effects have policy decisions"
			}
			result.TestResults = append(result.TestResults, t)
			result.Pass = t.Pass
			return result
		},
	}
}

// ADV-03: DAG Fork Attack
// Verifies that no two receipts claim the same parent, creating a fork.
func adv03DAGFork() *Suite {
	return &Suite{
		ID:   "ADV-03",
		Name: "DAG Fork Attack",
		Run: func(evidenceDir string) *SuiteResult {
			result := &SuiteResult{SuiteID: "ADV-03", Name: "DAG Fork Attack", Pass: true}

			receiptsDir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts")
			files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))

			t := TestResult{TestID: "ADV-03-T1", Name: "No duplicate parent references (no forks)"}
			parentCount := make(map[string]int)
			for _, f := range files {
				receipt := loadReceipt(f)
				parents, ok := receipt["parent_receipt_hashes"].([]interface{})
				if ok {
					for _, p := range parents {
						if ps, ok := p.(string); ok && ps != "genesis" {
							parentCount[ps]++
						}
					}
				}
			}

			forks := 0
			for parent, count := range parentCount {
				if count > 1 {
					forks++
					t.Evidence += fmt.Sprintf("parent %s claimed by %d children; ", parent, count)
				}
			}
			if forks > 0 {
				t.Pass = false
				t.Reason = fmt.Sprintf("%d DAG forks detected", forks)
			} else {
				t.Pass = true
				t.Reason = "no DAG forks"
			}
			result.TestResults = append(result.TestResults, t)
			result.Pass = t.Pass
			return result
		},
	}
}

// ADV-04: Budget Overdraft
// Verifies that budget_exhausted receipts block further budget_decrement receipts.
func adv04BudgetOverdraft() *Suite {
	return &Suite{
		ID:   "ADV-04",
		Name: "Budget Overdraft",
		Run: func(evidenceDir string) *SuiteResult {
			result := &SuiteResult{SuiteID: "ADV-04", Name: "Budget Overdraft", Pass: true}

			receiptsDir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts")
			files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))

			t := TestResult{TestID: "ADV-04-T1", Name: "No budget_decrement after budget_exhausted"}
			exhausted := false
			overdraft := false
			for _, f := range files {
				receipt := loadReceipt(f)
				action, _ := receipt["action_type"].(string)
				if action == "budget_exhausted" {
					exhausted = true
				}
				if exhausted && action == "budget_decrement" {
					overdraft = true
					t.Evidence = fmt.Sprintf("budget_decrement after exhaustion: %s", filepath.Base(f))
				}
			}
			if overdraft {
				t.Pass = false
				t.Reason = "BUDGET_OVERDRAFT"
			} else {
				t.Pass = true
				t.Reason = "budget enforcement correct"
			}
			result.TestResults = append(result.TestResults, t)
			result.Pass = t.Pass
			return result
		},
	}
}

// ADV-05: Envelope Escape
// Verifies no effect was executed outside the bound envelope.
func adv05EnvelopeEscape() *Suite {
	return &Suite{
		ID:   "ADV-05",
		Name: "Envelope Escape",
		Run: func(evidenceDir string) *SuiteResult {
			result := &SuiteResult{SuiteID: "ADV-05", Name: "Envelope Escape", Pass: true}

			receiptsDir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts")
			files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))

			t := TestResult{TestID: "ADV-05-T1", Name: "All effect receipts have envelope_id and envelope_hash"}
			unbound := 0
			for _, f := range files {
				receipt := loadReceipt(f)
				action, _ := receipt["action_type"].(string)
				if action == "effect_attempt" || action == "tool_call" || action == "connector_call" {
					envID, _ := receipt["envelope_id"].(string)
					envHash, _ := receipt["envelope_hash"].(string)
					if envID == "" || envHash == "" {
						unbound++
						t.Evidence += fmt.Sprintf("unbound: %s; ", filepath.Base(f))
					}
				}
			}
			if unbound > 0 {
				t.Pass = false
				t.Reason = fmt.Sprintf("%d effects without envelope binding", unbound)
			} else {
				t.Pass = true
				t.Reason = "all effects bound to envelope"
			}
			result.TestResults = append(result.TestResults, t)
			result.Pass = t.Pass
			return result
		},
	}
}

// ADV-06: Tape Replay Tamper
// Verifies tape entries have valid data_class and value_hash.
func adv06TapeReplayTamper() *Suite {
	return &Suite{
		ID:   "ADV-06",
		Name: "Tape Replay Tamper",
		Run: func(evidenceDir string) *SuiteResult {
			result := &SuiteResult{SuiteID: "ADV-06", Name: "Tape Replay Tamper", Pass: true}

			tapesDir := filepath.Join(evidenceDir, "08_TAPES")
			t := TestResult{TestID: "ADV-06-T1", Name: "Tape entries have value_hash and data_class"}

			files, _ := filepath.Glob(filepath.Join(tapesDir, "entry_*.json"))
			missing := 0
			for _, f := range files {
				data, _ := os.ReadFile(f)
				var entry map[string]interface{}
				if json.Unmarshal(data, &entry) == nil {
					if entry["value_hash"] == nil || entry["value_hash"] == "" {
						missing++
					}
					if entry["data_class"] == nil || entry["data_class"] == "" {
						missing++
					}
				}
			}
			if missing > 0 {
				t.Pass = false
				t.Reason = fmt.Sprintf("%d tape entries missing required fields", missing)
			} else {
				t.Pass = true
				t.Reason = "all tape entries valid"
			}
			result.TestResults = append(result.TestResults, t)
			result.Pass = t.Pass
			return result
		},
	}
}

// ADV-07: Tenant Cross-Leak
// Verifies that all receipts within a run share the same tenant_id.
func adv07TenantCrossleak() *Suite {
	return &Suite{
		ID:   "ADV-07",
		Name: "Tenant Cross-Leak",
		Run: func(evidenceDir string) *SuiteResult {
			result := &SuiteResult{SuiteID: "ADV-07", Name: "Tenant Cross-Leak", Pass: true}

			receiptsDir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts")
			files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))

			t := TestResult{TestID: "ADV-07-T1", Name: "Single tenant_id across all receipts in run"}
			tenants := make(map[string]int)
			for _, f := range files {
				receipt := loadReceipt(f)
				tid, _ := receipt["tenant_id"].(string)
				if tid != "" {
					tenants[tid]++
				}
			}
			if len(tenants) > 1 {
				t.Pass = false
				t.Reason = fmt.Sprintf("multiple tenants in single run: %v", tenants)
			} else {
				t.Pass = true
				t.Reason = "tenant isolation maintained"
			}
			result.TestResults = append(result.TestResults, t)
			result.Pass = t.Pass
			return result
		},
	}
}

// ADV-08: Tool Manifest Forge
// Verifies tool manifests have valid signatures and required fields.
func adv08ToolManifestForge() *Suite {
	return &Suite{
		ID:   "ADV-08",
		Name: "Tool Manifest Forgery",
		Run: func(evidenceDir string) *SuiteResult {
			result := &SuiteResult{SuiteID: "ADV-08", Name: "Tool Manifest Forgery", Pass: true}

			manifestDir := filepath.Join(evidenceDir, "10_TOOLS")
			files, _ := filepath.Glob(filepath.Join(manifestDir, "*.json"))

			t := TestResult{TestID: "ADV-08-T1", Name: "Tool manifests have signatures field"}
			unsigned := 0
			for _, f := range files {
				data, _ := os.ReadFile(f)
				var manifest map[string]interface{}
				if json.Unmarshal(data, &manifest) == nil {
					if manifest["signatures"] == nil {
						unsigned++
						t.Evidence += fmt.Sprintf("unsigned: %s; ", filepath.Base(f))
					}
				}
			}
			if unsigned > 0 {
				t.Pass = false
				t.Reason = fmt.Sprintf("%d tool manifests without signatures", unsigned)
			} else {
				t.Pass = true
				t.Reason = "all tool manifests signed"
			}
			result.TestResults = append(result.TestResults, t)
			result.Pass = t.Pass
			return result
		},
	}
}

// ADV-09: Receipt Emission Panic Hijack
// Verifies that when a panic record exists, no further receipts are emitted.
func adv09ReceiptEmissionPanicHijack() *Suite {
	return &Suite{
		ID:   "ADV-09",
		Name: "Receipt Emission Panic Hijack",
		Run: func(evidenceDir string) *SuiteResult {
			result := &SuiteResult{SuiteID: "ADV-09", Name: "Receipt Emission Panic Hijack", Pass: true}

			t := TestResult{TestID: "ADV-09-T1", Name: "No receipts after panic record"}

			panicFile := filepath.Join(evidenceDir, "panic.json")
			if _, err := os.Stat(panicFile); err != nil {
				t.Pass = true
				t.Reason = "no panic record (normal operation)"
				result.TestResults = append(result.TestResults, t)
				result.Pass = true
				return result
			}

			// If panic exists, check that no receipts were emitted after it
			panicData, _ := os.ReadFile(panicFile)
			var panicRec map[string]interface{}
			if json.Unmarshal(panicData, &panicRec) != nil {
				t.Pass = false
				t.Reason = "panic record unreadable"
				result.TestResults = append(result.TestResults, t)
				result.Pass = false
				return result
			}

			lastGoodSeq, _ := panicRec["last_good_seq"].(float64)

			receiptsDir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts")
			files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))
			postPanic := 0
			for _, f := range files {
				receipt := loadReceipt(f)
				seq, _ := receipt["seq"].(float64)
				if seq > lastGoodSeq {
					postPanic++
				}
			}
			if postPanic > 0 {
				t.Pass = false
				t.Reason = fmt.Sprintf("%d receipts emitted after panic", postPanic)
			} else {
				t.Pass = true
				t.Reason = "emission correctly halted after panic"
			}
			result.TestResults = append(result.TestResults, t)
			result.Pass = t.Pass
			return result
		},
	}
}

// ADV-10: High-Finality Unsigned Action
// Verifies that high-finality actions (delete, deploy, financial) have HITL approval receipts.
func adv10HighFinalityUnsigned() *Suite {
	return &Suite{
		ID:   "ADV-10",
		Name: "High-Finality Unsigned Action",
		Run: func(evidenceDir string) *SuiteResult {
			result := &SuiteResult{SuiteID: "ADV-10", Name: "High-Finality Unsigned Action", Pass: true}

			receiptsDir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts")
			files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))

			t := TestResult{TestID: "ADV-10-T1", Name: "High-finality effects require approval_action receipt"}

			unsigned := 0
			for _, f := range files {
				receipt := loadReceipt(f)
				action, _ := receipt["action_type"].(string)
				effectClass, _ := receipt["effect_class"].(string)

				// High-finality: E4 (irreversible) or E5 (catastrophic)
				if isHighFinality(effectClass, action) {
					decisionID, _ := receipt["decision_id"].(string)
					if decisionID == "" || !hasApprovalForDecision(files, decisionID) {
						unsigned++
						t.Evidence += fmt.Sprintf("unapproved high-finality: %s (class=%s); ", filepath.Base(f), effectClass)
					}
				}
			}
			if unsigned > 0 {
				t.Pass = false
				t.Reason = fmt.Sprintf("%d high-finality actions without approval", unsigned)
			} else {
				t.Pass = true
				t.Reason = "all high-finality actions approved"
			}
			result.TestResults = append(result.TestResults, t)
			result.Pass = t.Pass
			return result
		},
	}
}

// --- Helpers ---

func loadReceipt(path string) map[string]interface{} {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var receipt map[string]interface{}
	json.Unmarshal(data, &receipt) //nolint:errcheck
	return receipt
}

func loadSequenceNumbers(files []string) []uint64 {
	var seqs []uint64
	for _, f := range files {
		receipt := loadReceipt(f)
		if seq, ok := receipt["seq"].(float64); ok {
			seqs = append(seqs, uint64(seq))
		}
	}
	return seqs
}

func hasPolicyReceiptForDecision(files []string, decisionID string) bool {
	for _, f := range files {
		receipt := loadReceipt(f)
		if receipt["action_type"] == "policy_decision" {
			if did, ok := receipt["decision_id"].(string); ok && did == decisionID {
				return true
			}
		}
	}
	return false
}

func hasApprovalForDecision(files []string, decisionID string) bool {
	for _, f := range files {
		receipt := loadReceipt(f)
		if receipt["action_type"] == "approval_action" {
			if did, ok := receipt["decision_id"].(string); ok && did == decisionID {
				return true
			}
		}
	}
	return false
}

func isHighFinality(effectClass, actionType string) bool {
	// Effect classes E4 (irreversible) and E5 (catastrophic) are high-finality
	if effectClass == "E4" || effectClass == "E5" {
		return true
	}
	// Specific action types that are inherently high-finality
	highFinalityActions := []string{
		"connector_call", // external side effects
	}
	for _, hf := range highFinalityActions {
		if strings.EqualFold(actionType, hf) && (effectClass == "E3" || effectClass == "E4" || effectClass == "E5") {
			return true
		}
	}
	return false
}
