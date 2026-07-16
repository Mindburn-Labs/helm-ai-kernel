// Package adversarial implements the 10 mandatory adversarial test suites
// per §8.1 of the HELM Conformance Standard.
// quantum_posture: campaign authorization and tool manifests use classical
// Ed25519 verification; no post-quantum assurance is claimed.
//
// Each suite verifies that the system correctly handles a specific
// adversarial scenario by checking EvidencePack artifacts for expected
// behavior: receipts emitted, containment triggered, policies enforced.
package adversarial

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
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

// VerificationOptions supplies trust roots from outside the candidate
// EvidencePack. A signature embedded in the pack can never establish trust.
type VerificationOptions struct {
	CampaignPublicKeyHex string
}

// CampaignKeyID validates an Ed25519 campaign root and returns its stable ID.
func CampaignKeyID(publicKeyHex string) (string, error) {
	publicKey, err := hex.DecodeString(strings.TrimSpace(publicKeyHex))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("campaign public key must be a %d-byte Ed25519 key encoded as hex", ed25519.PublicKeySize)
	}
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// AllSuites returns the 10 mandatory adversarial test suites per §8.1.
func AllSuites() []*Suite {
	return AllSuitesWithOptions(VerificationOptions{})
}

// AllSuitesWithOptions binds suites to an external campaign trust root.
func AllSuitesWithOptions(opts VerificationOptions) []*Suite {
	return []*Suite{
		adv01ReceiptGapInjection(),
		adv02PolicyBypass(opts),
		adv03DAGFork(),
		adv04BudgetOverdraft(),
		adv05EnvelopeEscape(),
		adv06TapeReplayTamper(),
		adv07TenantCrossleak(),
		adv08ToolManifestForge(opts),
		adv09ReceiptEmissionPanicHijack(),
		adv10HighFinalityUnsigned(opts),
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
			seqs := loadSequenceNumbers(files)
			t.Pass = len(seqs) == len(files)
			if !t.Pass {
				t.Evidence = "one or more receipts have a missing or invalid seq"
			} else if len(seqs) > 0 && seqs[0] != 1 {
				t.Pass = false
				t.Evidence = fmt.Sprintf("receipt sequence starts at %d instead of genesis sequence 1", seqs[0])
			}
			for i := 1; t.Pass && i < len(seqs); i++ {
				if seqs[i] <= seqs[i-1] || seqs[i]-seqs[i-1] != 1 {
					t.Pass = false
					t.Evidence = fmt.Sprintf("non-contiguous sequence between seq %d and %d", seqs[i-1], seqs[i])
				}
			}
			if t.Pass {
				t.Reason = "no gaps in receipt sequence"
			} else {
				t.Reason = "RECEIPT_GAP_DETECTED"
			}
			result.TestResults = append(result.TestResults, t)
			result.Pass = t.Pass
			return result
		},
	}
}

// ADV-02: Policy Bypass
// Verifies that all actions have a corresponding policy decision receipt.
func adv02PolicyBypass(opts VerificationOptions) *Suite {
	return &Suite{
		ID:   "ADV-02",
		Name: "Policy Bypass Detection",
		Run: func(evidenceDir string) *SuiteResult {
			result := &SuiteResult{SuiteID: "ADV-02", Name: "Policy Bypass Detection", Pass: true}

			receiptsDir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts")
			files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))

			t := TestResult{TestID: "ADV-02-T1", Name: "All effect actions have preceding policy_decision"}
			effectsWithoutPolicy := 0
			for _, f := range files {
				receipt := loadReceipt(f)
				action, _ := receipt["action_type"].(string)
				if isEffectAction(action) {
					decisionID, _ := receipt["decision_id"].(string)
					if decisionID == "" || !hasBoundAuthorizationReceipt(files, receipt, "policy_decision", opts) {
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
			exhausted := make(map[string]bool)
			overdraft := false
			for _, f := range files {
				receipt := loadReceipt(f)
				action, _ := receipt["action_type"].(string)
				scope := budgetScope(receipt)
				if scope == "" {
					continue
				}
				if exhausted[scope] && action == "budget_decrement" {
					overdraft = true
					t.Evidence = fmt.Sprintf("budget_decrement after exhaustion for %s: %s", scope, filepath.Base(f))
				}
				if action == "budget_exhausted" {
					exhausted[scope] = true
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
				data, err := os.ReadFile(f)
				var entry map[string]interface{}
				if err != nil || json.Unmarshal(data, &entry) != nil || !validTapeEntry(entry) {
					missing++
					t.Evidence += fmt.Sprintf("invalid: %s; ", filepath.Base(f))
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
			missingTenant := 0
			for _, f := range files {
				receipt := loadReceipt(f)
				tid, _ := receipt["tenant_id"].(string)
				if strings.TrimSpace(tid) == "" {
					missingTenant++
					continue
				}
				tenants[tid]++
			}
			if missingTenant > 0 {
				t.Pass = false
				t.Reason = fmt.Sprintf("%d receipts missing tenant_id", missingTenant)
			} else if len(tenants) > 1 {
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
func adv08ToolManifestForge(opts VerificationOptions) *Suite {
	return &Suite{
		ID:   "ADV-08",
		Name: "Tool Manifest Forgery",
		Run: func(evidenceDir string) *SuiteResult {
			result := &SuiteResult{SuiteID: "ADV-08", Name: "Tool Manifest Forgery", Pass: true}

			files := toolManifestFiles(evidenceDir)

			t := TestResult{TestID: "ADV-08-T1", Name: "Tool manifests verify under the campaign trust root"}
			unsigned := 0
			for _, f := range files {
				data, err := os.ReadFile(f)
				var manifest map[string]interface{}
				if err != nil || json.Unmarshal(data, &manifest) != nil || !verifyCampaignSignatures(manifest, "signatures", opts.CampaignPublicKeyHex) {
					unsigned++
					t.Evidence += fmt.Sprintf("invalid or unsigned: %s; ", filepath.Base(f))
				}
			}
			if unsigned > 0 {
				t.Pass = false
				t.Reason = fmt.Sprintf("%d tool manifests invalid or without signatures", unsigned)
			} else {
				t.Pass = true
				t.Reason = "all tool manifests cryptographically verified"
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

			panicFiles := panicEvidenceFiles(evidenceDir)
			if len(panicFiles) == 0 {
				t.Pass = true
				t.Reason = "no panic record (normal operation)"
				result.TestResults = append(result.TestResults, t)
				result.Pass = true
				return result
			}

			// If panic exists, check that no receipts were emitted after it
			var lastGoodSeq float64
			haveBoundary := false
			for _, panicFile := range panicFiles {
				panicData, err := os.ReadFile(panicFile)
				var panicRec map[string]interface{}
				if err != nil || json.Unmarshal(panicData, &panicRec) != nil {
					t.Pass = false
					t.Reason = "panic record unreadable"
					result.TestResults = append(result.TestResults, t)
					result.Pass = false
					return result
				}
				boundary, ok := panicRec["last_good_seq"].(float64)
				if !ok {
					t.Pass = false
					t.Reason = "panic record missing last_good_seq"
					result.TestResults = append(result.TestResults, t)
					result.Pass = false
					return result
				}
				if !haveBoundary || boundary < lastGoodSeq {
					lastGoodSeq = boundary
					haveBoundary = true
				}
			}

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
func adv10HighFinalityUnsigned(opts VerificationOptions) *Suite {
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
					if decisionID == "" || !hasBoundAuthorizationReceipt(files, receipt, "approval_action", opts) {
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

func toolManifestFiles(evidenceDir string) []string {
	// Strict EvidencePack verification recognizes adversarial-only tool
	// fixtures exclusively through this declared extension.
	canonical, _ := filepath.Glob(filepath.Join(evidenceDir, "99_EXT", "adversarial", "tools", "*.json"))
	return canonical
}

func panicEvidenceFiles(evidenceDir string) []string {
	canonical := filepath.Join(evidenceDir, "06_LOGS", "receipt_emission_panic.json")
	legacy := filepath.Join(evidenceDir, "panic.json")
	files := make([]string, 0, 2)
	if _, err := os.Stat(canonical); err == nil {
		files = append(files, canonical)
	}
	if _, err := os.Stat(legacy); err == nil {
		files = append(files, legacy)
	}
	return files
}

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
		if seq, ok := receiptSequence(receipt); ok {
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

func isEffectAction(action string) bool {
	return action == "effect_attempt" || action == "tool_call" || action == "connector_call"
}

func budgetScope(receipt map[string]interface{}) string {
	for _, key := range []string{"budget_id", "budget_snapshot_ref", "decision_id"} {
		if value, _ := receipt[key].(string); strings.TrimSpace(value) != "" {
			return key + ":" + strings.TrimSpace(value)
		}
	}
	return ""
}

func hasBoundAuthorizationReceipt(files []string, effect map[string]interface{}, actionType string, opts VerificationOptions) bool {
	receipts := make([]map[string]interface{}, 0, len(files))
	for _, path := range files {
		if receipt := loadReceipt(path); receipt != nil {
			receipts = append(receipts, receipt)
		}
	}
	return hasBoundAuthorization(receipts, effect, actionType, opts)
}

func hasBoundAuthorization(receipts []map[string]interface{}, effect map[string]interface{}, actionType string, opts VerificationOptions) bool {
	effectSeq, ok := receiptSequence(effect)
	if !ok || !hasNonEmptyString(effect, "decision_id") || !hasNonEmptyString(effect, "tenant_id") || !hasNonEmptyString(effect, "envelope_id") || !hasNonEmptyString(effect, "envelope_hash") {
		return false
	}
	for _, receipt := range receipts {
		if receipt["action_type"] != actionType || receipt["decision_id"] != effect["decision_id"] || receipt["tenant_id"] != effect["tenant_id"] || receipt["envelope_id"] != effect["envelope_id"] || receipt["envelope_hash"] != effect["envelope_hash"] {
			continue
		}
		if !authorizationReceiptAccepted(receipt, actionType) {
			continue
		}
		seq, sequenced := receiptSequence(receipt)
		if !sequenced || seq >= effectSeq || !receiptIsAncestor(receipts, effect, receipt) {
			continue
		}
		if verifyCampaignSignatures(receipt, "campaign_signatures", opts.CampaignPublicKeyHex) {
			return true
		}
	}
	return false
}

func authorizationReceiptAccepted(receipt map[string]interface{}, actionType string) bool {
	status, ok := receipt["status"].(string)
	if !ok {
		return false
	}
	status = strings.ToUpper(strings.TrimSpace(status))
	accepted := false
	switch actionType {
	case "policy_decision":
		accepted = status == "APPLIED" || status == "ALLOW" || status == "ALLOWED"
	case "approval_action":
		accepted = status == "APPLIED" || status == "APPROVED" || status == "ALLOW" || status == "ALLOWED"
	}
	if !accepted {
		return false
	}
	if verdict, exists := receipt["verdict"]; exists {
		value, valid := verdict.(string)
		if !valid {
			return false
		}
		value = strings.ToUpper(strings.TrimSpace(value))
		if value != "ALLOW" && value != "ALLOWED" && value != "APPROVE" && value != "APPROVED" {
			return false
		}
	}
	return true
}

func receiptIsAncestor(receipts []map[string]interface{}, descendant, ancestor map[string]interface{}) bool {
	ancestorID := receiptIdentity(ancestor)
	if ancestorID == "" {
		return false
	}
	index := make(map[string]map[string]interface{}, len(receipts)*2)
	for _, receipt := range receipts {
		if id, _ := receipt["receipt_id"].(string); id != "" {
			index[id] = receipt
		}
		if hash, _ := receipt["receipt_hash"].(string); hash != "" {
			index[hash] = receipt
		}
	}
	queue := receiptParentRefs(descendant)
	seen := map[string]bool{}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		if parent == ancestorID {
			return true
		}
		if seen[parent] {
			continue
		}
		seen[parent] = true
		if receipt := index[parent]; receipt != nil {
			queue = append(queue, receiptParentRefs(receipt)...)
		}
	}
	return false
}

func receiptIdentity(receipt map[string]interface{}) string {
	if value, _ := receipt["receipt_hash"].(string); value != "" {
		return value
	}
	value, _ := receipt["receipt_id"].(string)
	return value
}

func receiptParentRefs(receipt map[string]interface{}) []string {
	raw, _ := receipt["parent_receipt_hashes"].([]interface{})
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if value, _ := item.(string); value != "" && value != "genesis" {
			out = append(out, value)
		}
	}
	return out
}

func receiptSequence(receipt map[string]interface{}) (float64, bool) {
	seq, ok := receipt["seq"].(float64)
	return seq, ok && seq >= 0 && seq <= math.MaxUint64 && math.Trunc(seq) == seq
}

func hasNonEmptyString(value map[string]interface{}, key string) bool {
	raw, ok := value[key].(string)
	return ok && strings.TrimSpace(raw) != ""
}

func verifyCampaignSignatures(document map[string]interface{}, field, trustedPublicKeyHex string) bool {
	publicKey, err := hex.DecodeString(strings.TrimSpace(trustedPublicKeyHex))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	rawSignatures, ok := document[field].([]interface{})
	if !ok || len(rawSignatures) == 0 {
		return false
	}
	payload := make(map[string]interface{}, len(document)-1)
	for key, value := range document {
		if key != field {
			payload[key] = value
		}
	}
	canonical, err := canonicalize.JCS(payload)
	if err != nil {
		return false
	}
	wantKeyID, err := CampaignKeyID(trustedPublicKeyHex)
	if err != nil {
		return false
	}
	for _, raw := range rawSignatures {
		signature, ok := raw.(map[string]interface{})
		if !ok || signature["algorithm"] != "ed25519" || signature["key_id"] != wantKeyID {
			return false
		}
		signatureHex, _ := signature["signature"].(string)
		signatureBytes, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(signatureHex), "hex:"))
		if err != nil || len(signatureBytes) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(publicKey), canonical, signatureBytes) {
			return false
		}
	}
	return true
}

func validTapeEntry(entry map[string]interface{}) bool {
	valueHash, ok := entry["value_hash"].(string)
	if !ok || !hasNonEmptyString(entry, "data_class") {
		return false
	}
	encodedValue, present := entry["value"].(string)
	if !present {
		return false
	}
	value, err := base64.StdEncoding.DecodeString(encodedValue)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(value)
	return strings.EqualFold(strings.TrimPrefix(valueHash, "sha256:"), hex.EncodeToString(digest[:]))
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
