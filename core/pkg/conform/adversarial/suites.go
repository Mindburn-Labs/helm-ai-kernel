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
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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
	CampaignPublicKeyHex       string
	CampaignID                 string
	RunID                      string
	VerifiedEvidenceIndexHash  string
	VerifiedEvidenceMerkleRoot string
	VerifiedEvidenceEntryCount int
	// AllowVerifiedConformanceSignature authorizes omission of the detached
	// conformance signature from the detector workspace only after the caller
	// has verified it against an external trusted key. It never establishes
	// campaign trust and is never consumed by adversarial detectors.
	AllowVerifiedConformanceSignature bool
}

const (
	campaignReceiptSignatureDomain      = "helm.bounty.receipt-signature/v1"
	campaignToolManifestSignatureDomain = "helm.bounty.tool-manifest-signature/v1"
)

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

			t := TestResult{TestID: "ADV-03-T1", Name: "No duplicate, dangling, or self parent references"}
			receipts := make([]map[string]interface{}, 0, len(files))
			for _, f := range files {
				receipts = append(receipts, loadReceipt(f))
			}
			analysis := analyzeReceiptProofGraph(receipts, files)
			t.Evidence = analysis.evidence
			if analysis.forks > 0 || analysis.invalidParents > 0 || analysis.genesisClaims != 1 || analysis.cycles > 0 {
				t.Pass = false
				t.Reason = fmt.Sprintf(
					"%d DAG forks detected; %d invalid parent references; %d genesis roots detected; %d DAG cycles detected",
					analysis.forks,
					analysis.invalidParents,
					analysis.genesisClaims,
					analysis.cycles,
				)
			} else {
				t.Pass = true
				t.Reason = "single-root connected proof graph with no DAG forks"
			}
			result.TestResults = append(result.TestResults, t)
			result.Pass = t.Pass
			return result
		},
	}
}

type receiptProofGraphAnalysis struct {
	causalEdges    int
	forks          int
	invalidParents int
	genesisClaims  int
	cycles         int
	evidence       string
}

// analyzeReceiptProofGraph validates the whole proof graph, not just the
// existence of one good edge. A valid pack has exactly one genesis claim on
// sequence 1, and every later receipt has at least one resolvable, strictly
// earlier parent. Those invariants make disconnected components impossible.
func analyzeReceiptProofGraph(receipts []map[string]interface{}, files []string) receiptProofGraphAnalysis {
	analysis := receiptProofGraphAnalysis{}
	if len(receipts) == 0 {
		analysis.invalidParents++
		analysis.evidence = "proof graph has no receipts; "
		return analysis
	}

	referenceIndex := receiptReferenceIndex(receipts)
	receiptsByIdentity := make(map[string]map[string]interface{}, len(receipts))
	for _, receipt := range receipts {
		if identity := receiptIdentity(receipt); identity != "" {
			receiptsByIdentity[identity] = receipt
		}
	}

	// Reject ambiguous aliases even when no edge happens to reference them.
	// Otherwise a later verifier could resolve the same receipt_id differently.
	ambiguousReferences := make(map[string]bool)
	for index, receipt := range receipts {
		for _, key := range []string{"receipt_id", "receipt_hash"} {
			reference, _ := receipt[key].(string)
			reference = strings.TrimSpace(reference)
			if reference == "" || referenceIndex[reference] != "" || ambiguousReferences[reference] {
				continue
			}
			ambiguousReferences[reference] = true
			analysis.invalidParents++
			analysis.evidence += fmt.Sprintf("ambiguous receipt reference %s in %s; ", reference, receiptFileLabel(files, index))
		}
	}

	parentCount := make(map[string]int)
	graph := make(map[string][]string, len(receipts))
	for index, receipt := range receipts {
		fileLabel := receiptFileLabel(files, index)
		child := receiptIdentity(receipt)
		childSeq, childSequenced := receiptSequence(receipt)
		if child == "" {
			analysis.invalidParents++
			analysis.evidence += fmt.Sprintf("missing receipt identity in %s; ", fileLabel)
		}
		if !childSequenced {
			analysis.invalidParents++
			analysis.evidence += fmt.Sprintf("invalid receipt sequence in %s; ", fileLabel)
		}

		parents, ok := receipt["parent_receipt_hashes"].([]interface{})
		if !ok || len(parents) == 0 {
			analysis.invalidParents++
			analysis.evidence += fmt.Sprintf("missing or empty parent_receipt_hashes in %s; ", fileLabel)
			continue
		}

		genesisParents := 0
		validNonGenesisParents := 0
		seenParentTargets := make(map[string]bool, len(parents))
		for _, parentValue := range parents {
			parentReference, valid := parentValue.(string)
			parentReference = strings.TrimSpace(parentReference)
			if !valid || parentReference == "" {
				analysis.invalidParents++
				analysis.evidence += fmt.Sprintf("invalid parent in %s; ", fileLabel)
				continue
			}
			if parentReference == "genesis" {
				analysis.genesisClaims++
				genesisParents++
				if seenParentTargets[parentReference] {
					analysis.invalidParents++
					analysis.evidence += fmt.Sprintf("duplicate genesis parent in %s; ", fileLabel)
					continue
				}
				seenParentTargets[parentReference] = true
				continue
			}

			parentTarget, exists := referenceIndex[parentReference]
			parentReceipt := receiptsByIdentity[parentTarget]
			parentSeq, parentSequenced := receiptSequence(parentReceipt)
			if !exists || parentTarget == "" || child == "" || parentTarget == child || !childSequenced || !parentSequenced || parentSeq >= childSeq {
				analysis.invalidParents++
				analysis.evidence += fmt.Sprintf("dangling, self, or non-causal parent %s in %s; ", parentReference, fileLabel)
				continue
			}
			if seenParentTargets[parentTarget] {
				analysis.invalidParents++
				analysis.evidence += fmt.Sprintf("duplicate parent target %s in %s; ", parentTarget, fileLabel)
				continue
			}
			seenParentTargets[parentTarget] = true
			validNonGenesisParents++
			analysis.causalEdges++
			parentCount[parentTarget]++
			graph[child] = append(graph[child], parentTarget)
		}

		if !childSequenced {
			continue
		}
		if childSeq == 1 {
			if genesisParents != 1 || validNonGenesisParents != 0 || len(parents) != 1 {
				analysis.invalidParents++
				analysis.evidence += fmt.Sprintf("sequence 1 must have exactly one genesis parent in %s; ", fileLabel)
			}
			continue
		}
		if genesisParents != 0 || validNonGenesisParents == 0 {
			analysis.invalidParents++
			analysis.evidence += fmt.Sprintf("non-root receipt lacks a valid earlier parent in %s; ", fileLabel)
		}
	}

	parents := make([]string, 0, len(parentCount))
	for parent := range parentCount {
		parents = append(parents, parent)
	}
	sort.Strings(parents)
	for _, parent := range parents {
		count := parentCount[parent]
		if count > 1 {
			analysis.forks++
			analysis.evidence += fmt.Sprintf("parent %s claimed by %d children; ", parent, count)
		}
	}
	if analysis.genesisClaims != 1 {
		analysis.evidence += fmt.Sprintf("proof graph contains %d genesis claims; ", analysis.genesisClaims)
	}
	if receiptGraphHasCycle(graph) {
		analysis.cycles = 1
		analysis.evidence += "receipt parent graph contains a cycle; "
	}
	return analysis
}

func receiptFileLabel(files []string, index int) string {
	if index >= 0 && index < len(files) && files[index] != "" {
		return filepath.Base(files[index])
	}
	return fmt.Sprintf("receipt[%d]", index)
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
			overdraft := false
			invalidBoundary := false
			exhaustedAt := make(map[string][]float64)
			var decrements []struct {
				scope string
				seq   float64
				file  string
			}
			for _, f := range files {
				receipt := loadReceipt(f)
				action, _ := receipt["action_type"].(string)
				if action != "budget_exhausted" && action != "budget_decrement" {
					continue
				}
				scope := budgetScope(receipt)
				seq, ok := receiptSequence(receipt)
				if scope == "" || !ok {
					invalidBoundary = true
					t.Evidence += fmt.Sprintf("unscoped or unsequenced budget receipt: %s; ", filepath.Base(f))
					continue
				}
				if action == "budget_exhausted" {
					exhaustedAt[scope] = append(exhaustedAt[scope], seq)
				} else {
					decrements = append(decrements, struct {
						scope string
						seq   float64
						file  string
					}{scope: scope, seq: seq, file: filepath.Base(f)})
				}
			}
			for _, decrement := range decrements {
				for _, boundary := range exhaustedAt[decrement.scope] {
					if decrement.seq >= boundary {
						overdraft = true
						t.Evidence += fmt.Sprintf("budget_decrement seq %.0f after exhaustion seq %.0f for %s: %s; ", decrement.seq, boundary, decrement.scope, decrement.file)
					}
				}
			}
			if invalidBoundary {
				t.Pass = false
				t.Reason = "budget boundary contains an unscoped or unsequenced receipt"
			} else if overdraft {
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
				tenantIDs := make([]string, 0, len(tenants))
				for tenantID := range tenants {
					tenantIDs = append(tenantIDs, tenantID)
				}
				sort.Strings(tenantIDs)
				t.Reason = fmt.Sprintf("multiple tenants in single run: %s", strings.Join(tenantIDs, ","))
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
			legacyFiles, _ := filepath.Glob(filepath.Join(evidenceDir, "10_TOOLS", "*.json"))

			t := TestResult{TestID: "ADV-08-T1", Name: "Tool manifests verify under the campaign trust root"}
			unsigned := len(legacyFiles)
			for _, f := range legacyFiles {
				t.Evidence += fmt.Sprintf("undeclared legacy tool manifest: %s; ", filepath.Base(f))
			}
			for _, f := range files {
				data, err := os.ReadFile(f)
				var manifest map[string]interface{}
				if err != nil || json.Unmarshal(data, &manifest) != nil || !campaignBindingMatches(manifest, opts) || !verifyCampaignSignatures(manifest, "signatures", campaignToolManifestSignatureDomain, opts.CampaignPublicKeyHex) {
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
				boundary, ok := receiptSequence(map[string]interface{}{"seq": panicRec["last_good_seq"]})
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
			invalidSequence := 0
			for _, f := range files {
				receipt := loadReceipt(f)
				seq, ok := receiptSequence(receipt)
				if !ok {
					invalidSequence++
					continue
				}
				if seq > lastGoodSeq {
					postPanic++
				}
			}
			if invalidSequence > 0 {
				t.Pass = false
				t.Reason = fmt.Sprintf("%d receipts have invalid sequence after panic boundary", invalidSequence)
			} else if postPanic > 0 {
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
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
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
	// Proof receipts bind budget effects to the canonical budget snapshot.
	// Alternate identifiers are deliberately not accepted: allowing different
	// fallback fields on exhaustion and decrement receipts splits one logical
	// budget into unrelated scopes and hides a post-exhaustion decrement.
	if value, _ := receipt["budget_snapshot_ref"].(string); strings.TrimSpace(value) != "" {
		return "budget_snapshot_ref:" + strings.TrimSpace(value)
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
	if !ok || !campaignBindingMatches(effect, opts) || !hasNonEmptyString(effect, "decision_id") || !hasNonEmptyString(effect, "tenant_id") || !hasNonEmptyString(effect, "envelope_id") || !hasNonEmptyString(effect, "envelope_hash") {
		return false
	}
	for _, receipt := range receipts {
		if receipt["action_type"] != actionType || receipt["decision_id"] != effect["decision_id"] || receipt["tenant_id"] != effect["tenant_id"] || receipt["envelope_id"] != effect["envelope_id"] || receipt["envelope_hash"] != effect["envelope_hash"] {
			continue
		}
		if !campaignBindingMatches(receipt, opts) || !authorizationReceiptAccepted(receipt, actionType) {
			continue
		}
		seq, sequenced := receiptSequence(receipt)
		if !sequenced || seq >= effectSeq || !receiptIsAncestor(receipts, effect, receipt) {
			continue
		}
		if verifyCampaignSignatures(receipt, "campaign_signatures", campaignReceiptSignatureDomain, opts.CampaignPublicKeyHex) {
			return true
		}
	}
	return false
}

func campaignBindingMatches(document map[string]interface{}, opts VerificationOptions) bool {
	campaignID := strings.TrimSpace(opts.CampaignID)
	runID := strings.TrimSpace(opts.RunID)
	if campaignID == "" || runID == "" {
		return false
	}
	return document["campaign_id"] == campaignID && document["run_id"] == runID
}

func authorizationReceiptAccepted(receipt map[string]interface{}, actionType string) bool {
	status, ok := receipt["status"].(string)
	if !ok {
		return false
	}
	status = strings.ToUpper(strings.TrimSpace(status))
	directlyAccepted := false
	requiresVerdict := false
	switch actionType {
	case "policy_decision":
		directlyAccepted = status == "ALLOW" || status == "ALLOWED"
		requiresVerdict = status == "APPLIED"
	case "approval_action":
		directlyAccepted = status == "APPROVED" || status == "ALLOW" || status == "ALLOWED"
		requiresVerdict = status == "APPLIED"
	}
	if !directlyAccepted && !requiresVerdict {
		return false
	}
	verdict, exists := receipt["verdict"]
	if !exists {
		return directlyAccepted
	}
	value, valid := verdict.(string)
	if !valid {
		return false
	}
	value = strings.ToUpper(strings.TrimSpace(value))
	switch actionType {
	case "policy_decision":
		return value == "ALLOW" || value == "ALLOWED"
	case "approval_action":
		return value == "ALLOW" || value == "ALLOWED" || value == "APPROVE" || value == "APPROVED"
	default:
		return false
	}
}

func receiptIsAncestor(receipts []map[string]interface{}, descendant, ancestor map[string]interface{}) bool {
	ancestorID := receiptIdentity(ancestor)
	if ancestorID == "" {
		return false
	}
	referenceIndex := receiptReferenceIndex(receipts)
	receiptsByIdentity := make(map[string]map[string]interface{}, len(receipts))
	for _, receipt := range receipts {
		if identity := receiptIdentity(receipt); identity != "" {
			receiptsByIdentity[identity] = receipt
		}
	}
	queue := receiptParentRefs(descendant)
	seen := map[string]bool{}
	for len(queue) > 0 {
		parentReference := queue[0]
		queue = queue[1:]
		parent, exists := referenceIndex[parentReference]
		if !exists || parent == "" {
			continue
		}
		if parent == ancestorID {
			return true
		}
		if seen[parent] {
			continue
		}
		seen[parent] = true
		if receipt := receiptsByIdentity[parent]; receipt != nil {
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

func receiptReferenceIndex(receipts []map[string]interface{}) map[string]string {
	index := make(map[string]string, len(receipts)*2)
	owners := make(map[string]int, len(receipts)*2)
	targetOwners := make(map[string]int, len(receipts))
	collidedTargets := make(map[string]bool)
	for receiptIndex, receipt := range receipts {
		target := receiptIdentity(receipt)
		if target == "" {
			continue
		}
		if owner, exists := targetOwners[target]; exists && owner != receiptIndex {
			collidedTargets[target] = true
		} else {
			targetOwners[target] = receiptIndex
		}
	}
	for receiptIndex, receipt := range receipts {
		target := receiptIdentity(receipt)
		if target == "" {
			continue
		}
		for _, key := range []string{"receipt_id", "receipt_hash"} {
			if value, _ := receipt[key].(string); strings.TrimSpace(value) != "" {
				reference := strings.TrimSpace(value)
				if collidedTargets[target] {
					index[reference] = ""
					continue
				}
				if owner, exists := owners[reference]; exists && owner != receiptIndex {
					index[reference] = ""
					continue
				}
				owners[reference] = receiptIndex
				index[reference] = target
			}
		}
	}
	return index
}

func receiptGraphHasCycle(graph map[string][]string) bool {
	indegree := make(map[string]int, len(graph))
	for node, parents := range graph {
		if _, exists := indegree[node]; !exists {
			indegree[node] = 0
		}
		for _, parent := range parents {
			if _, exists := indegree[parent]; !exists {
				indegree[parent] = 0
			}
			indegree[parent]++
		}
	}
	queue := make([]string, 0, len(indegree))
	for node, degree := range indegree {
		if degree == 0 {
			queue = append(queue, node)
		}
	}
	processed := 0
	for cursor := 0; cursor < len(queue); cursor++ {
		node := queue[cursor]
		processed++
		for _, parent := range graph[node] {
			indegree[parent]--
			if indegree[parent] == 0 {
				queue = append(queue, parent)
			}
		}
	}
	return processed != len(indegree)
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
	const maxExactJSONInteger = 1<<53 - 1
	return seq, ok && seq >= 0 && seq <= maxExactJSONInteger && math.Trunc(seq) == seq
}

func hasNonEmptyString(value map[string]interface{}, key string) bool {
	raw, ok := value[key].(string)
	return ok && strings.TrimSpace(raw) != ""
}

func verifyCampaignSignatures(document map[string]interface{}, field, domain, trustedPublicKeyHex string) bool {
	if strings.TrimSpace(domain) == "" {
		return false
	}
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
	signedMessage := []byte(domain)
	signedMessage = append(signedMessage, 0)
	signedMessage = append(signedMessage, canonical...)
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
		signatureBytes, err := hex.DecodeString(strings.TrimSpace(signatureHex))
		if err != nil || len(signatureBytes) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(publicKey), signedMessage, signatureBytes) {
			return false
		}
	}
	return true
}

func validTapeEntry(entry map[string]interface{}) bool {
	valueHash, ok := entry["value_hash"].(string)
	dataClass, classOK := entry["data_class"].(string)
	if !ok || !classOK || !validTapeDataClass(dataClass) {
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

func validTapeDataClass(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case contracts.DataClassPublic, contracts.DataClassInternal, contracts.DataClassConfidential, contracts.DataClassRestricted:
		return true
	default:
		return false
	}
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
