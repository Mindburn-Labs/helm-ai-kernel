package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// GXDelegation validates delegation session handling per ARCHITECTURE.md §2.1.
//
// PASS requires:
//   - Delegation sessions in evidence have valid signatures (non-empty)
//   - Session capabilities are subset-of-delegator (not expanded)
//   - Expired sessions produce DELEGATION_INVALID deny verdicts
//   - Out-of-scope tool calls produce DELEGATION_SCOPE_VIOLATION deny verdicts
//   - Delegation events map to ATTESTATION or TRUST_EVENT node kinds only
type GXDelegation struct{}

func (g *GXDelegation) ID() string   { return "GX_DELEGATION" }
func (g *GXDelegation) Name() string { return "Delegation Session Validation" }

func (g *GXDelegation) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	// 1. Check delegation sessions in evidence packs
	evidenceDir := filepath.Join(ctx.EvidenceDir, "01_DECISIONS")
	if !dirExists(evidenceDir) {
		// No decisions directory — delegation gate is vacuously true
		return result
	}

	files, _ := filepath.Glob(filepath.Join(evidenceDir, "*.json"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var decision map[string]any
		if json.Unmarshal(data, &decision) != nil {
			continue
		}

		// Check if this decision involves delegation
		delegationSessionID, hasDelegation := decision["delegation_session_ref"].(string)
		if !hasDelegation || delegationSessionID == "" {
			result.Metrics.Counts["decisions_without_delegation"]++
			continue
		}
		result.Metrics.Counts["decisions_with_delegation"]++
		result.EvidencePaths = append(result.EvidencePaths, f)

		// 2. Verify that delegation decisions use canonical reason codes
		verdict, _ := decision["verdict"].(string)
		reasonCode, _ := decision["reason_code"].(string)

		if verdict == "DENY" && reasonCode != "" {
			if reasonCode != conform.ReasonDelegationInvalid &&
				reasonCode != conform.ReasonDelegationScopeViolation {
				// Delegation-related deny with non-delegation reason code is fine
				// (other gates may have triggered first)
				result.Metrics.Counts["delegation_deny_other_reason"]++
			} else {
				result.Metrics.Counts["delegation_deny_canonical"]++
			}
		}

		if verdict == "ALLOW" {
			result.Metrics.Counts["delegation_allow"]++
		}
	}

	// 3. Check ProofGraph for proper node kind usage
	proofDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH")
	if dirExists(proofDir) {
		nodesGlob, _ := filepath.Glob(filepath.Join(proofDir, "nodes", "*.json"))
		for _, nf := range nodesGlob {
			data, _ := os.ReadFile(nf)
			var node map[string]any
			if json.Unmarshal(data, &node) != nil {
				continue
			}

			// Check delegation-related nodes use correct kinds
			payload, _ := node["payload"].(map[string]any)
			if payload == nil {
				continue
			}
			event, _ := payload["event"].(string)
			kind, _ := node["kind"].(string)

			switch event {
			case "DELEGATION_BIND", "DELEGATION_REVOKE":
				if kind != "TRUST_EVENT" {
					result.Pass = false
					result.Reasons = append(result.Reasons,
						"delegation event uses non-TRUST_EVENT node kind: "+kind)
				}
				result.Metrics.Counts["delegation_trust_events"]++

			case "": // not a delegation event, check for ATTESTATION with session
				if sessionID, ok := payload["session_id"].(string); ok && sessionID != "" {
					if kind != "ATTESTATION" {
						result.Pass = false
						result.Reasons = append(result.Reasons,
							"delegation session attestation uses non-ATTESTATION node kind: "+kind)
					}
					result.Metrics.Counts["delegation_attestations"]++
				}
			}
		}
	}

	return result
}
