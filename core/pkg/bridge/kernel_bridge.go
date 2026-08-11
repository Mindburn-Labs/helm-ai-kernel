// Package bridge provides KernelBridge — the composition layer that wires
// Guardian, Executor, ProofGraph, and Budget into a single governance call.
// This is used by the proxy CLI to govern tool_calls with a single Govern() call.
package bridge

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/budget"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

// GovernResult captures the outcome of a governance decision.
type GovernResult struct {
	Decision   *contracts.DecisionRecord            `json:"decision"`
	Intent     *contracts.AuthorizedExecutionIntent `json:"intent,omitempty"` // nil if denied
	ReasonCode string                               `json:"reason_code"`
	NodeID     string                               `json:"node_id"` // ProofGraph node hash
	Allowed    bool                                 `json:"allowed"`
}

// KernelBridge composes Guardian + ProofGraph + Budget into a single governance call.
// It does NOT own the Executor — the proxy does not execute tool calls, it only governs them.
// The LLM framework drives execution; the proxy observes, validates, and receipts.
type KernelBridge struct {
	guardian *guardian.Guardian
	prgGraph *prg.Graph
	graph    *proofgraph.Graph
	budget   budget.Enforcer // nil = skip budget check
	tenantID string
}

// NewKernelBridge creates a bridge with the given Guardian, PRG, ProofGraph, and optional budget enforcer.
func NewKernelBridge(g *guardian.Guardian, prgGraph *prg.Graph, pg *proofgraph.Graph, budgetEnforcer budget.Enforcer, tenantID string) *KernelBridge {
	return &KernelBridge{
		guardian: g,
		prgGraph: prgGraph,
		graph:    pg,
		budget:   budgetEnforcer,
		tenantID: tenantID,
	}
}

// Govern evaluates a tool call against the governance pipeline:
//  1. Budget check (if enforcer configured)
//  2. Guardian.EvaluateDecision → DecisionRecord
//  3. ProofGraph INTENT node (always)
//  4. ProofGraph ATTESTATION node with verdict
//
// The cost argument carries the effect's measured monetary cost so budget
// consumption tracks real spend: an expensive model call consumes
// proportionally more than a cheap one. When a budget enforcer is configured,
// callers must provide a priced breakdown; raw token counts are usage evidence,
// not cents, and fail closed rather than being reinterpreted as money.
//
// Returns a GovernResult with the decision, reason code, and ProofGraph node ID.
// This is fail-closed: any error results in denial.
func (kb *KernelBridge) Govern(ctx context.Context, toolName string, argsHash string, cost *effects.CostBreakdown) (*GovernResult, error) {
	// 1. Budget check (fail-closed)
	if kb.budget != nil {
		amount, costErr := budgetCents(cost)
		if costErr != nil {
			reason := string(contracts.ReasonBudgetError)
			nodeID, _ := kb.appendNode(proofgraph.NodeTypeAttestation, map[string]string{
				"tool":      toolName,
				"verdict":   "DENY",
				"reason":    reason,
				"args_hash": argsHash,
				"error":     costErr.Error(),
			})
			return &GovernResult{
				ReasonCode: reason,
				NodeID:     nodeID,
				Allowed:    false,
			}, nil
		}

		budgetCost := budget.Cost{Amount: amount, Currency: "USD", Reason: "tool_call:" + toolName}
		decision, err := kb.budget.Check(ctx, kb.tenantID, budgetCost)
		if err != nil || !decision.Allowed {
			reason := string(contracts.ReasonBudgetExceeded)
			if err != nil {
				reason = string(contracts.ReasonBudgetError)
			}
			// Record denial in ProofGraph
			nodeID, _ := kb.appendNode(proofgraph.NodeTypeAttestation, map[string]string{
				"tool":      toolName,
				"verdict":   "DENY",
				"reason":    reason,
				"args_hash": argsHash,
			})
			return &GovernResult{
				ReasonCode: reason,
				NodeID:     nodeID,
				Allowed:    false,
			}, nil
		}
	}

	// 2. Record INTENT in ProofGraph
	intentNodeID, _ := kb.appendNode(proofgraph.NodeTypeIntent, map[string]string{
		"tool":      toolName,
		"args_hash": argsHash,
		"tenant":    kb.tenantID,
	})

	// 3. Guardian evaluation
	// Guardian uses tool_name as PRG action ID. Tool policy must already be
	// present in the PRG graph; missing policy fails closed in Guardian.

	req := guardian.DecisionRequest{
		Principal: kb.tenantID,
		Action:    "EXECUTE_TOOL",
		Resource:  toolName,
		Context: map[string]interface{}{
			"args_hash": argsHash,
		},
	}

	decision, err := kb.guardian.EvaluateDecision(ctx, req)
	if err != nil {
		// Fail-closed: Guardian error = denial
		reason := string(contracts.ReasonPDPError)
		nodeID, _ := kb.appendNode(proofgraph.NodeTypeAttestation, map[string]string{
			"tool":        toolName,
			"verdict":     "DENY",
			"reason":      reason,
			"intent_node": intentNodeID,
			"error":       err.Error(),
		})
		return &GovernResult{
			ReasonCode: reason,
			NodeID:     nodeID,
			Allowed:    false,
		}, nil
	}

	// 4. Record ATTESTATION with verdict
	allowed := decision.Verdict == string(contracts.VerdictAllow)
	reasonCode := decision.ReasonCode
	if !allowed && reasonCode == "" {
		reasonCode = string(contracts.ReasonPolicyViolation)
	}

	attestNodeID, _ := kb.appendNode(proofgraph.NodeTypeAttestation, map[string]string{
		"tool":        toolName,
		"verdict":     decision.Verdict,
		"decision_id": decision.ID,
		"reason":      decision.Reason,
		"reason_code": reasonCode,
		"intent_node": intentNodeID,
	})

	return &GovernResult{
		Decision:   decision,
		ReasonCode: reasonCode,
		NodeID:     attestNodeID,
		Allowed:    allowed,
	}, nil
}

// Graph returns the underlying ProofGraph for serialization/export.
func (kb *KernelBridge) Graph() *proofgraph.Graph {
	return kb.graph
}

// budgetCents resolves the amount to charge the budget for one governed effect
// in the enforcer's cents unit. It never invents a price or reinterprets another
// unit as money:
//
//  1. TotalCents — the settled/estimated total when the effect priced itself.
//  2. ModelCostCents + ToolCostCents — the priced components, when no total.
//
// Token counts remain useful usage evidence, but they are not cents. Missing,
// negative, overflowing, or internally inconsistent monetary data fails closed.
// A non-nil all-zero breakdown is an explicit zero-cost effect (for example, a
// local model) and is therefore distinct from a missing price.
func budgetCents(cost *effects.CostBreakdown) (int64, error) {
	if cost == nil {
		return 0, fmt.Errorf("priced cost breakdown is required")
	}
	if cost.InputTokens < 0 || cost.OutputTokens < 0 || cost.ModelCostCents < 0 || cost.ToolCostCents < 0 || cost.TotalCents < 0 {
		return 0, fmt.Errorf("cost breakdown fields must not be negative")
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	if cost.ToolCostCents > 0 && cost.ModelCostCents > maxInt64-cost.ToolCostCents {
		return 0, fmt.Errorf("priced cost components overflow int64 cents")
	}
	pricedComponents := cost.ModelCostCents + cost.ToolCostCents
	if cost.TotalCents > 0 && pricedComponents > 0 && cost.TotalCents != pricedComponents {
		return 0, fmt.Errorf("total cost %d cents does not match priced components %d cents", cost.TotalCents, pricedComponents)
	}
	if cost.TotalCents > 0 {
		return cost.TotalCents, nil
	}
	if pricedComponents > 0 {
		return pricedComponents, nil
	}
	if cost.InputTokens > 0 || cost.OutputTokens > 0 {
		return 0, fmt.Errorf("token usage is not a monetary cost")
	}
	return 0, nil
}

// appendNode is a helper that marshals the payload and appends to the ProofGraph.
func (kb *KernelBridge) appendNode(kind proofgraph.NodeType, payload map[string]string) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	node, err := kb.graph.Append(kind, data, kb.tenantID, kb.graph.LamportClock()+1)
	if err != nil {
		return "", fmt.Errorf("append node: %w", err)
	}
	return node.NodeHash, nil
}
