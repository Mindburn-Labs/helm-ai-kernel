// Package mcp provides the HELM runtime adapter for Model Context Protocol (MCP) clients.
//
// The MCPAdapter wraps the existing mcp.Gateway (it does NOT replace it),
// adding principal resolution, effect type classification, and receipt emission
// through the canonical RuntimeAdapter interface.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters"
)

// MCPAdapter intercepts MCP tool calls and routes them through HELM governance.
type MCPAdapter struct {
	graph  *proofgraph.Graph
	bridge *GovernedBridge
	logger *slog.Logger
}

// Config configures the MCPAdapter.
type Config struct {
	Graph *proofgraph.Graph
	// Bridge, when set, evaluates each tool call through the governed execution
	// bridge (ALLOW/DENY/ESCALATE, permit, receipt, optional dispatch). When nil
	// the adapter stays deny-only and fail-closed (BRIDGE_NOT_CONFIGURED).
	Bridge *GovernedBridge
	Logger *slog.Logger
}

// NewMCPAdapter creates a new MCP runtime adapter.
func NewMCPAdapter(cfg Config) (*MCPAdapter, error) {
	if cfg.Graph == nil {
		return nil, fmt.Errorf("runtimeadapters/mcp: ProofGraph is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &MCPAdapter{
		graph:  cfg.Graph,
		bridge: cfg.Bridge,
		logger: logger,
	}, nil
}

// ID returns the adapter identifier.
func (a *MCPAdapter) ID() string {
	return "mcp-adapter-v1"
}

// Intercept processes an MCP tool call through HELM governance.
func (a *MCPAdapter) Intercept(ctx context.Context, req *runtimeadapters.AdaptedRequest) (*runtimeadapters.AdaptedResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("runtimeadapters/mcp: nil request")
	}

	// Compute input hash for receipt
	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/mcp: input hash failed: %w", err)
	}

	// Create ProofGraph INTENT node for the tool call
	payload, err := json.Marshal(mcpProofPayload{
		AdapterID:   a.ID(),
		RuntimeType: "mcp",
		ToolName:    req.ToolName,
		PrincipalID: req.PrincipalID,
		InputHash:   inputHash,
	})
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/mcp: payload marshal failed: %w", err)
	}

	node, err := a.graph.Append(proofgraph.NodeTypeIntent, payload, req.PrincipalID, 0)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/mcp: proofgraph append failed: %w", err)
	}

	a.logger.InfoContext(ctx, "mcp tool call intercepted",
		"tool", req.ToolName,
		"principal", req.PrincipalID,
		"proof_node", node.NodeHash,
	)

	// Without a governed bridge the adapter stays fail-closed: it records the
	// intercepted call and denies execution.
	if a.bridge == nil {
		return &runtimeadapters.AdaptedResponse{
			Allowed:        false,
			DenyReason:     &runtimeadapters.DenyReason{Code: "BRIDGE_NOT_CONFIGURED", Message: "MCP adapter execution bridge is not configured", Actionable: "contact_admin"},
			ReceiptID:      node.NodeHash,
			DecisionID:     node.NodeHash,
			ProofGraphNode: node.NodeHash,
		}, nil
	}

	return a.governed(ctx, req, inputHash, node.NodeHash)
}

// governed routes an intercepted call through the execution bridge, records an
// EFFECT node linked to the INTENT, and maps the verdict to an AdaptedResponse.
func (a *MCPAdapter) governed(ctx context.Context, req *runtimeadapters.AdaptedRequest, inputHash, intentNode string) (*runtimeadapters.AdaptedResponse, error) {
	outcome := a.bridge.Govern(ctx, req, inputHash)

	effectPayload, err := json.Marshal(mcpEffectPayload{
		AdapterID:            a.ID(),
		ToolName:             req.ToolName,
		IntentNode:           intentNode,
		Verdict:              string(outcome.Verdict),
		ReasonCode:           outcome.ReasonCode,
		DecisionID:           outcome.DecisionID,
		ReceiptHash:          outcome.ReceiptHash,
		DispatchState:        outcome.DispatchState,
		OutputHash:           outcome.OutputHash,
		PermitID:             permitID(outcome.Permit),
		ReservationID:        effectReservationID(outcome.EffectReservation),
		ReservationState:     effectReservationState(outcome.EffectReservation),
		ReleaseAuthorityHash: effectReleaseAuthorityHash(outcome.EffectReservation),
	})
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/mcp: effect payload marshal failed: %w", err)
	}
	effectNode, err := a.graph.Append(proofgraph.NodeTypeEffect, effectPayload, req.PrincipalID, 0)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/mcp: proofgraph effect append failed: %w", err)
	}

	receiptID := outcome.ReceiptHash
	if receiptID == "" {
		receiptID = effectNode.NodeHash
	}
	decisionID := outcome.DecisionID
	if decisionID == "" {
		decisionID = intentNode
	}

	resp := &runtimeadapters.AdaptedResponse{
		Allowed:        outcome.Verdict == contracts.VerdictAllow,
		Result:         outcome.Output,
		ReceiptID:      receiptID,
		DecisionID:     decisionID,
		ProofGraphNode: effectNode.NodeHash,
	}
	if resp.Allowed {
		a.logger.InfoContext(ctx, "mcp tool call allowed",
			"tool", req.ToolName, "dispatch", outcome.DispatchState, "permit", permitID(outcome.Permit))
		return resp, nil
	}

	resp.DenyReason = &runtimeadapters.DenyReason{
		Code:       outcome.ReasonCode,
		Message:    outcome.Reason,
		Actionable: actionableFor(outcome),
	}
	a.logger.InfoContext(ctx, "mcp tool call not allowed",
		"tool", req.ToolName, "verdict", outcome.Verdict, "reason", outcome.ReasonCode)
	return resp, nil
}

func actionableFor(outcome GovernedOutcome) string {
	if outcome.Verdict == contracts.VerdictEscalate {
		return "request_approval"
	}
	if outcome.DispatchState == DispatchStateStarted || outcome.DispatchState == DispatchStateUncertain ||
		(outcome.EffectReservation != nil && (outcome.EffectReservation.State == approvalceremony.EffectReservationStateStarted ||
			outcome.EffectReservation.State == approvalceremony.EffectReservationStateUncertain)) {
		return "reconcile_effect"
	}
	return "modify_scope"
}

func permitID(p *effects.EffectPermit) string {
	if p == nil {
		return ""
	}
	return p.PermitID
}

type mcpProofPayload struct {
	AdapterID   string `json:"adapter_id"`
	RuntimeType string `json:"runtime_type"`
	ToolName    string `json:"tool_name"`
	PrincipalID string `json:"principal_id"`
	InputHash   string `json:"input_hash"`
}

type mcpEffectPayload struct {
	AdapterID            string `json:"adapter_id"`
	ToolName             string `json:"tool_name"`
	IntentNode           string `json:"intent_node"`
	Verdict              string `json:"verdict"`
	ReasonCode           string `json:"reason_code,omitempty"`
	DecisionID           string `json:"decision_id,omitempty"`
	ReceiptHash          string `json:"receipt_hash,omitempty"`
	DispatchState        string `json:"dispatch_state"`
	OutputHash           string `json:"output_hash,omitempty"`
	PermitID             string `json:"permit_id,omitempty"`
	ReservationID        string `json:"reservation_id,omitempty"`
	ReservationState     string `json:"reservation_state,omitempty"`
	ReleaseAuthorityHash string `json:"release_authority_hash,omitempty"`
}

func effectReservationID(event *approvalceremony.EffectReservationEvent) string {
	if event == nil {
		return ""
	}
	return event.Admission.Admission.AdmissionID
}

func effectReservationState(event *approvalceremony.EffectReservationEvent) string {
	if event == nil {
		return ""
	}
	return string(event.State)
}

func effectReleaseAuthorityHash(event *approvalceremony.EffectReservationEvent) string {
	if event == nil {
		return ""
	}
	return event.ReleaseAuthority.Authority.AuthorityHash
}
