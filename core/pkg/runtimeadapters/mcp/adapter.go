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

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtimeadapters"
)

// MCPAdapter intercepts MCP tool calls and routes them through HELM governance.
type MCPAdapter struct {
	graph  *proofgraph.Graph
	logger *slog.Logger
}

// Config configures the MCPAdapter.
type Config struct {
	Graph  *proofgraph.Graph
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

	// The OSS adapter records the intercepted call and denies execution until a
	// deployment supplies a governed MCP execution bridge.
	return &runtimeadapters.AdaptedResponse{
		Allowed:        false,
		DenyReason:     &runtimeadapters.DenyReason{Code: "BRIDGE_NOT_CONFIGURED", Message: "MCP adapter execution bridge is not configured", Actionable: "contact_admin"},
		ReceiptID:      node.NodeHash,
		DecisionID:     node.NodeHash,
		ProofGraphNode: node.NodeHash,
	}, nil
}

type mcpProofPayload struct {
	AdapterID   string `json:"adapter_id"`
	RuntimeType string `json:"runtime_type"`
	ToolName    string `json:"tool_name"`
	PrincipalID string `json:"principal_id"`
	InputHash   string `json:"input_hash"`
}
