// Package openclaw provides the HELM runtime adapter for OpenClaw-class assistants.
//
// OpenClaw assistants issue tool calls that must be intercepted and governed
// by HELM before any external effect is produced.
package openclaw

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtimeadapters"
)

// OpenClawAdapter intercepts OpenClaw tool calls and routes them through HELM governance.
type OpenClawAdapter struct {
	graph  *proofgraph.Graph
	logger *slog.Logger
}

// Config configures the OpenClawAdapter.
type Config struct {
	Graph  *proofgraph.Graph
	Logger *slog.Logger
}

// NewOpenClawAdapter creates a new OpenClaw runtime adapter.
func NewOpenClawAdapter(cfg Config) (*OpenClawAdapter, error) {
	if cfg.Graph == nil {
		return nil, fmt.Errorf("runtimeadapters/openclaw: ProofGraph is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &OpenClawAdapter{
		graph:  cfg.Graph,
		logger: logger,
	}, nil
}

// ID returns the adapter identifier.
func (a *OpenClawAdapter) ID() string {
	return "openclaw-adapter-v1"
}

// Intercept processes an OpenClaw tool call through HELM governance.
func (a *OpenClawAdapter) Intercept(ctx context.Context, req *runtimeadapters.AdaptedRequest) (*runtimeadapters.AdaptedResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("runtimeadapters/openclaw: nil request")
	}

	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/openclaw: input hash failed: %w", err)
	}

	payload, err := json.Marshal(openClawProofPayload{
		AdapterID:   a.ID(),
		RuntimeType: "openclaw",
		ToolName:    req.ToolName,
		PrincipalID: req.PrincipalID,
		InputHash:   inputHash,
	})
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/openclaw: payload marshal failed: %w", err)
	}

	node, err := a.graph.Append(proofgraph.NodeTypeIntent, payload, req.PrincipalID, 0)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/openclaw: proofgraph append failed: %w", err)
	}

	a.logger.InfoContext(ctx, "openclaw tool call intercepted",
		"tool", req.ToolName,
		"principal", req.PrincipalID,
		"proof_node", node.NodeHash,
	)

	return &runtimeadapters.AdaptedResponse{
		Allowed:        false,
		DenyReason:     &runtimeadapters.DenyReason{Code: "NOT_IMPLEMENTED", Message: "OpenClaw adapter governance bridge not yet wired", Actionable: "contact_admin"},
		ReceiptID:      node.NodeHash,
		DecisionID:     node.NodeHash,
		ProofGraphNode: node.NodeHash,
	}, nil
}

type openClawProofPayload struct {
	AdapterID   string `json:"adapter_id"`
	RuntimeType string `json:"runtime_type"`
	ToolName    string `json:"tool_name"`
	PrincipalID string `json:"principal_id"`
	InputHash   string `json:"input_hash"`
}
