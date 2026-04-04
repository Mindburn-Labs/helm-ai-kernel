// Package generic_http provides the HELM runtime adapter for arbitrary HTTP tool callers.
//
// The GenericHTTPAdapter can be inserted as HTTP middleware in front of any
// tool endpoint to intercept and govern tool calls via HELM.
package generic_http

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtimeadapters"
)

// GenericHTTPAdapter intercepts HTTP tool calls and routes them through HELM governance.
type GenericHTTPAdapter struct {
	graph  *proofgraph.Graph
	logger *slog.Logger
}

// Config configures the GenericHTTPAdapter.
type Config struct {
	Graph  *proofgraph.Graph
	Logger *slog.Logger
}

// NewGenericHTTPAdapter creates a new generic HTTP runtime adapter.
func NewGenericHTTPAdapter(cfg Config) (*GenericHTTPAdapter, error) {
	if cfg.Graph == nil {
		return nil, fmt.Errorf("runtimeadapters/generic_http: ProofGraph is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &GenericHTTPAdapter{
		graph:  cfg.Graph,
		logger: logger,
	}, nil
}

// ID returns the adapter identifier.
func (a *GenericHTTPAdapter) ID() string {
	return "generic-http-adapter-v1"
}

// Intercept processes an HTTP tool call through HELM governance.
func (a *GenericHTTPAdapter) Intercept(ctx context.Context, req *runtimeadapters.AdaptedRequest) (*runtimeadapters.AdaptedResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("runtimeadapters/generic_http: nil request")
	}

	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/generic_http: input hash failed: %w", err)
	}

	payload, err := json.Marshal(httpProofPayload{
		AdapterID:   a.ID(),
		RuntimeType: "http",
		ToolName:    req.ToolName,
		PrincipalID: req.PrincipalID,
		InputHash:   inputHash,
	})
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/generic_http: payload marshal failed: %w", err)
	}

	node, err := a.graph.Append(proofgraph.NodeTypeIntent, payload, req.PrincipalID, 0)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/generic_http: proofgraph append failed: %w", err)
	}

	a.logger.InfoContext(ctx, "http tool call intercepted",
		"tool", req.ToolName,
		"principal", req.PrincipalID,
		"proof_node", node.NodeHash,
	)

	return &runtimeadapters.AdaptedResponse{
		Allowed:        false,
		DenyReason:     &runtimeadapters.DenyReason{Code: "NOT_IMPLEMENTED", Message: "Generic HTTP adapter governance bridge not yet wired", Actionable: "contact_admin"},
		ReceiptID:      node.NodeHash,
		DecisionID:     node.NodeHash,
		ProofGraphNode: node.NodeHash,
	}, nil
}

type httpProofPayload struct {
	AdapterID   string `json:"adapter_id"`
	RuntimeType string `json:"runtime_type"`
	ToolName    string `json:"tool_name"`
	PrincipalID string `json:"principal_id"`
	InputHash   string `json:"input_hash"`
}
