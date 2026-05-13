// Package grpc provides the HELM runtime adapter for gRPC services.
//
// The GRPCAdapter can be used as a governance interceptor for gRPC unary and
// streaming calls. It extracts the method name and principal from request
// metadata, evaluates through the Guardian pipeline, and records decisions
// in the ProofGraph.
package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters"
)

// GRPCAdapter intercepts gRPC calls and routes them through HELM governance.
type GRPCAdapter struct {
	graph  *proofgraph.Graph
	logger *slog.Logger
}

// Config configures the GRPCAdapter.
type Config struct {
	Graph  *proofgraph.Graph
	Logger *slog.Logger
}

// NewGRPCAdapter creates a new gRPC runtime adapter.
func NewGRPCAdapter(cfg Config) (*GRPCAdapter, error) {
	if cfg.Graph == nil {
		return nil, fmt.Errorf("runtimeadapters/grpc: ProofGraph is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &GRPCAdapter{
		graph:  cfg.Graph,
		logger: logger,
	}, nil
}

// ID returns the adapter identifier.
func (a *GRPCAdapter) ID() string {
	return "grpc-adapter-v1"
}

// Intercept processes a gRPC call through HELM governance.
//
// Expected AdaptedRequest fields:
//   - RuntimeType: "grpc"
//   - ToolName: the full gRPC method name (e.g. "/pkg.Service/Method")
//   - PrincipalID: the caller identity (from gRPC metadata or mTLS)
//   - Arguments: the deserialized request message fields
//   - Metadata: gRPC metadata headers ("grpc.service", "grpc.method", "grpc.authority")
func (a *GRPCAdapter) Intercept(ctx context.Context, req *runtimeadapters.AdaptedRequest) (*runtimeadapters.AdaptedResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("runtimeadapters/grpc: nil request")
	}

	// Compute canonical input hash for receipt integrity.
	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/grpc: input hash failed: %w", err)
	}

	// Extract gRPC-specific metadata for proof payload.
	service := metaOrDefault(req.Metadata, "grpc.service", "")
	method := metaOrDefault(req.Metadata, "grpc.method", "")
	authority := metaOrDefault(req.Metadata, "grpc.authority", "")

	payload, err := json.Marshal(grpcProofPayload{
		AdapterID:   a.ID(),
		RuntimeType: "grpc",
		FullMethod:  req.ToolName,
		Service:     service,
		Method:      method,
		Authority:   authority,
		PrincipalID: req.PrincipalID,
		InputHash:   inputHash,
	})
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/grpc: payload marshal failed: %w", err)
	}

	node, err := a.graph.Append(proofgraph.NodeTypeIntent, payload, req.PrincipalID, 0)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/grpc: proofgraph append failed: %w", err)
	}

	a.logger.InfoContext(ctx, "grpc call intercepted",
		"full_method", req.ToolName,
		"service", service,
		"method", method,
		"principal", req.PrincipalID,
		"proof_node", node.NodeHash,
	)

	// The OSS adapter records the intercepted call and denies execution until a
	// deployment supplies an upstream gRPC bridge.
	return &runtimeadapters.AdaptedResponse{
		Allowed:        false,
		DenyReason:     &runtimeadapters.DenyReason{Code: "BRIDGE_NOT_CONFIGURED", Message: "gRPC adapter upstream bridge is not configured", Actionable: "contact_admin"},
		ReceiptID:      node.NodeHash,
		DecisionID:     node.NodeHash,
		ProofGraphNode: node.NodeHash,
	}, nil
}

// metaOrDefault returns the value for key from the metadata map, or a fallback.
func metaOrDefault(meta map[string]string, key, fallback string) string {
	if meta != nil {
		if v, ok := meta[key]; ok {
			return v
		}
	}
	return fallback
}

type grpcProofPayload struct {
	AdapterID   string `json:"adapter_id"`
	RuntimeType string `json:"runtime_type"`
	FullMethod  string `json:"full_method"`
	Service     string `json:"service,omitempty"`
	Method      string `json:"method,omitempty"`
	Authority   string `json:"authority,omitempty"`
	PrincipalID string `json:"principal_id"`
	InputHash   string `json:"input_hash"`
}
