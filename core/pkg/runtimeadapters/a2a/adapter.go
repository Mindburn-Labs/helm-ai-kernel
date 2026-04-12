// Package a2a provides the HELM runtime adapter for Agent-to-Agent (A2A) protocol messages.
//
// The A2AAdapter intercepts agent-to-agent messages, evaluates the sending
// principal and action through the Guardian pipeline, and records the
// governance decision in the ProofGraph. It does NOT replace the A2A transport
// layer; it sits in front of it as a non-bypassable policy enforcement point.
package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtimeadapters"
)

// A2AAdapter intercepts A2A protocol messages and routes them through HELM governance.
type A2AAdapter struct {
	graph  *proofgraph.Graph
	logger *slog.Logger
}

// Config configures the A2AAdapter.
type Config struct {
	Graph  *proofgraph.Graph
	Logger *slog.Logger
}

// NewA2AAdapter creates a new A2A runtime adapter.
func NewA2AAdapter(cfg Config) (*A2AAdapter, error) {
	if cfg.Graph == nil {
		return nil, fmt.Errorf("runtimeadapters/a2a: ProofGraph is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &A2AAdapter{
		graph:  cfg.Graph,
		logger: logger,
	}, nil
}

// ID returns the adapter identifier.
func (a *A2AAdapter) ID() string {
	return "a2a-adapter-v1"
}

// Intercept processes an A2A protocol message through HELM governance.
//
// Expected AdaptedRequest fields:
//   - RuntimeType: "a2a"
//   - ToolName: the A2A method (e.g. "tasks/send", "tasks/get", "tasks/cancel")
//   - PrincipalID: the sending agent's identity
//   - Arguments: the A2A envelope payload
//   - Metadata: optional A2A headers ("a2a.task_id", "a2a.from_agent", "a2a.to_agent")
func (a *A2AAdapter) Intercept(ctx context.Context, req *runtimeadapters.AdaptedRequest) (*runtimeadapters.AdaptedResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("runtimeadapters/a2a: nil request")
	}

	// Compute canonical input hash for receipt integrity.
	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/a2a: input hash failed: %w", err)
	}

	// Extract A2A-specific metadata for proof payload.
	fromAgent := metaOrDefault(req.Metadata, "a2a.from_agent", req.PrincipalID)
	toAgent := metaOrDefault(req.Metadata, "a2a.to_agent", "")
	taskID := metaOrDefault(req.Metadata, "a2a.task_id", "")

	payload, err := json.Marshal(a2aProofPayload{
		AdapterID:   a.ID(),
		RuntimeType: "a2a",
		Method:      req.ToolName,
		PrincipalID: req.PrincipalID,
		FromAgent:   fromAgent,
		ToAgent:     toAgent,
		TaskID:      taskID,
		InputHash:   inputHash,
	})
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/a2a: payload marshal failed: %w", err)
	}

	node, err := a.graph.Append(proofgraph.NodeTypeIntent, payload, req.PrincipalID, 0)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/a2a: proofgraph append failed: %w", err)
	}

	a.logger.InfoContext(ctx, "a2a message intercepted",
		"method", req.ToolName,
		"principal", req.PrincipalID,
		"from_agent", fromAgent,
		"to_agent", toAgent,
		"task_id", taskID,
		"proof_node", node.NodeHash,
	)

	// In a full implementation, this would:
	// 1. Parse the A2A envelope from req.Arguments
	// 2. Resolve the sending agent to a HELM principal via identity registry
	// 3. Classify the A2A method into an effect type (READ, WRITE, DELEGATE)
	// 4. Evaluate through Guardian pipeline (Freeze -> Context -> Identity -> Egress -> Threat -> Delegation)
	// 5. If ALLOW: forward the message, create EFFECT node
	// 6. If DENY: return DenyReason with actionable guidance
	// 7. If ESCALATE: create InboxItem for human approval
	//
	// For now, return the governance intercept proof as a placeholder.
	return &runtimeadapters.AdaptedResponse{
		Allowed:        false,
		DenyReason:     &runtimeadapters.DenyReason{Code: "NOT_IMPLEMENTED", Message: "A2A adapter governance bridge not yet wired", Actionable: "contact_admin"},
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

type a2aProofPayload struct {
	AdapterID   string `json:"adapter_id"`
	RuntimeType string `json:"runtime_type"`
	Method      string `json:"method"`
	PrincipalID string `json:"principal_id"`
	FromAgent   string `json:"from_agent"`
	ToAgent     string `json:"to_agent,omitempty"`
	TaskID      string `json:"task_id,omitempty"`
	InputHash   string `json:"input_hash"`
}
