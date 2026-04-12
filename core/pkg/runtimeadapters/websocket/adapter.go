// Package websocket provides the HELM runtime adapter for WebSocket connections.
//
// The WebSocketAdapter intercepts individual WebSocket messages for governance
// evaluation. It can allow or deny each message independently, enabling
// fine-grained control over streaming agent communication channels.
package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtimeadapters"
)

// WebSocketAdapter intercepts WebSocket messages and routes them through HELM governance.
type WebSocketAdapter struct {
	graph  *proofgraph.Graph
	logger *slog.Logger
}

// Config configures the WebSocketAdapter.
type Config struct {
	Graph  *proofgraph.Graph
	Logger *slog.Logger
}

// NewWebSocketAdapter creates a new WebSocket runtime adapter.
func NewWebSocketAdapter(cfg Config) (*WebSocketAdapter, error) {
	if cfg.Graph == nil {
		return nil, fmt.Errorf("runtimeadapters/websocket: ProofGraph is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &WebSocketAdapter{
		graph:  cfg.Graph,
		logger: logger,
	}, nil
}

// ID returns the adapter identifier.
func (a *WebSocketAdapter) ID() string {
	return "websocket-adapter-v1"
}

// Intercept processes a WebSocket message through HELM governance.
//
// Expected AdaptedRequest fields:
//   - RuntimeType: "websocket"
//   - ToolName: the message action or channel (e.g. "agent.tool_call", "agent.response")
//   - PrincipalID: the connection owner's identity
//   - Arguments: the parsed message payload
//   - Metadata: WebSocket-specific headers ("ws.message_type", "ws.direction", "ws.connection_id")
//
// ws.message_type values: "text", "binary"
// ws.direction values: "inbound" (client -> server), "outbound" (server -> client)
func (a *WebSocketAdapter) Intercept(ctx context.Context, req *runtimeadapters.AdaptedRequest) (*runtimeadapters.AdaptedResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("runtimeadapters/websocket: nil request")
	}

	// Compute canonical input hash for receipt integrity.
	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/websocket: input hash failed: %w", err)
	}

	// Extract WebSocket-specific metadata for proof payload.
	messageType := metaOrDefault(req.Metadata, "ws.message_type", "text")
	direction := metaOrDefault(req.Metadata, "ws.direction", "inbound")
	connectionID := metaOrDefault(req.Metadata, "ws.connection_id", "")

	payload, err := json.Marshal(wsProofPayload{
		AdapterID:    a.ID(),
		RuntimeType:  "websocket",
		Action:       req.ToolName,
		PrincipalID:  req.PrincipalID,
		MessageType:  messageType,
		Direction:    direction,
		ConnectionID: connectionID,
		InputHash:    inputHash,
	})
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/websocket: payload marshal failed: %w", err)
	}

	node, err := a.graph.Append(proofgraph.NodeTypeIntent, payload, req.PrincipalID, 0)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/websocket: proofgraph append failed: %w", err)
	}

	a.logger.InfoContext(ctx, "websocket message intercepted",
		"action", req.ToolName,
		"principal", req.PrincipalID,
		"message_type", messageType,
		"direction", direction,
		"connection_id", connectionID,
		"proof_node", node.NodeHash,
	)

	// In a full implementation, this would:
	// 1. Parse the WebSocket message payload from req.Arguments
	// 2. Classify the message direction and action type
	// 3. Resolve the connection owner to a HELM principal
	// 4. Evaluate through Guardian pipeline
	// 5. If ALLOW: forward the message, create EFFECT node
	// 6. If DENY: drop the message, return DenyReason
	// 7. If ESCALATE: buffer the message, create InboxItem for approval
	//
	// For now, return the governance intercept proof as a placeholder.
	return &runtimeadapters.AdaptedResponse{
		Allowed:        false,
		DenyReason:     &runtimeadapters.DenyReason{Code: "NOT_IMPLEMENTED", Message: "WebSocket adapter governance bridge not yet wired", Actionable: "contact_admin"},
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

type wsProofPayload struct {
	AdapterID    string `json:"adapter_id"`
	RuntimeType  string `json:"runtime_type"`
	Action       string `json:"action"`
	PrincipalID  string `json:"principal_id"`
	MessageType  string `json:"message_type"`
	Direction    string `json:"direction"`
	ConnectionID string `json:"connection_id,omitempty"`
	InputHash    string `json:"input_hash"`
}
