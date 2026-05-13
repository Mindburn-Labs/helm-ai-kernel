package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connector"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

// Compile-time interface compliance check.
var _ effects.Connector = (*Connector)(nil)

// Config configures a new Slack Connector.
type Config struct {
	ConnectorID string
	BotToken    string
}

// Connector is the HELM Slack connector.
//
// It composes:
//   - Client:      HTTP bridge to Slack API
//   - ZeroTrust:   connector trust gate (rate limits, provenance)
//   - ProofGraph:  cryptographic receipt chain
//
// Every Slack action produces an INTENT -> EFFECT chain in the ProofGraph.
type Connector struct {
	client      *Client
	gate        *connector.ZeroTrustGate
	graph       *proofgraph.Graph
	connectorID string
	seq         atomic.Uint64
}

// NewConnector creates a new Slack connector with ZeroTrust enforcement.
func NewConnector(cfg Config) *Connector {
	if cfg.ConnectorID == "" {
		cfg.ConnectorID = "slack-v1"
	}

	gate := connector.NewZeroTrustGate()
	gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        cfg.ConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      3600,
		AllowedDataClasses: AllowedDataClasses(),
		RateLimitPerMinute: 120,
		RequireProvenance:  true,
	})

	return &Connector{
		client:      NewClient(cfg.BotToken),
		gate:        gate,
		graph:       proofgraph.NewGraph(),
		connectorID: cfg.ConnectorID,
	}
}

// ID returns the connector identifier.
func (c *Connector) ID() string {
	return c.connectorID
}

// AllowedDataClasses returns the set of data classes this connector supports.
func AllowedDataClasses() []string {
	return []string{
		"slack.message.send",
		"slack.message.read",
		"slack.channel.list",
		"slack.message.update",
	}
}

// Graph returns the ProofGraph for inspection/export.
func (c *Connector) Graph() *proofgraph.Graph {
	return c.graph
}

// Execute dispatches a tool call through the Slack connector with full
// ZeroTrust gate enforcement and ProofGraph receipt generation.
func (c *Connector) Execute(ctx context.Context, permit *effects.EffectPermit, toolName string, params map[string]any) (any, error) {
	switch toolName {
	case "slack.send_message":
		return c.executeSendMessage(ctx, params)
	case "slack.read_channel":
		return c.executeReadChannel(ctx, params)
	case "slack.list_channels":
		return c.executeListChannels(ctx, params)
	case "slack.update_message":
		return c.executeUpdateMessage(ctx, params)
	default:
		return nil, fmt.Errorf("slack: unknown tool %q", toolName)
	}
}

func (c *Connector) executeSendMessage(ctx context.Context, params map[string]any) (any, error) {
	dataClass := "slack.message.send"

	// 1. ZeroTrust gate
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "slack.send_message.intent",
		ToolName: "slack.send_message",
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("slack: marshal intent: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentData, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("slack: append intent: %w", err)
	}

	// 3. Build request from params
	req := &SendMessageRequest{
		ChannelID: stringParam(params, "channel_id"),
		Text:      stringParam(params, "text"),
		ThreadTS:  stringParam(params, "thread_ts"),
	}

	// 4. Execute via client
	result, err := c.client.SendMessage(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("slack: send_message: %w", err)
	}

	// 5. EFFECT node
	contentHash, _ := canonicalize.CanonicalHash(result)
	responseBytes, _ := json.Marshal(result)
	provTag := connector.ComputeProvenanceTag(c.connectorID, intentData, responseBytes, 3600, connector.TrustLevelVerified)

	effectData, err := json.Marshal(effectPayload{
		Type:           "slack.send_message.effect",
		ToolName:       "slack.send_message",
		ContentHash:    contentHash,
		ProvenanceHash: provTag.ResponseHash,
	})
	if err != nil {
		return nil, fmt.Errorf("slack: marshal effect: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectData, c.connectorID, c.nextSeq()); err != nil {
		return nil, fmt.Errorf("slack: append effect: %w", err)
	}

	return result, nil
}

func (c *Connector) executeReadChannel(ctx context.Context, params map[string]any) (any, error) {
	dataClass := "slack.message.read"

	// 1. ZeroTrust gate
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "slack.read_channel.intent",
		ToolName: "slack.read_channel",
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("slack: marshal intent: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentData, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("slack: append intent: %w", err)
	}

	// 3. Execute via client
	channelID := stringParam(params, "channel_id")
	limit := intParam(params, "limit", 100)
	result, err := c.client.ReadChannel(ctx, channelID, limit)
	if err != nil {
		return nil, fmt.Errorf("slack: read_channel: %w", err)
	}

	// 4. EFFECT node
	contentHash, _ := canonicalize.CanonicalHash(result)
	responseBytes, _ := json.Marshal(result)
	provTag := connector.ComputeProvenanceTag(c.connectorID, intentData, responseBytes, 3600, connector.TrustLevelVerified)

	effectData, err := json.Marshal(effectPayload{
		Type:           "slack.read_channel.effect",
		ToolName:       "slack.read_channel",
		ContentHash:    contentHash,
		ProvenanceHash: provTag.ResponseHash,
	})
	if err != nil {
		return nil, fmt.Errorf("slack: marshal effect: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectData, c.connectorID, c.nextSeq()); err != nil {
		return nil, fmt.Errorf("slack: append effect: %w", err)
	}

	return result, nil
}

func (c *Connector) executeListChannels(ctx context.Context, params map[string]any) (any, error) {
	dataClass := "slack.channel.list"

	// 1. ZeroTrust gate
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "slack.list_channels.intent",
		ToolName: "slack.list_channels",
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("slack: marshal intent: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentData, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("slack: append intent: %w", err)
	}

	// 3. Execute via client
	result, err := c.client.ListChannels(ctx)
	if err != nil {
		return nil, fmt.Errorf("slack: list_channels: %w", err)
	}

	// 4. EFFECT node
	contentHash, _ := canonicalize.CanonicalHash(result)
	responseBytes, _ := json.Marshal(result)
	provTag := connector.ComputeProvenanceTag(c.connectorID, intentData, responseBytes, 3600, connector.TrustLevelVerified)

	effectData, err := json.Marshal(effectPayload{
		Type:           "slack.list_channels.effect",
		ToolName:       "slack.list_channels",
		ContentHash:    contentHash,
		ProvenanceHash: provTag.ResponseHash,
	})
	if err != nil {
		return nil, fmt.Errorf("slack: marshal effect: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectData, c.connectorID, c.nextSeq()); err != nil {
		return nil, fmt.Errorf("slack: append effect: %w", err)
	}

	return result, nil
}

func (c *Connector) executeUpdateMessage(ctx context.Context, params map[string]any) (any, error) {
	dataClass := "slack.message.update"

	// 1. ZeroTrust gate
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "slack.update_message.intent",
		ToolName: "slack.update_message",
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("slack: marshal intent: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentData, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("slack: append intent: %w", err)
	}

	// 3. Build request from params
	req := &UpdateMessageRequest{
		ChannelID: stringParam(params, "channel_id"),
		MessageTS: stringParam(params, "message_ts"),
		Text:      stringParam(params, "text"),
	}

	// 4. Execute via client
	result, err := c.client.UpdateMessage(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("slack: update_message: %w", err)
	}

	// 5. EFFECT node
	contentHash, _ := canonicalize.CanonicalHash(result)
	responseBytes, _ := json.Marshal(result)
	provTag := connector.ComputeProvenanceTag(c.connectorID, intentData, responseBytes, 3600, connector.TrustLevelVerified)

	effectData, err := json.Marshal(effectPayload{
		Type:           "slack.update_message.effect",
		ToolName:       "slack.update_message",
		ContentHash:    contentHash,
		ProvenanceHash: provTag.ResponseHash,
	})
	if err != nil {
		return nil, fmt.Errorf("slack: marshal effect: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectData, c.connectorID, c.nextSeq()); err != nil {
		return nil, fmt.Errorf("slack: append effect: %w", err)
	}

	return result, nil
}

// nextSeq returns the next monotonic sequence number.
func (c *Connector) nextSeq() uint64 {
	return c.seq.Add(1)
}

// stringParam extracts a string parameter from the params map.
func stringParam(params map[string]any, key string) string {
	v, ok := params[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// intParam extracts an integer parameter from the params map with a default.
func intParam(params map[string]any, key string, defaultVal int) int {
	v, ok := params[key]
	if !ok {
		return defaultVal
	}
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case int64:
		return int(n)
	default:
		return defaultVal
	}
}
