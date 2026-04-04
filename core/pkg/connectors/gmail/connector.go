package gmail

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/connector"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/connectors/oauth2"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// Compile-time interface compliance check.
var _ effects.Connector = (*Connector)(nil)

// Config configures a new Gmail Connector.
type Config struct {
	ConnectorID string
	TokenStore  oauth2.TokenStore
	BaseURL     string
}

// Connector is the HELM Gmail connector.
//
// It composes:
//   - Client:      HTTP bridge to Gmail API
//   - ZeroTrust:   connector trust gate (rate limits, provenance)
//   - ProofGraph:  cryptographic receipt chain
//   - TokenStore:  OAuth2 token management
//
// Every Gmail action produces an INTENT -> EFFECT chain in the ProofGraph.
type Connector struct {
	client      *Client
	gate        *connector.ZeroTrustGate
	graph       *proofgraph.Graph
	connectorID string
	tokenStore  oauth2.TokenStore
	seq         atomic.Uint64
}

// NewConnector creates a new Gmail connector with ZeroTrust enforcement.
func NewConnector(cfg Config) *Connector {
	if cfg.ConnectorID == "" {
		cfg.ConnectorID = "gmail-v1"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://gmail.googleapis.com"
	}

	gate := connector.NewZeroTrustGate()
	gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        cfg.ConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      3600,
		AllowedDataClasses: AllowedDataClasses(),
		RateLimitPerMinute: 60,
		RequireProvenance:  true,
	})

	return &Connector{
		client:      NewClient(cfg.BaseURL),
		gate:        gate,
		graph:       proofgraph.NewGraph(),
		connectorID: cfg.ConnectorID,
		tokenStore:  cfg.TokenStore,
	}
}

// ID returns the connector identifier.
func (c *Connector) ID() string {
	return c.connectorID
}

// AllowedDataClasses returns the set of data classes this connector supports.
func AllowedDataClasses() []string {
	return []string{
		"gmail.send.outbound",
		"gmail.read.inbound",
		"gmail.draft.internal",
		"gmail.list.inbound",
	}
}

// Graph returns the ProofGraph for inspection/export.
func (c *Connector) Graph() *proofgraph.Graph {
	return c.graph
}

// Execute dispatches a tool call through the Gmail connector with full
// ZeroTrust gate enforcement and ProofGraph receipt generation.
func (c *Connector) Execute(ctx context.Context, permit *effects.EffectPermit, toolName string, params map[string]any) (any, error) {
	switch toolName {
	case "gmail.send":
		return c.executeSend(ctx, params)
	case "gmail.read_thread":
		return c.executeReadThread(ctx, params)
	case "gmail.list_threads":
		return c.executeListThreads(ctx, params)
	case "gmail.create_draft":
		return c.executeCreateDraft(ctx, params)
	default:
		return nil, fmt.Errorf("gmail: unknown tool %q", toolName)
	}
}

func (c *Connector) executeSend(ctx context.Context, params map[string]any) (any, error) {
	dataClass := "gmail.send.outbound"

	// 1. ZeroTrust gate
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "gmail.send.intent",
		ToolName: "gmail.send",
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("gmail: marshal intent: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentData, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("gmail: append intent: %w", err)
	}

	// 3. Build request from params
	req := &SendRequest{
		Subject: stringParam(params, "subject"),
		Body:    stringParam(params, "body"),
	}
	if to, ok := params["to"]; ok {
		req.To = toStringSlice(to)
	}

	// 4. Execute via client
	result, err := c.client.Send(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gmail: send: %w", err)
	}

	// 5. EFFECT node
	contentHash, _ := canonicalize.CanonicalHash(result)
	responseBytes, _ := json.Marshal(result)
	provTag := connector.ComputeProvenanceTag(c.connectorID, intentData, responseBytes, 3600, connector.TrustLevelVerified)

	effectData, err := json.Marshal(effectPayload{
		Type:           "gmail.send.effect",
		ToolName:       "gmail.send",
		ContentHash:    contentHash,
		ProvenanceHash: provTag.ResponseHash,
	})
	if err != nil {
		return nil, fmt.Errorf("gmail: marshal effect: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectData, c.connectorID, c.nextSeq()); err != nil {
		return nil, fmt.Errorf("gmail: append effect: %w", err)
	}

	return result, nil
}

func (c *Connector) executeReadThread(ctx context.Context, params map[string]any) (any, error) {
	dataClass := "gmail.read.inbound"

	// 1. ZeroTrust gate
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "gmail.read_thread.intent",
		ToolName: "gmail.read_thread",
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("gmail: marshal intent: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentData, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("gmail: append intent: %w", err)
	}

	// 3. Execute via client
	threadID := stringParam(params, "thread_id")
	result, err := c.client.ReadThread(ctx, threadID)
	if err != nil {
		return nil, fmt.Errorf("gmail: read_thread: %w", err)
	}

	// 4. EFFECT node
	contentHash, _ := canonicalize.CanonicalHash(result)
	responseBytes, _ := json.Marshal(result)
	provTag := connector.ComputeProvenanceTag(c.connectorID, intentData, responseBytes, 3600, connector.TrustLevelVerified)

	effectData, err := json.Marshal(effectPayload{
		Type:           "gmail.read_thread.effect",
		ToolName:       "gmail.read_thread",
		ContentHash:    contentHash,
		ProvenanceHash: provTag.ResponseHash,
	})
	if err != nil {
		return nil, fmt.Errorf("gmail: marshal effect: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectData, c.connectorID, c.nextSeq()); err != nil {
		return nil, fmt.Errorf("gmail: append effect: %w", err)
	}

	return result, nil
}

func (c *Connector) executeListThreads(ctx context.Context, params map[string]any) (any, error) {
	dataClass := "gmail.list.inbound"

	// 1. ZeroTrust gate
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "gmail.list_threads.intent",
		ToolName: "gmail.list_threads",
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("gmail: marshal intent: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentData, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("gmail: append intent: %w", err)
	}

	// 3. Execute via client
	query := stringParam(params, "query")
	maxResults := intParam(params, "max_results", 20)
	result, err := c.client.ListThreads(ctx, query, maxResults)
	if err != nil {
		return nil, fmt.Errorf("gmail: list_threads: %w", err)
	}

	// 4. EFFECT node
	contentHash, _ := canonicalize.CanonicalHash(result)
	responseBytes, _ := json.Marshal(result)
	provTag := connector.ComputeProvenanceTag(c.connectorID, intentData, responseBytes, 3600, connector.TrustLevelVerified)

	effectData, err := json.Marshal(effectPayload{
		Type:           "gmail.list_threads.effect",
		ToolName:       "gmail.list_threads",
		ContentHash:    contentHash,
		ProvenanceHash: provTag.ResponseHash,
	})
	if err != nil {
		return nil, fmt.Errorf("gmail: marshal effect: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectData, c.connectorID, c.nextSeq()); err != nil {
		return nil, fmt.Errorf("gmail: append effect: %w", err)
	}

	return result, nil
}

func (c *Connector) executeCreateDraft(ctx context.Context, params map[string]any) (any, error) {
	dataClass := "gmail.draft.internal"

	// 1. ZeroTrust gate
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "gmail.create_draft.intent",
		ToolName: "gmail.create_draft",
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("gmail: marshal intent: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentData, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("gmail: append intent: %w", err)
	}

	// 3. Build request from params
	req := &DraftRequest{
		Subject: stringParam(params, "subject"),
		Body:    stringParam(params, "body"),
	}
	if to, ok := params["to"]; ok {
		req.To = toStringSlice(to)
	}

	// 4. Execute via client
	result, err := c.client.CreateDraft(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gmail: create_draft: %w", err)
	}

	// 5. EFFECT node
	contentHash, _ := canonicalize.CanonicalHash(result)
	responseBytes, _ := json.Marshal(result)
	provTag := connector.ComputeProvenanceTag(c.connectorID, intentData, responseBytes, 3600, connector.TrustLevelVerified)

	effectData, err := json.Marshal(effectPayload{
		Type:           "gmail.create_draft.effect",
		ToolName:       "gmail.create_draft",
		ContentHash:    contentHash,
		ProvenanceHash: provTag.ResponseHash,
	})
	if err != nil {
		return nil, fmt.Errorf("gmail: marshal effect: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectData, c.connectorID, c.nextSeq()); err != nil {
		return nil, fmt.Errorf("gmail: append effect: %w", err)
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

// toStringSlice converts a parameter value to a string slice.
func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		result := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}
