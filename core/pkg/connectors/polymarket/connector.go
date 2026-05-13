// Package polymarket provides a HELM connector for the Polymarket prediction market.
//
// Architecture:
//   - constants.go: Connector ID, tool names, data class mappings
//   - types.go:     Order intent, P0 policy, deny result types
//   - policy.go:    P0 policy validation logic
//   - connector.go: High-level connector composing ZeroTrust gate + ProofGraph
//
// IMPORTANT: This connector does NOT submit orders to Polymarket directly.
// It evaluates HELM policy and produces ProofGraph nodes. The Rust execution
// engine (titan-execution-rs) handles actual venue submission.
//
// Per HELM Standard v1.2: every tool call produces an INTENT node chain
// in the ProofGraph DAG. Denied intents produce INTENT nodes with denial payloads.
package polymarket

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

// Ensure Connector implements effects.Connector at compile time.
var _ effects.Connector = (*Connector)(nil)

// Connector is the HELM connector for the Polymarket prediction market.
//
// It composes:
//   - ZeroTrust:  connector trust gate (rate limits, data classes)
//   - ProofGraph: cryptographic receipt chain
//   - P0 policy:  Polymarket-specific risk ceilings
//
// Every tool call produces an INTENT node in the ProofGraph.
// Denied intents are recorded with denial payloads for audit trail.
type Connector struct {
	gate        *connector.ZeroTrustGate
	graph       *proofgraph.Graph
	p0          PolymarketP0
	connectorID string
	seq         atomic.Uint64
}

// Config configures a new Polymarket connector.
type Config struct {
	ConnectorID string
	P0          *PolymarketP0 // nil = DefaultP0()
}

// NewConnector creates a new Polymarket connector.
func NewConnector(cfg Config) *Connector {
	if cfg.ConnectorID == "" {
		cfg.ConnectorID = ConnectorID
	}

	p0 := DefaultP0()
	if cfg.P0 != nil {
		p0 = *cfg.P0
	}

	gate := connector.NewZeroTrustGate()
	gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        cfg.ConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      300, // 5 minutes — trading requires fresh data
		AllowedDataClasses: AllowedDataClasses(),
		RateLimitPerMinute: 30, // Conservative for prediction market orders
		RequireProvenance:  true,
	})

	return &Connector{
		gate:        gate,
		graph:       proofgraph.NewGraph(),
		p0:          p0,
		connectorID: cfg.ConnectorID,
	}
}

// ID returns the connector identifier.
func (c *Connector) ID() string {
	return c.connectorID
}

// Execute dispatches a tool call through the zero-trust gate, validates against P0
// policy, and records the result in the ProofGraph. Implements effects.Connector.
//
// This connector does NOT execute orders. It only evaluates policy and produces
// ProofGraph nodes. The Rust execution engine handles venue submission.
func (c *Connector) Execute(ctx context.Context, permit *effects.EffectPermit, toolName string, params map[string]any) (any, error) {
	// 1. Validate permit.ConnectorID matches
	if permit.ConnectorID != c.connectorID {
		return nil, fmt.Errorf("polymarket: permit connector_id %q does not match %q", permit.ConnectorID, c.connectorID)
	}

	// 2. Resolve data class for this tool
	dataClass, ok := toolDataClassMap[toolName]
	if !ok {
		return nil, fmt.Errorf("polymarket: unknown tool %q", toolName)
	}

	// 3. Gate check (rate limits, data classes, trust level)
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("polymarket: gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 4. Compute input hash via JCS canonicalization
	inputHash, err := canonicalize.CanonicalHash(params)
	if err != nil {
		return nil, fmt.Errorf("polymarket: canonical hash of params: %w", err)
	}

	// 5. Parse intent from params and validate against P0 policy
	intent, parseErr := parseOrderIntent(params)
	if parseErr != nil {
		return nil, fmt.Errorf("polymarket: parse intent: %w", parseErr)
	}

	deny := ValidateIntent(intent, c.p0)

	if deny != nil {
		// 6a. DENIED: emit INTENT node with denial payload
		denialPayload, _ := json.Marshal(map[string]any{
			"type":       "polymarket.intent",
			"tool":       toolName,
			"input_hash": inputHash,
			"permit_id":  permit.PermitID,
			"denied":     true,
			"reason":     deny.Reason,
			"detail":     deny.Detail,
		})
		seq := c.seq.Add(1)
		if _, appendErr := c.graph.Append(proofgraph.NodeTypeIntent, denialPayload, c.connectorID, seq); appendErr != nil {
			return nil, fmt.Errorf("polymarket: append denied intent: %w", appendErr)
		}

		return nil, fmt.Errorf("polymarket: P0 denied: %s — %s", deny.Reason, deny.Detail)
	}

	// 6b. ALLOWED: emit INTENT node with success payload
	intentPayload, err := json.Marshal(map[string]any{
		"type":       "polymarket.intent",
		"tool":       toolName,
		"input_hash": inputHash,
		"permit_id":  permit.PermitID,
		"intent_id":  intent.IntentID,
		"token_id":   intent.TokenID,
		"side":       intent.Side,
		"size":       intent.Size,
		"price":      intent.Price,
		"mode":       intent.Mode,
		"denied":     false,
	})
	if err != nil {
		return nil, fmt.Errorf("polymarket: marshal intent payload: %w", err)
	}
	seq := c.seq.Add(1)
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentPayload, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("polymarket: append intent: %w", err)
	}

	// 7. Return success — Rust execution engine handles actual venue submission
	return map[string]any{
		"status":     "policy_approved",
		"intent_id":  intent.IntentID,
		"token_id":   intent.TokenID,
		"side":       intent.Side,
		"size":       intent.Size,
		"price":      intent.Price,
		"mode":       intent.Mode,
		"input_hash": inputHash,
	}, nil
}

// Graph returns the ProofGraph for inspection/export.
func (c *Connector) Graph() *proofgraph.Graph {
	return c.graph
}

// P0 returns the current P0 policy for inspection.
func (c *Connector) P0() PolymarketP0 {
	return c.p0
}

// parseOrderIntent extracts a PolymarketOrderIntent from the params map.
func parseOrderIntent(params map[string]any) (PolymarketOrderIntent, error) {
	intent := PolymarketOrderIntent{
		IntentID:   stringParam(params, "intent_id"),
		AccountID:  stringParam(params, "account_id"),
		TokenID:    stringParam(params, "token_id"),
		Side:       stringParam(params, "side"),
		Price:      stringParam(params, "price"),
		Size:       stringParam(params, "size"),
		OrderType:  stringParam(params, "order_type"),
		VenueState: stringParam(params, "venue_state"),
		PolicyHash: stringParam(params, "policy_hash"),
		PlanHash:   stringParam(params, "plan_hash"),
		Mode:       stringParam(params, "mode"),
	}

	if v, ok := params["post_only"]; ok {
		if b, ok := v.(bool); ok {
			intent.PostOnly = b
		}
	}

	if v, ok := params["neg_risk"]; ok {
		if b, ok := v.(bool); ok {
			intent.NegRisk = b
		}
	}

	if v, ok := params["expiration_ts"]; ok {
		switch n := v.(type) {
		case float64:
			intent.ExpirationTs = int64(n)
		case int64:
			intent.ExpirationTs = n
		}
	}

	// Validate required fields
	if intent.IntentID == "" {
		return intent, fmt.Errorf("missing required param intent_id")
	}
	if intent.TokenID == "" {
		return intent, fmt.Errorf("missing required param token_id")
	}
	if intent.Side == "" {
		return intent, fmt.Errorf("missing required param side")
	}
	if intent.Size == "" {
		return intent, fmt.Errorf("missing required param size")
	}
	if intent.Price == "" {
		return intent, fmt.Errorf("missing required param price")
	}
	if intent.Mode == "" {
		return intent, fmt.Errorf("missing required param mode")
	}

	return intent, nil
}

// stringParam extracts a string parameter from the params map.
func stringParam(params map[string]any, key string) string {
	v, _ := params[key].(string)
	return v
}
