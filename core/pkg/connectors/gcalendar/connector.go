package gcalendar

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/connector"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// Compile-time interface compliance check.
var _ effects.Connector = (*Connector)(nil)

// Config configures a new Google Calendar Connector.
type Config struct {
	ConnectorID string
	BaseURL     string
}

// Connector is the HELM Google Calendar connector.
//
// It composes:
//   - Client:      HTTP bridge to Google Calendar API
//   - ZeroTrust:   connector trust gate (rate limits, provenance)
//   - ProofGraph:  cryptographic receipt chain
//
// Every Calendar action produces an INTENT -> EFFECT chain in the ProofGraph.
type Connector struct {
	client      *Client
	gate        *connector.ZeroTrustGate
	graph       *proofgraph.Graph
	connectorID string
	seq         atomic.Uint64
}

// NewConnector creates a new Google Calendar connector with ZeroTrust enforcement.
func NewConnector(cfg Config) *Connector {
	if cfg.ConnectorID == "" {
		cfg.ConnectorID = "gcalendar-v1"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://www.googleapis.com/calendar/v3"
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
	}
}

// ID returns the connector identifier.
func (c *Connector) ID() string {
	return c.connectorID
}

// AllowedDataClasses returns the set of data classes this connector supports.
func AllowedDataClasses() []string {
	return []string{
		"gcalendar.event.create",
		"gcalendar.event.read",
		"gcalendar.event.update",
		"gcalendar.availability.read",
	}
}

// Graph returns the ProofGraph for inspection/export.
func (c *Connector) Graph() *proofgraph.Graph {
	return c.graph
}

// Execute dispatches a tool call through the Google Calendar connector with full
// ZeroTrust gate enforcement and ProofGraph receipt generation.
func (c *Connector) Execute(ctx context.Context, permit *effects.EffectPermit, toolName string, params map[string]any) (any, error) {
	switch toolName {
	case "gcalendar.create_event":
		return c.executeCreateEvent(ctx, params)
	case "gcalendar.read_availability":
		return c.executeReadAvailability(ctx, params)
	case "gcalendar.update_event":
		return c.executeUpdateEvent(ctx, params)
	case "gcalendar.list_events":
		return c.executeListEvents(ctx, params)
	default:
		return nil, fmt.Errorf("gcalendar: unknown tool %q", toolName)
	}
}

func (c *Connector) executeCreateEvent(ctx context.Context, params map[string]any) (any, error) {
	dataClass := "gcalendar.event.create"

	// 1. ZeroTrust gate
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "gcalendar.create_event.intent",
		ToolName: "gcalendar.create_event",
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("gcalendar: marshal intent: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentData, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("gcalendar: append intent: %w", err)
	}

	// 3. Build request from params
	req := &CreateEventRequest{
		Title:       stringParam(params, "title"),
		Description: stringParam(params, "description"),
		Location:    stringParam(params, "location"),
	}
	if st := stringParam(params, "start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			req.StartTime = t
		}
	}
	if et := stringParam(params, "end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			req.EndTime = t
		}
	}
	if attendees, ok := params["attendee_emails"]; ok {
		req.AttendeeEmails = toStringSlice(attendees)
	}

	// 4. Execute via client
	result, err := c.client.CreateEvent(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gcalendar: create_event: %w", err)
	}

	// 5. EFFECT node
	contentHash, _ := canonicalize.CanonicalHash(result)
	responseBytes, _ := json.Marshal(result)
	provTag := connector.ComputeProvenanceTag(c.connectorID, intentData, responseBytes, 3600, connector.TrustLevelVerified)

	effectData, err := json.Marshal(effectPayload{
		Type:           "gcalendar.create_event.effect",
		ToolName:       "gcalendar.create_event",
		ContentHash:    contentHash,
		ProvenanceHash: provTag.ResponseHash,
	})
	if err != nil {
		return nil, fmt.Errorf("gcalendar: marshal effect: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectData, c.connectorID, c.nextSeq()); err != nil {
		return nil, fmt.Errorf("gcalendar: append effect: %w", err)
	}

	return result, nil
}

func (c *Connector) executeReadAvailability(ctx context.Context, params map[string]any) (any, error) {
	dataClass := "gcalendar.availability.read"

	// 1. ZeroTrust gate
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "gcalendar.read_availability.intent",
		ToolName: "gcalendar.read_availability",
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("gcalendar: marshal intent: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentData, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("gcalendar: append intent: %w", err)
	}

	// 3. Parse time range from params
	var startTime, endTime time.Time
	if st := stringParam(params, "start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			startTime = t
		}
	}
	if et := stringParam(params, "end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			endTime = t
		}
	}

	// 4. Execute via client
	result, err := c.client.ReadAvailability(ctx, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("gcalendar: read_availability: %w", err)
	}

	// 5. EFFECT node
	contentHash, _ := canonicalize.CanonicalHash(result)
	responseBytes, _ := json.Marshal(result)
	provTag := connector.ComputeProvenanceTag(c.connectorID, intentData, responseBytes, 3600, connector.TrustLevelVerified)

	effectData, err := json.Marshal(effectPayload{
		Type:           "gcalendar.read_availability.effect",
		ToolName:       "gcalendar.read_availability",
		ContentHash:    contentHash,
		ProvenanceHash: provTag.ResponseHash,
	})
	if err != nil {
		return nil, fmt.Errorf("gcalendar: marshal effect: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectData, c.connectorID, c.nextSeq()); err != nil {
		return nil, fmt.Errorf("gcalendar: append effect: %w", err)
	}

	return result, nil
}

func (c *Connector) executeUpdateEvent(ctx context.Context, params map[string]any) (any, error) {
	dataClass := "gcalendar.event.update"

	// 1. ZeroTrust gate
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "gcalendar.update_event.intent",
		ToolName: "gcalendar.update_event",
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("gcalendar: marshal intent: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentData, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("gcalendar: append intent: %w", err)
	}

	// 3. Build request from params
	req := &UpdateEventRequest{
		EventID:     stringParam(params, "event_id"),
		Title:       stringParam(params, "title"),
		Description: stringParam(params, "description"),
		Location:    stringParam(params, "location"),
	}
	if st := stringParam(params, "start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			req.StartTime = t
		}
	}
	if et := stringParam(params, "end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			req.EndTime = t
		}
	}
	if attendees, ok := params["attendee_emails"]; ok {
		req.AttendeeEmails = toStringSlice(attendees)
	}

	// 4. Execute via client
	result, err := c.client.UpdateEvent(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gcalendar: update_event: %w", err)
	}

	// 5. EFFECT node
	contentHash, _ := canonicalize.CanonicalHash(result)
	responseBytes, _ := json.Marshal(result)
	provTag := connector.ComputeProvenanceTag(c.connectorID, intentData, responseBytes, 3600, connector.TrustLevelVerified)

	effectData, err := json.Marshal(effectPayload{
		Type:           "gcalendar.update_event.effect",
		ToolName:       "gcalendar.update_event",
		ContentHash:    contentHash,
		ProvenanceHash: provTag.ResponseHash,
	})
	if err != nil {
		return nil, fmt.Errorf("gcalendar: marshal effect: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectData, c.connectorID, c.nextSeq()); err != nil {
		return nil, fmt.Errorf("gcalendar: append effect: %w", err)
	}

	return result, nil
}

func (c *Connector) executeListEvents(ctx context.Context, params map[string]any) (any, error) {
	dataClass := "gcalendar.event.read"

	// 1. ZeroTrust gate
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "gcalendar.list_events.intent",
		ToolName: "gcalendar.list_events",
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("gcalendar: marshal intent: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentData, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("gcalendar: append intent: %w", err)
	}

	// 3. Parse time range from params
	var startTime, endTime time.Time
	if st := stringParam(params, "start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			startTime = t
		}
	}
	if et := stringParam(params, "end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			endTime = t
		}
	}
	maxResults := intParam(params, "max_results", 50)

	// 4. Execute via client
	result, err := c.client.ListEvents(ctx, startTime, endTime, maxResults)
	if err != nil {
		return nil, fmt.Errorf("gcalendar: list_events: %w", err)
	}

	// 5. EFFECT node
	contentHash, _ := canonicalize.CanonicalHash(result)
	responseBytes, _ := json.Marshal(result)
	provTag := connector.ComputeProvenanceTag(c.connectorID, intentData, responseBytes, 3600, connector.TrustLevelVerified)

	effectData, err := json.Marshal(effectPayload{
		Type:           "gcalendar.list_events.effect",
		ToolName:       "gcalendar.list_events",
		ContentHash:    contentHash,
		ProvenanceHash: provTag.ResponseHash,
	})
	if err != nil {
		return nil, fmt.Errorf("gcalendar: marshal effect: %w", err)
	}
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectData, c.connectorID, c.nextSeq()); err != nil {
		return nil, fmt.Errorf("gcalendar: append effect: %w", err)
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
