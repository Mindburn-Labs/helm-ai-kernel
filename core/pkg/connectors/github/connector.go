package github

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/connector"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// Ensure Connector implements effects.Connector at compile time.
var _ effects.Connector = (*Connector)(nil)

// Connector is the HELM connector for the GitHub API.
//
// It composes:
//   - Client:     HTTP bridge to GitHub REST API
//   - ZeroTrust:  connector trust gate (rate limits, data classes)
//   - ProofGraph: cryptographic receipt chain
//
// Every tool call produces an INTENT -> EFFECT chain in the ProofGraph.
type Connector struct {
	client      *Client
	gate        *connector.ZeroTrustGate
	graph       *proofgraph.Graph
	connectorID string
	seq         atomic.Uint64
}

// Config configures a new GitHub connector.
//
// Token is optional. When empty, the underlying Client returns "not connected"
// errors for every method — useful for unit tests and schema-validation paths
// that should not touch the network. Set Token (a GitHub personal access token,
// classic or fine-grained) to enable real API calls.
type Config struct {
	BaseURL     string
	ConnectorID string
	Token       string
}

// NewConnector creates a new GitHub connector.
//
// If cfg.Token is non-empty, the connector will make authenticated requests
// to the GitHub REST API with rate-limit awareness and retry-on-transient.
// If cfg.Token is empty, every tool call returns a "not connected" error
// (preserving backward compatibility with token-less unit tests).
func NewConnector(cfg Config) *Connector {
	if cfg.ConnectorID == "" {
		cfg.ConnectorID = ConnectorID
	}

	gate := connector.NewZeroTrustGate()
	gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        cfg.ConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      3600,
		AllowedDataClasses: AllowedDataClasses(),
		RateLimitPerMinute: 30,
		RequireProvenance:  true,
	})

	var client *Client
	if cfg.Token != "" {
		client = NewClientWithToken(cfg.BaseURL, cfg.Token)
	} else {
		client = NewClient(cfg.BaseURL)
	}

	return &Connector{
		client:      client,
		gate:        gate,
		graph:       proofgraph.NewGraph(),
		connectorID: cfg.ConnectorID,
	}
}

// ID returns the connector identifier.
func (c *Connector) ID() string {
	return c.connectorID
}

// Execute dispatches a tool call through the zero-trust gate and records it in
// the ProofGraph. Implements effects.Connector.
func (c *Connector) Execute(ctx context.Context, permit *effects.EffectPermit, toolName string, params map[string]any) (any, error) {
	// 1. Validate permit.ConnectorID matches
	if permit.ConnectorID != c.connectorID {
		return nil, fmt.Errorf("github: permit connector_id %q does not match %q", permit.ConnectorID, c.connectorID)
	}

	// 2. Resolve data class for this tool
	dataClass, ok := toolDataClassMap[toolName]
	if !ok {
		return nil, fmt.Errorf("github: unknown tool %q", toolName)
	}

	// 3. Gate check
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("github: gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 4. Compute input hash via canonicalize.CanonicalHash
	inputHash, err := canonicalize.CanonicalHash(params)
	if err != nil {
		return nil, fmt.Errorf("github: canonical hash of params: %w", err)
	}

	// 5. Append INTENT node to ProofGraph
	intentPayload, err := json.Marshal(map[string]any{
		"type":       "github.intent",
		"tool":       toolName,
		"input_hash": inputHash,
		"permit_id":  permit.PermitID,
	})
	if err != nil {
		return nil, fmt.Errorf("github: marshal intent payload: %w", err)
	}
	seq := c.seq.Add(1)
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentPayload, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("github: append intent: %w", err)
	}

	// 6. Dispatch to appropriate client method
	result, execErr := c.dispatch(ctx, toolName, params)

	// 7. Append EFFECT node to ProofGraph
	effectEntry := map[string]any{
		"type":       "github.effect",
		"tool":       toolName,
		"input_hash": inputHash,
		"permit_id":  permit.PermitID,
		"success":    execErr == nil,
	}
	if execErr != nil {
		effectEntry["error"] = execErr.Error()
	} else {
		outputHash, hashErr := canonicalize.CanonicalHash(result)
		if hashErr == nil {
			effectEntry["output_hash"] = outputHash
		}
	}
	effectPayload, _ := json.Marshal(effectEntry)
	seq = c.seq.Add(1)
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectPayload, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("github: append effect: %w", err)
	}

	if execErr != nil {
		return nil, execErr
	}
	return result, nil
}

// dispatch routes to the appropriate client method based on toolName.
func (c *Connector) dispatch(ctx context.Context, toolName string, params map[string]any) (any, error) {
	switch toolName {
	case "github.list_prs":
		repo := stringParam(params, "repo")
		if repo == "" {
			return nil, fmt.Errorf("github: list_prs: missing required param repo")
		}
		state := stringParam(params, "state")
		if state == "" {
			state = "open"
		}
		return c.client.ListPRs(ctx, repo, state)

	case "github.read_pr":
		repo := stringParam(params, "repo")
		if repo == "" {
			return nil, fmt.Errorf("github: read_pr: missing required param repo")
		}
		number, ok := intParam(params, "number")
		if !ok {
			return nil, fmt.Errorf("github: read_pr: missing required param number")
		}
		return c.client.ReadPR(ctx, repo, number)

	case "github.create_issue":
		req := &CreateIssueRequest{
			Repo:      stringParam(params, "repo"),
			Title:     stringParam(params, "title"),
			Body:      stringParam(params, "body"),
			Labels:    stringSliceParam(params, "labels"),
			Assignees: stringSliceParam(params, "assignees"),
		}
		if req.Repo == "" {
			return nil, fmt.Errorf("github: create_issue: missing required param repo")
		}
		if req.Title == "" {
			return nil, fmt.Errorf("github: create_issue: missing required param title")
		}
		return c.client.CreateIssue(ctx, req)

	case "github.add_comment":
		issueNumber, ok := intParam(params, "issue_number")
		if !ok {
			return nil, fmt.Errorf("github: add_comment: missing required param issue_number")
		}
		req := &AddCommentRequest{
			Repo:        stringParam(params, "repo"),
			IssueNumber: issueNumber,
			Body:        stringParam(params, "body"),
		}
		if req.Repo == "" {
			return nil, fmt.Errorf("github: add_comment: missing required param repo")
		}
		if req.Body == "" {
			return nil, fmt.Errorf("github: add_comment: missing required param body")
		}
		return c.client.AddComment(ctx, req)

	default:
		return nil, fmt.Errorf("github: unknown tool %q", toolName)
	}
}

// Graph returns the ProofGraph for inspection/export.
func (c *Connector) Graph() *proofgraph.Graph {
	return c.graph
}

// stringParam extracts a string parameter from the params map.
func stringParam(params map[string]any, key string) string {
	v, _ := params[key].(string)
	return v
}

// intParam extracts an integer parameter from the params map.
// Handles both int and float64 (JSON numbers decode to float64).
func intParam(params map[string]any, key string) (int, bool) {
	switch v := params[key].(type) {
	case int:
		return v, true
	case float64:
		return int(v), true
	case int64:
		return int(v), true
	default:
		return 0, false
	}
}

// stringSliceParam extracts a string slice parameter from the params map.
func stringSliceParam(params map[string]any, key string) []string {
	v, ok := params[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return nil
	}
}
