package gdocs_drive

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

// Connector is the HELM connector for Google Docs and Google Drive.
//
// It composes:
//   - Client:     HTTP bridge to Google APIs
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

// Config configures a new Google Docs/Drive connector.
type Config struct {
	BaseURL     string
	ConnectorID string
}

// NewConnector creates a new Google Docs/Drive connector.
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

// Execute dispatches a tool call through the zero-trust gate and records it in
// the ProofGraph. Implements effects.Connector.
func (c *Connector) Execute(ctx context.Context, permit *effects.EffectPermit, toolName string, params map[string]any) (any, error) {
	// 1. Validate permit.ConnectorID matches
	if permit.ConnectorID != c.connectorID {
		return nil, fmt.Errorf("gdocs_drive: permit connector_id %q does not match %q", permit.ConnectorID, c.connectorID)
	}

	// 2. Resolve data class for this tool
	dataClass, ok := toolDataClassMap[toolName]
	if !ok {
		return nil, fmt.Errorf("gdocs_drive: unknown tool %q", toolName)
	}

	// 3. Gate check
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gdocs_drive: gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 4. Compute input hash via canonicalize.CanonicalHash
	inputHash, err := canonicalize.CanonicalHash(params)
	if err != nil {
		return nil, fmt.Errorf("gdocs_drive: canonical hash of params: %w", err)
	}

	// 5. Append INTENT node to ProofGraph
	intentPayload, err := json.Marshal(map[string]any{
		"type":       "gdocs_drive.intent",
		"tool":       toolName,
		"input_hash": inputHash,
		"permit_id":  permit.PermitID,
	})
	if err != nil {
		return nil, fmt.Errorf("gdocs_drive: marshal intent payload: %w", err)
	}
	seq := c.seq.Add(1)
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentPayload, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("gdocs_drive: append intent: %w", err)
	}

	// 6. Dispatch to appropriate client method
	result, execErr := c.dispatch(ctx, toolName, params)

	// 7. Append EFFECT node to ProofGraph
	effectEntry := map[string]any{
		"type":       "gdocs_drive.effect",
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
		return nil, fmt.Errorf("gdocs_drive: append effect: %w", err)
	}

	if execErr != nil {
		return nil, execErr
	}
	return result, nil
}

// dispatch routes to the appropriate client method based on toolName.
func (c *Connector) dispatch(ctx context.Context, toolName string, params map[string]any) (any, error) {
	switch toolName {
	case "gdocs.read_document":
		documentID, _ := params["document_id"].(string)
		if documentID == "" {
			return nil, fmt.Errorf("gdocs_drive: read_document: missing required param document_id")
		}
		return c.client.ReadDocument(ctx, documentID)

	case "gdocs.create_document":
		req := &CreateDocRequest{
			Title:    stringParam(params, "title"),
			Body:     stringParam(params, "body"),
			FolderID: stringParam(params, "folder_id"),
		}
		if req.Title == "" {
			return nil, fmt.Errorf("gdocs_drive: create_document: missing required param title")
		}
		return c.client.CreateDocument(ctx, req)

	case "gdocs.append_to_document":
		req := &AppendRequest{
			DocumentID: stringParam(params, "document_id"),
			Content:    stringParam(params, "content"),
		}
		if req.DocumentID == "" {
			return nil, fmt.Errorf("gdocs_drive: append_to_document: missing required param document_id")
		}
		if err := c.client.AppendToDocument(ctx, req); err != nil {
			return nil, err
		}
		return map[string]string{"status": "appended"}, nil

	case "gdrive.list_files":
		pageToken, _ := params["page_token"].(string)
		return c.client.ListFiles(ctx, pageToken)

	case "gdrive.get_file":
		fileID, _ := params["file_id"].(string)
		if fileID == "" {
			return nil, fmt.Errorf("gdocs_drive: get_file: missing required param file_id")
		}
		return c.client.GetFile(ctx, fileID)

	default:
		return nil, fmt.Errorf("gdocs_drive: unknown tool %q", toolName)
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
