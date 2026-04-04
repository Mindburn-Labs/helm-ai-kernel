package chandra

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"
)

// ToolParseDocument is the tool name exposed by this connector.
const ToolParseDocument = "chandra.parse_document"

// Config configures a new Chandra Connector.
type Config struct {
	ConnectorID   string
	APIKey        string
	RatePerMinute int // 0 → use default (30)
}

// graphNode is a lightweight, self-contained INTENT/EFFECT record stored in the
// connector's internal proof chain.
type graphNode struct {
	Kind      string
	Source    string
	Sequence  uint64
	Data      []byte
	Timestamp time.Time
}

// internalGraph is a minimal append-only DAG used instead of
// proofgraph.Graph to keep this package self-contained.
type internalGraph struct {
	nodes []graphNode
}

func (g *internalGraph) append(kind, source string, seq uint64, data []byte) {
	g.nodes = append(g.nodes, graphNode{
		Kind:      kind,
		Source:    source,
		Sequence:  seq,
		Data:      data,
		Timestamp: time.Now(),
	})
}

func (g *internalGraph) len() int         { return len(g.nodes) }
func (g *internalGraph) all() []graphNode { return g.nodes }

// rateLimiter is a simple per-minute token-bucket counter.
type rateLimiter struct {
	limit     int
	count     int
	windowEnd time.Time
}

func newRateLimiter(perMinute int) *rateLimiter {
	return &rateLimiter{
		limit:     perMinute,
		windowEnd: time.Now().Add(time.Minute),
	}
}

func (r *rateLimiter) allow() bool {
	now := time.Now()
	if now.After(r.windowEnd) {
		r.count = 0
		r.windowEnd = now.Add(time.Minute)
	}
	if r.count >= r.limit {
		return false
	}
	r.count++
	return true
}

// Connector is the self-contained HELM Chandra document intelligence connector.
//
// It composes:
//   - Client:       HTTP bridge to the Chandra API
//   - rateLimiter:  per-minute call budget
//   - internalGraph: append-only INTENT → EFFECT chain
//
// Every call produces an INTENT → EFFECT pair in the internal graph.
// When the connector framework stabilises, this can be wired to the real
// effects.Connector interface and proofgraph.Graph without changing the
// public API.
type Connector struct {
	client      *Client
	graph       *internalGraph
	rl          *rateLimiter
	connectorID string
	seq         atomic.Uint64
}

// NewConnector creates a new Chandra connector.
func NewConnector(cfg Config) *Connector {
	if cfg.ConnectorID == "" {
		cfg.ConnectorID = "chandra-v1"
	}
	ratePerMin := cfg.RatePerMinute
	if ratePerMin <= 0 {
		ratePerMin = 30
	}
	return &Connector{
		client:      NewClient(cfg.APIKey),
		graph:       &internalGraph{},
		rl:          newRateLimiter(ratePerMin),
		connectorID: cfg.ConnectorID,
	}
}

// ID returns the connector identifier.
func (c *Connector) ID() string { return c.connectorID }

// AllowedDataClasses returns the set of data classes this connector supports.
func AllowedDataClasses() []string {
	return []string{
		"chandra.document.parse",
	}
}

// GraphLen returns the number of nodes in the internal proof graph.
func (c *Connector) GraphLen() int { return c.graph.len() }

// GraphNodes returns all nodes in the internal proof graph.
func (c *Connector) GraphNodes() []graphNode { return c.graph.all() }

// Execute dispatches a tool call through the connector with rate-limit enforcement
// and INTENT → EFFECT graph recording.
func (c *Connector) Execute(ctx context.Context, toolName string, params map[string]any) (any, error) {
	switch toolName {
	case ToolParseDocument:
		return c.executeParseDocument(ctx, params)
	default:
		return nil, fmt.Errorf("chandra: unknown tool %q", toolName)
	}
}

func (c *Connector) executeParseDocument(ctx context.Context, params map[string]any) (any, error) {
	// 1. Rate limit gate
	if !c.rl.allow() {
		return nil, fmt.Errorf("gate denied: rate limit exceeded (chandra.document.parse)")
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "chandra.parse_document.intent",
		ToolName: ToolParseDocument,
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("chandra: marshal intent: %w", err)
	}
	c.graph.append("INTENT", c.connectorID, seq, intentData)

	// 3. Build request from params
	req := &ParseRequest{
		DocumentURL: stringParam(params, "document_url"),
		MediaType:   stringParam(params, "media_type"),
		Options: ParseOptions{
			ExtractTables:  boolParam(params, "extract_tables"),
			ExtractImages:  boolParam(params, "extract_images"),
			OCREnabled:     boolParam(params, "ocr_enabled"),
			LayoutAnalysis: boolParam(params, "layout_analysis"),
		},
	}

	// 4. Execute via client
	result, err := c.client.ParseDocument(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("chandra: parse_document: %w", err)
	}

	// 5. Compute content hash and stamp result
	hash, _ := ContentHash(result)
	result.ContentHash = hash

	// 6. EFFECT node
	responseBytes, _ := json.Marshal(result)
	provHash, _ := provenanceHash(c.connectorID, intentData, responseBytes)
	effectData, err := json.Marshal(effectPayload{
		Type:           "chandra.parse_document.effect",
		ToolName:       ToolParseDocument,
		ContentHash:    hash,
		ProvenanceHash: provHash,
	})
	if err != nil {
		return nil, fmt.Errorf("chandra: marshal effect: %w", err)
	}
	c.graph.append("EFFECT", c.connectorID, c.nextSeq(), effectData)

	return result, nil
}

// nextSeq returns the next monotonic sequence number.
func (c *Connector) nextSeq() uint64 { return c.seq.Add(1) }

// stringParam extracts a string parameter from the params map.
func stringParam(params map[string]any, key string) string {
	v, ok := params[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// boolParam extracts a bool parameter from the params map.
func boolParam(params map[string]any, key string) bool {
	v, ok := params[key]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}
