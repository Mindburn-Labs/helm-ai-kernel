package vibevoice

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"
)

// ToolTranscribe is the tool name exposed by this connector.
const ToolTranscribe = "vibevoice.transcribe"

// Config configures a new VibeVoice Connector.
type Config struct {
	ConnectorID    string
	APIKey         string
	RatePerMinute  int // 0 → use default (60)
}

// graphNode is a lightweight, self-contained INTENT/EFFECT record stored in the
// connector's internal proof chain.  It mirrors the structure of the real
// proofgraph.Node so that it can be wired in without API changes when the
// framework stabilises.
type graphNode struct {
	Kind      string // "INTENT" or "EFFECT"
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

func (g *internalGraph) len() int        { return len(g.nodes) }
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

// Connector is the self-contained HELM VibeVoice ASR connector.
//
// It composes:
//   - Client:       HTTP bridge to the VibeVoice API
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

// NewConnector creates a new VibeVoice connector.
func NewConnector(cfg Config) *Connector {
	if cfg.ConnectorID == "" {
		cfg.ConnectorID = "vibevoice-v1"
	}
	ratePerMin := cfg.RatePerMinute
	if ratePerMin <= 0 {
		ratePerMin = 60
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
		"vibevoice.audio.transcribe",
	}
}

// GraphLen returns the number of nodes in the internal proof graph.
// Provided for testing; replace with Graph() when wiring to the framework.
func (c *Connector) GraphLen() int { return c.graph.len() }

// GraphNodes returns all nodes in the internal proof graph.
func (c *Connector) GraphNodes() []graphNode { return c.graph.all() }

// Execute dispatches a tool call through the connector with rate-limit enforcement
// and INTENT → EFFECT graph recording.
func (c *Connector) Execute(ctx context.Context, toolName string, params map[string]any) (any, error) {
	switch toolName {
	case ToolTranscribe:
		return c.executeTranscribe(ctx, params)
	default:
		return nil, fmt.Errorf("vibevoice: unknown tool %q", toolName)
	}
}

func (c *Connector) executeTranscribe(ctx context.Context, params map[string]any) (any, error) {
	// 1. Rate limit gate
	if !c.rl.allow() {
		return nil, fmt.Errorf("gate denied: rate limit exceeded (vibevoice.audio.transcribe)")
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "vibevoice.transcribe.intent",
		ToolName: ToolTranscribe,
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("vibevoice: marshal intent: %w", err)
	}
	c.graph.append("INTENT", c.connectorID, seq, intentData)

	// 3. Build request from params
	req := &TranscriptionRequest{
		AudioURL:     stringParam(params, "audio_url"),
		LanguageCode: stringParam(params, "language_code"),
		SampleRate:   intParam(params, "sample_rate", 16000),
		Encoding:     stringParam(params, "encoding"),
	}

	// 4. Execute via client
	result, err := c.client.Transcribe(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("vibevoice: transcribe: %w", err)
	}

	// 5. Compute content hash and stamp result
	hash, _ := ContentHash(result)
	result.ContentHash = hash

	// 6. EFFECT node
	responseBytes, _ := json.Marshal(result)
	provHash, _ := provenanceHash(c.connectorID, intentData, responseBytes)
	effectData, err := json.Marshal(effectPayload{
		Type:           "vibevoice.transcribe.effect",
		ToolName:       ToolTranscribe,
		ContentHash:    hash,
		ProvenanceHash: provHash,
	})
	if err != nil {
		return nil, fmt.Errorf("vibevoice: marshal effect: %w", err)
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
