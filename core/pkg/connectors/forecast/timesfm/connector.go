package timesfm

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"
)

// ToolForecast is the tool name exposed by this connector.
const ToolForecast = "timesfm.forecast"

// Config configures a new TimesFM Connector.
type Config struct {
	ConnectorID   string
	APIKey        string
	RatePerMinute int // 0 → use default (120)
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

// Connector is the self-contained HELM TimesFM probabilistic forecasting connector.
//
// It composes:
//   - Client:       HTTP bridge to the TimesFM API
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

// NewConnector creates a new TimesFM connector.
func NewConnector(cfg Config) *Connector {
	if cfg.ConnectorID == "" {
		cfg.ConnectorID = "timesfm-v1"
	}
	ratePerMin := cfg.RatePerMinute
	if ratePerMin <= 0 {
		ratePerMin = 120
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
		"timesfm.series.forecast",
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
	case ToolForecast:
		return c.executeForecast(ctx, params)
	default:
		return nil, fmt.Errorf("timesfm: unknown tool %q", toolName)
	}
}

func (c *Connector) executeForecast(ctx context.Context, params map[string]any) (any, error) {
	// 1. Rate limit gate
	if !c.rl.allow() {
		return nil, fmt.Errorf("gate denied: rate limit exceeded (timesfm.series.forecast)")
	}

	// 2. INTENT node
	seq := c.nextSeq()
	intentData, err := json.Marshal(intentPayload{
		Type:     "timesfm.forecast.intent",
		ToolName: ToolForecast,
		Params:   params,
	})
	if err != nil {
		return nil, fmt.Errorf("timesfm: marshal intent: %w", err)
	}
	c.graph.append("INTENT", c.connectorID, seq, intentData)

	// 3. Build request from params
	req := &ForecastRequest{
		Symbol:       stringParam(params, "symbol"),
		TargetSeries: stringParam(params, "target_series"),
		HistoryDays:  intParam(params, "history_days", 30),
		HorizonSteps: intParam(params, "horizon_steps", 10),
		Quantiles:    float64SliceParam(params, "quantiles", []float64{0.1, 0.5, 0.9}),
	}

	// 4. Execute via client
	result, err := c.client.Forecast(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("timesfm: forecast: %w", err)
	}

	// 5. Compute content hash and stamp result
	hash, _ := ContentHash(result)
	result.ContentHash = hash

	// 6. EFFECT node
	responseBytes, _ := json.Marshal(result)
	provHash, _ := provenanceHash(c.connectorID, intentData, responseBytes)
	effectData, err := json.Marshal(effectPayload{
		Type:           "timesfm.forecast.effect",
		ToolName:       ToolForecast,
		ContentHash:    hash,
		ProvenanceHash: provHash,
	})
	if err != nil {
		return nil, fmt.Errorf("timesfm: marshal effect: %w", err)
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

// float64SliceParam extracts a []float64 parameter from the params map with a default.
func float64SliceParam(params map[string]any, key string, defaultVal []float64) []float64 {
	v, ok := params[key]
	if !ok {
		return defaultVal
	}
	switch val := v.(type) {
	case []float64:
		return val
	case []any:
		out := make([]float64, 0, len(val))
		for _, elem := range val {
			if f, ok := elem.(float64); ok {
				out = append(out, f)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return defaultVal
}
