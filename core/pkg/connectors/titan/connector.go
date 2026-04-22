package titan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/connector"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/nats-io/nats.go"
)

// ── Config ────────────────────────────────────────────────────────────────

// Config configures the Titan connector set.
type Config struct {
	NatsURL      string // e.g. "nats://nats:4222"
	BrainHTTPURL string // e.g. "http://titan-brain:3100" (fallback)
	BrainAPIKey  string
	OpsHTTPURL   string // e.g. "http://titan-opsd:3050"
	OpsSecret    string // HMAC signing key for ops commands
	ExecHTTPURL  string // e.g. "http://titan-execution:3002" (read-only)
}

// ── Runtime Connector ─────────────────────────────────────────────────────

// RuntimeConnector provides read-only access to Titan system state.
type RuntimeConnector struct {
	nc   *nats.Conn
	gate *connector.ZeroTrustGate
	cfg  Config
}

// NewRuntimeConnector creates the Titan runtime connector.
func NewRuntimeConnector(nc *nats.Conn, cfg Config) *RuntimeConnector {
	gate := connector.NewZeroTrustGate()
	gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        RuntimeConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      30,
		RateLimitPerMinute: 600,
		RequireProvenance:  true,
	})
	return &RuntimeConnector{nc: nc, gate: gate, cfg: cfg}
}

// ID returns the connector identifier.
func (c *RuntimeConnector) ID() string { return RuntimeConnectorID }

// GetSystemStatus returns current Titan system state via NATS request-reply.
func (c *RuntimeConnector) GetSystemStatus(ctx context.Context) (*SystemStatus, error) {
	msg, err := c.nc.RequestWithContext(ctx, "titan.cmd.brain.readmodel.query.v1",
		mustJSON(map[string]string{"viewName": "system-summary"}))
	if err != nil {
		return nil, fmt.Errorf("runtime: NATS request failed: %w", err)
	}

	var resp struct {
		View  json.RawMessage `json:"view"`
		Found bool            `json:"found"`
	}
	if err := json.Unmarshal(msg.Data, &resp); err != nil || !resp.Found {
		return nil, fmt.Errorf("runtime: readmodel not found")
	}

	var status SystemStatus
	if err := json.Unmarshal(resp.View, &status); err != nil {
		return nil, fmt.Errorf("runtime: unmarshal failed: %w", err)
	}
	return &status, nil
}

// GetVenueHealth returns venue connectivity status.
func (c *RuntimeConnector) GetVenueHealth(ctx context.Context) ([]VenueHealth, error) {
	msg, err := c.nc.RequestWithContext(ctx, "titan.cmd.brain.readmodel.query.v1",
		mustJSON(map[string]string{"viewName": "venue-health"}))
	if err != nil {
		return nil, fmt.Errorf("runtime: venue-health NATS request failed: %w", err)
	}

	var resp struct {
		View struct {
			Venues []VenueHealth `json:"venues"`
		} `json:"view"`
		Found bool `json:"found"`
	}
	if err := json.Unmarshal(msg.Data, &resp); err != nil || !resp.Found {
		return nil, fmt.Errorf("runtime: venue-health not found")
	}
	return resp.View.Venues, nil
}

// ── Brain Connector ───────────────────────────────────────────────────────

// BrainConnector provides intent submission and strategy state access.
type BrainConnector struct {
	nc   *nats.Conn
	gate *connector.ZeroTrustGate
	cfg  Config
}

// NewBrainConnector creates the Titan brain connector.
func NewBrainConnector(nc *nats.Conn, cfg Config) *BrainConnector {
	gate := connector.NewZeroTrustGate()
	gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        BrainConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      10,
		RateLimitPerMinute: 100,
		RequireProvenance:  true,
	})
	return &BrainConnector{nc: nc, gate: gate, cfg: cfg}
}

// ID returns the connector identifier.
func (c *BrainConnector) ID() string { return BrainConnectorID }

// SubmitIntent submits a governed trade intent from HELM to Titan execution.
func (c *BrainConnector) SubmitIntent(ctx context.Context, intent TradeIntent) error {
	data, err := json.Marshal(intent)
	if err != nil {
		return fmt.Errorf("brain: marshal intent: %w", err)
	}
	subject := fmt.Sprintf("titan.cmd.prediction.execution.place.v1.%s.%s.%s",
		intent.Venue, intent.Symbol, intent.Side)
	return c.nc.Publish(subject, data)
}

// AskCore sends a natural language query to Titan Core (Claude).
func (c *BrainConnector) AskCore(ctx context.Context, message string) (string, error) {
	msg, err := c.nc.RequestWithContext(ctx, "titan.cmd.brain.core.query.v1",
		mustJSON(map[string]interface{}{
			"message":       message,
			"correlationId": fmt.Sprintf("helm-%d", time.Now().UnixMilli()),
		}))
	if err != nil {
		return "", fmt.Errorf("brain: core query failed: %w", err)
	}

	var resp struct {
		Answer string `json:"answer"`
	}
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return "", err
	}
	return resp.Answer, nil
}

// ── Execution Connector ───────────────────────────────────────────────────

// ExecutionConnector provides read-only access to execution state.
type ExecutionConnector struct {
	nc  *nats.Conn
	cfg Config
}

// NewExecutionConnector creates the Titan execution connector.
func NewExecutionConnector(nc *nats.Conn, cfg Config) *ExecutionConnector {
	return &ExecutionConnector{nc: nc, cfg: cfg}
}

// ID returns the connector identifier.
func (c *ExecutionConnector) ID() string { return ExecutionConnectorID }

// GetPositions returns open positions from a specific venue via NATS RPC.
func (c *ExecutionConnector) GetPositions(ctx context.Context, venue string) ([]Position, error) {
	subject := fmt.Sprintf("titan.rpc.execution.get_positions.v1.%s", venue)
	msg, err := c.nc.RequestWithContext(ctx, subject, nil)
	if err != nil {
		return nil, fmt.Errorf("execution: positions request failed: %w", err)
	}

	var resp struct {
		Positions []Position `json:"positions"`
	}
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return nil, err
	}
	return resp.Positions, nil
}

// GetBalances returns account balances from a specific venue.
func (c *ExecutionConnector) GetBalances(ctx context.Context, venue string) (json.RawMessage, error) {
	subject := fmt.Sprintf("titan.rpc.execution.get_balances.v1.%s", venue)
	msg, err := c.nc.RequestWithContext(ctx, subject, nil)
	if err != nil {
		return nil, fmt.Errorf("execution: balances request failed: %w", err)
	}
	return msg.Data, nil
}

// ── Ops Connector ─────────────────────────────────────────────────────────

// OpsConnector proxies operator commands through OpsD with signature enforcement.
type OpsConnector struct {
	nc  *nats.Conn
	cfg Config
	mu  sync.Mutex
}

// NewOpsConnector creates the Titan ops connector.
func NewOpsConnector(nc *nats.Conn, cfg Config) *OpsConnector {
	return &OpsConnector{nc: nc, cfg: cfg}
}

// ID returns the connector identifier.
func (c *OpsConnector) ID() string { return OpsConnectorID }

// SendCommand sends a signed operator command to Titan OpsD via HTTP.
// Commands are HMAC-signed per packages/shared/src/security/ops-security.ts.
func (c *OpsConnector) SendCommand(ctx context.Context, cmd OpsCommand) (*OpsReceipt, error) {
	data, err := json.Marshal(cmd)
	if err != nil {
		return nil, fmt.Errorf("ops: marshal command: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.OpsHTTPURL+"/v1/ops/command", jsonReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ops-Signature", cmd.Signature)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ops: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	var receipt OpsReceipt
	if err := json.NewDecoder(resp.Body).Decode(&receipt); err != nil {
		return nil, fmt.Errorf("ops: decode receipt: %w", err)
	}
	return &receipt, nil
}

// Halt sends a system halt command.
func (c *OpsConnector) Halt(ctx context.Context, actorID, reason string) (*OpsReceipt, error) {
	return c.SendCommand(ctx, OpsCommand{
		Type:    "HALT",
		ActorID: actorID,
		Reason:  reason,
	})
}

// Resume sends a system resume command.
func (c *OpsConnector) Resume(ctx context.Context, actorID string) (*OpsReceipt, error) {
	return c.SendCommand(ctx, OpsCommand{
		Type:    "RESUME",
		ActorID: actorID,
		Reason:  "operator resume",
	})
}

// ── Evidence Connector ────────────────────────────────────────────────────

// EvidenceConnector provides access to Titan's receipt chain and proof artifacts.
type EvidenceConnector struct {
	nc    *nats.Conn
	graph *proofgraph.Graph
	cfg   Config
}

// NewEvidenceConnector creates the Titan evidence connector.
func NewEvidenceConnector(nc *nats.Conn, graph *proofgraph.Graph, cfg Config) *EvidenceConnector {
	return &EvidenceConnector{nc: nc, graph: graph, cfg: cfg}
}

// ID returns the connector identifier.
func (c *EvidenceConnector) ID() string { return EvidenceConnectorID }

// AppendReceipt appends a Titan receipt to the HELM ProofGraph.
func (c *EvidenceConnector) AppendReceipt(receipt Receipt, nodeType proofgraph.NodeType) error {
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	_, err = c.graph.Append(nodeType, data, "titan-connector", 0)
	return err
}

// ── Helpers ───────────────────────────────────────────────────────────────

func mustJSON(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

func jsonReader(data []byte) *jsonBodyReader {
	return &jsonBodyReader{data: data, pos: 0}
}

type jsonBodyReader struct {
	data []byte
	pos  int
}

func (r *jsonBodyReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
