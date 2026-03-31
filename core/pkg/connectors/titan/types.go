// Package titan provides HELM connectors for the Titan autonomous trading system.
//
// Architecture (5 connectors):
//   - runtime:   Read-only system state, health, mode, venue status, topology
//   - brain:     Plan staging, signal explanation, intent submission, bounded control
//   - execution: Truth snapshots, fills, order state, position deltas
//   - ops:       Halt/resume/throttle, incident ack, signed operator proxy
//   - evidence:  Receipts, proof adapters, export bundles, replay packages
//
// All connectors communicate with Titan via NATS JetStream or HTTP fallback.
// If Titan schema drifts, connectors fail closed. No heuristic parsing.
package titan

import "time"

// ── Shared Types ──────────────────────────────────────────────────────────

// ExecutionMode mirrors Titan's Rust ExecutionMode enum.
type ExecutionMode string

const (
	ModePaper       ExecutionMode = "Paper"
	ModeLiveLimited ExecutionMode = "LiveLimited"
	ModeLiveFull    ExecutionMode = "LiveFull"
)

// ConnectorID constants for all five Titan connectors.
const (
	RuntimeConnectorID   = "titan-runtime"
	BrainConnectorID     = "titan-brain"
	ExecutionConnectorID = "titan-execution"
	OpsConnectorID       = "titan-ops"
	EvidenceConnectorID  = "titan-evidence"
)

// ── Runtime Types ─────────────────────────────────────────────────────────

// SystemStatus is the read-only system snapshot from the runtime connector.
type SystemStatus struct {
	Mode           ExecutionMode `json:"mode"`
	Online         bool          `json:"online"`
	Armed          bool          `json:"armed"`
	Halted         bool          `json:"halted"`
	DEFCON         int           `json:"defcon"`
	CircuitBreaker string        `json:"circuit_breaker"`
	Uptime         time.Duration `json:"uptime"`
}

// VenueHealth reports venue connectivity.
type VenueHealth struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"` // CONNECTED, DISCONNECTED, DEGRADED
	LatencyMs int    `json:"latency_ms,omitempty"`
}

// TopologyNode represents a service in the Titan topology.
type TopologyNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`   // service, infrastructure, gateway, bridge
	Tier   string `json:"tier"`   // data, analysis, risk, execution, cognitive, governance
	Group  string `json:"group"`  // pipeline, helm, infra
	Status string `json:"status"` // alive, degraded, dead
}

// ── Brain Types ───────────────────────────────────────────────────────────

// TradeIntent is the intent envelope emitted by Brain before execution.
type TradeIntent struct {
	IntentID   string `json:"intent_id"`
	StrategyID string `json:"strategy_id"`
	Venue      string `json:"venue"`
	Symbol     string `json:"symbol"`
	Side       string `json:"side"` // BUY, SELL, YES, NO
	Quantity   float64 `json:"quantity"`
	NotionalUSD float64 `json:"notional_usd"`
	SignalSource string `json:"signal_source"`
	RiskRegime  string `json:"risk_regime"`
}

// BrainDecision is a governed decision from Brain.
type BrainDecision struct {
	DecisionID string `json:"decision_id"`
	Type       string `json:"type"` // TRADE, HEDGE, REDUCE, SKIP
	Approved   bool   `json:"approved"`
	Reason     string `json:"reason"`
}

// ── Execution Types ───────────────────────────────────────────────────────

// Fill is an order fill event from the execution engine.
type Fill struct {
	FillID    string  `json:"fill_id"`
	Venue     string  `json:"venue"`
	Symbol    string  `json:"symbol"`
	Side      string  `json:"side"`
	Quantity  float64 `json:"quantity"`
	FillPrice float64 `json:"fill_price"`
	Timestamp time.Time `json:"timestamp"`
	OrderID   string  `json:"order_id,omitempty"`
}

// Position is an open position from shadow state.
type Position struct {
	Symbol     string  `json:"symbol"`
	Venue      string  `json:"venue"`
	Side       string  `json:"side"`
	Size       float64 `json:"size"`
	EntryPrice float64 `json:"entry_price"`
	MarkPrice  float64 `json:"mark_price"`
	PnL        float64 `json:"pnl"`
}

// ── Ops Types ─────────────────────────────────────────────────────────────

// OpsCommand is a signed operator command routed through OpsD.
type OpsCommand struct {
	Type      string `json:"type"` // HALT, RESUME, THROTTLE, FLATTEN, ARM, DISARM
	ActorID   string `json:"actor_id"`
	Reason    string `json:"reason"`
	Signature string `json:"signature"` // HMAC-SHA256
}

// OpsReceipt is the result of an OpsD command execution.
type OpsReceipt struct {
	CommandID string `json:"command_id"`
	Status    string `json:"status"` // SUCCESS, FAILURE
	Error     string `json:"error,omitempty"`
}

// ── Evidence Types ────────────────────────────────────────────────────────

// Receipt is a HELM receipt from Titan's ReceiptChain.
type Receipt struct {
	ReceiptID    string `json:"receipt_id"`
	DecisionID   string `json:"decision_id"`
	Status       string `json:"status"` // APPROVED, DENIED
	Signature    string `json:"signature"`
	LamportClock int64  `json:"lamport_clock"`
	PrevHash     string `json:"prev_hash"`
}

// TradeReceiptBundle is the full receipt bundle for a governed trade.
type TradeReceiptBundle struct {
	TradeID          string  `json:"trade_id"`
	Principal        string  `json:"principal"`
	PlanHash         string  `json:"plan_hash"`
	PolicyHash       string  `json:"policy_hash"`
	SignalSource     string  `json:"signal_source"`
	StrategyID       string  `json:"strategy_id"`
	Venue            string  `json:"venue"`
	Symbol           string  `json:"symbol"`
	SizingInputs     map[string]interface{} `json:"sizing_inputs"`
	RiskRegime       string  `json:"risk_regime"`
	ApprovalRefs     []string `json:"approval_refs,omitempty"`
	FillRefs         []string `json:"fill_refs"`
	FinalStateDelta  map[string]interface{} `json:"final_state_delta"`
}
