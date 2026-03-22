package effects

import (
	"context"
	"time"
)

// EffectType classifies the kind of side effect being executed.
// The taxonomy is defined in protocols/json-schemas/effects/.
type EffectType string

const (
	EffectTypeRead    EffectType = "READ"
	EffectTypeWrite   EffectType = "WRITE"
	EffectTypeDelete  EffectType = "DELETE"
	EffectTypeExecute EffectType = "EXECUTE"
	EffectTypeNetwork EffectType = "NETWORK"
	EffectTypeFinance EffectType = "FINANCE"
)

// EffectRequest is the canonical input to the effects gateway.
// It represents a fully governed request to produce an external side effect.
type EffectRequest struct {
	RequestID   string         `json:"request_id"`
	EffectType  EffectType     `json:"effect_type"`
	ConnectorID string         `json:"connector_id"`
	ToolName    string         `json:"tool_name"`
	Params      map[string]any `json:"params"`
	ResourceRef string         `json:"resource_ref"`
	PlanHash    string         `json:"plan_hash,omitempty"`
	PolicyHash  string         `json:"policy_hash,omitempty"`
	VerdictHash string         `json:"verdict_hash,omitempty"`
	RequestedAt time.Time      `json:"requested_at"`
}

// EffectOutcome is the result of executing an effect through the gateway.
type EffectOutcome struct {
	RequestID   string        `json:"request_id"`
	PermitID    string        `json:"permit_id"`
	Success     bool          `json:"success"`
	Output      any           `json:"output,omitempty"`
	Error       string        `json:"error,omitempty"`
	OutputHash  string        `json:"output_hash,omitempty"`
	Duration    time.Duration `json:"duration"`
	CompletedAt time.Time     `json:"completed_at"`
}

// EffectPermit is the canonical authorization token for a single effect execution.
// It binds a KernelVerdict to a specific connector, action, and scope.
type EffectPermit struct {
	PermitID    string      `json:"permit_id"`
	IntentHash  string      `json:"intent_hash"`
	VerdictHash string      `json:"verdict_hash"`
	PlanHash    string      `json:"plan_hash,omitempty"`
	PolicyHash  string      `json:"policy_hash,omitempty"`
	EffectType  EffectType  `json:"effect_type"`
	ConnectorID string      `json:"connector_id"`
	Scope       EffectScope `json:"scope"`
	ResourceRef string      `json:"resource_ref"`
	ExpiresAt   time.Time   `json:"expires_at"`
	SingleUse   bool        `json:"single_use"`
	Nonce       string      `json:"nonce"`
	IssuedAt    time.Time   `json:"issued_at"`
	IssuerID    string      `json:"issuer_id"`
	Signature   string      `json:"signature,omitempty"`
}

// EffectScope defines the boundaries of what a permit allows.
type EffectScope struct {
	AllowedAction string   `json:"allowed_action"`
	AllowedParams []string `json:"allowed_params,omitempty"`
	DenyPatterns  []string `json:"deny_patterns,omitempty"`
}

// Connector is the minimal interface for effect execution.
// Connectors MUST validate the permit before executing any action.
// Connectors MUST NOT exceed the permit scope.
type Connector interface {
	Execute(ctx context.Context, permit *EffectPermit, toolName string, params map[string]any) (any, error)
	ID() string
}

// Gateway is the canonical interface for the effects execution chokepoint.
// ALL external effects MUST flow through this gateway.
type Gateway interface {
	Execute(ctx context.Context, req *EffectRequest) (*EffectOutcome, error)
	RegisterConnector(c Connector)
}

// NonceStore tracks consumed permit nonces to prevent replay.
type NonceStore interface {
	HasNonce(nonce string) bool
	RecordNonce(nonce string) error
}
