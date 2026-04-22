package identity

import "time"

// IdentityToken represents an authenticated identity via SSO.
type IdentityToken struct {
	Subject string                 `json:"sub"`
	Email   string                 `json:"email"`
	Issuer  string                 `json:"iss"`
	Claims  map[string]interface{} `json:"claims"`
}

// ── Delegation Session Contracts ──────────────────────────────
//
// DelegationSession is the canonical delegation primitive. Per HELM Standard
// v1.3, every delegation starts as deny-all and only explicitly added
// capabilities are permitted. A session can only narrow the delegator's own
// authority — it can never expand it.
//
// Delegation sessions compile into P2-equivalent narrowing overlays in the
// Guardian policy evaluation chain. They are NOT a parallel authorization
// system.
//
// ProofGraph representation:
//   - Session creation → ATTESTATION node
//   - Identity binding → TRUST_EVENT node
//   - Session revocation → TRUST_EVENT node

// DelegationSession represents a cryptographically-bound, time-boxed
// delegation of a subset of one principal's authority to another.
type DelegationSession struct {
	SessionID            string            `json:"session_id"`
	DelegatorPrincipal   string            `json:"delegator_principal"`
	DelegatePrincipal    string            `json:"delegate_principal"`
	AllowedTools         []string          `json:"allowed_tools"`
	Capabilities         []CapabilityGrant `json:"capabilities"`
	RiskCeiling          string            `json:"risk_ceiling"`           // max risk class delegate can act under
	SessionNonce         string            `json:"session_nonce"`          // anti-replay nonce
	VerifierBinding      string            `json:"verifier_binding"`       // PKCE-style verifier hash
	DelegationPolicyHash string            `json:"delegation_policy_hash"` // hash of delegation policy
	TrustRootRef         string            `json:"trust_root_ref"`         // reference to trust registry entry
	PrincipalSeqFloor    uint64            `json:"principal_seq_floor"`    // causal ordering floor
	CreatedWithMFA       bool              `json:"created_with_mfa"`
	ExpiresAt            time.Time         `json:"expires_at"`
	CreatedAt            time.Time         `json:"created_at"`
	SignatureEd25519     string            `json:"signature"`
}

// CapabilityGrant defines a specific resource/action scope within a
// delegation session. Each grant narrows the delegator's authority to
// a specific resource with specific allowed actions.
type CapabilityGrant struct {
	Resource   string   `json:"resource"`              // tool name, MCP endpoint, or resource identifier
	Actions    []string `json:"actions"`               // e.g. ["EXECUTE_TOOL", "READ"]
	Conditions []string `json:"conditions,omitempty"`   // CEL expressions for further narrowing
}

type PrincipalType string

const (
	PrincipalUser    PrincipalType = "USER"
	PrincipalAgent   PrincipalType = "AGENT"
	PrincipalService PrincipalType = "SERVICE"
)

// Principal represents any entity that can be authenticated.
type Principal interface {
	ID() string
	Type() PrincipalType
}

// AgentIdentity represents a HELM agent.
type AgentIdentity struct {
	AgentID     string
	DelegatorID string // User who delegated execution
	Scopes      []string
}

func (a *AgentIdentity) ID() string          { return a.AgentID }
func (a *AgentIdentity) Type() PrincipalType { return PrincipalAgent }
