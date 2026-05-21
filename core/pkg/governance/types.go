package governance

import (
	"time"
)

// DecisionRecord is the output of the Decision Engine.
// It proves that an Intent was evaluated against Policy and permitted.
type DecisionRecord struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"` // Binding
	IntentID  string    `json:"intent_id"`
	Decision  string    `json:"decision"` // PERMIT, DENY
	PolicyID  string    `json:"policy_id"`
	Timestamp time.Time `json:"timestamp"`
	Signature []byte    `json:"signature"` // Signed by Governance Key

	// V2: Cryptographic binding to effect semantics
	EffectDigest string `json:"effect_digest,omitempty"`
}

// ExecutionIntent is the token authorizing the Executor to act.
// It MUST contain the DecisionRecord ID and be signed by the Kernel.
type ExecutionIntent struct {
	ID               string `json:"id"`
	TenantID         string `json:"tenant_id"` // Binding
	TargetCapability string `json:"target_capability"`
	Payload          []byte `json:"payload"`
	DecisionID       string `json:"decision_id"`
	Signature        []byte `json:"signature"` // Signed by Governance Key
}
