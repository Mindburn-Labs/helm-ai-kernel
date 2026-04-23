package kernelruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// KernelRuntime is the sole gateway for effecting change or reading state.
// All capabilities must be invoked through this interface.
type KernelRuntime interface {
	// SubmitIntent proposes an effect.
	// It enters the Decision Engine -> ExecutionIntent -> SafeExecutor pipeline.
	SubmitIntent(ctx context.Context, intent *SignedIntent) (*Receipt, error)

	// Query executes a read against a projection.
	// Reads are auditable and subject to policy.
	Query(ctx context.Context, query *QueryRequest) (*QueryResult, error)

	// CheckHealth returns the status of the runtime components.
	CheckHealth(ctx context.Context) error
}

// SignedIntent is a wrapper around an intent payload, signed by an actor.
// This is the Node 9 (Decision & Execution) intent envelope.
type SignedIntent struct {
	TenantID  string
	ActorID   string
	Context   *ActorContext // V2 Context
	Payload   []byte        // JSON serialized intent
	Signature []byte
}

// ActorContext v2
// See helm://schemas/actor_context/v2.json
type ActorContext struct {
	TenantID               string                 `json:"tenant_id"`
	OrgID                  string                 `json:"org_id"`
	WorkspaceID            string                 `json:"workspace_id"`
	RoleID                 string                 `json:"role_id"`
	Environment            string                 `json:"environment"` // dev|stage|prod
	Jurisdiction           string                 `json:"jurisdiction"`
	DataClassesAllowed     []string               `json:"data_classes_allowed"`
	ApprovalAuthorityScope map[string]interface{} `json:"approval_authority_scope"`
	Identity               Identity               `json:"identity"`
	SessionID              string                 `json:"session_id"`
	RequestID              string                 `json:"request_id"`
}

type Identity struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	AuthTime     string `json:"auth_time"`
	AuthStrength string `json:"auth_strength"`
}

// Receipt is the proof of submission (async) or execution (sync).
type Receipt struct {
	ID        string
	TenantID  string
	Status    string
	Timestamp int64
}

// CanonicalHash returns the deterministic hash of the ActorContext.
func (c *ActorContext) CanonicalHash() (string, error) {
	// Canonical JSON hashing using standard library (sorts keys)
	bytes, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal failed: %w", err)
	}
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:]), nil
}

// QueryRequest defines a read operation.
type QueryRequest struct {
	Projection string
	Params     map[string]interface{}
}

// QueryResult returns data.
type QueryResult struct {
	Data interface{}
}
