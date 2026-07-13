package safedep

import "context"

// AuthorityRequest contains only server-owned identifiers used to obtain the
// Safe Deprecation authority record for an execution. Callers must not derive
// this request from a DecisionRecord.InputContext or an effect parameter map.
// Those maps are explanatory payloads and may be controlled by an untrusted
// client before a decision is issued.
type AuthorityRequest struct {
	TenantID    string
	WorkspaceID string
	SessionID   string
	SubjectID   string
	DecisionID  string
	// EffectDigestHash is the decision- and intent-bound identifier for the
	// effect semantics. Do not key authority on Effect.EffectID: that display
	// identifier is intentionally outside the canonical effect digest.
	EffectDigestHash string
	EffectType       string
	Action           string
	ToolName         string
}

// AuthorityResolver resolves Safe Deprecation evidence from a server-owned
// attestation, continuity, and emergency-authority store. The returned gate
// request is intentionally separate from caller-provided decision context so
// a client cannot weaken a hazardous action by changing what is signed.
type AuthorityResolver interface {
	Resolve(ctx context.Context, request AuthorityRequest) (GateRequest, error)
}

// AuthorityResolverFunc adapts a function for tests and simple adapters.
type AuthorityResolverFunc func(context.Context, AuthorityRequest) (GateRequest, error)

func (f AuthorityResolverFunc) Resolve(ctx context.Context, request AuthorityRequest) (GateRequest, error) {
	return f(ctx, request)
}
