package guardian

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capability"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Context keys for governed capability dispatch (capability-manifest/v1,
// docs/governance/capability-registry.md). Chunk 1 scope: resolution,
// manifest-hash drift check, and context enrichment. Token mint/verify and
// rollback binding are follow-up chunks.
const (
	// ContextKeyCapabilityID names the capability being dispatched. When a
	// capability registry is configured and this key is present, the guardian
	// resolves it before any other evaluation.
	ContextKeyCapabilityID = "capability_id"
	// ContextKeyCapabilityManifestHash optionally pins the manifest revision
	// the caller believes it is dispatching against. A mismatch with the
	// registry's hash fails closed (manifest drift).
	ContextKeyCapabilityManifestHash = "capability_manifest_hash"
	// ContextKeyCapabilityToken optionally presents a capability-token/v1
	// grant (JSON string or map). When a token verifier is configured, the
	// token is verified and one use consumed; any failure denies fail closed.
	ContextKeyCapabilityToken = "capability_token"
	// ContextKeyTaskID binds the dispatch to a task; required when a
	// capability token is presented.
	ContextKeyTaskID = "task_id"
)

// WithCapabilityRegistry attaches a governed capability registry. Dispatch
// requests carrying ContextKeyCapabilityID are resolved before policy
// evaluation: unknown capabilities ESCALATE (quarantine posture), manifest
// hash mismatches DENY (fail closed), and resolved manifests enrich the
// decision context for downstream policy/PDP evaluation.
func WithCapabilityRegistry(reg *capability.Registry) GuardianOption {
	return func(g *Guardian) { g.capabilityRegistry = reg }
}

// SetCapabilityRegistry attaches or replaces the capability registry.
func (g *Guardian) SetCapabilityRegistry(reg *capability.Registry) {
	g.capabilityRegistry = reg
}

// CapabilityRegistry returns the attached registry, or nil.
func (g *Guardian) CapabilityRegistry() *capability.Registry {
	return g.capabilityRegistry
}

// WithCapabilityTokenVerifier attaches a capability token verifier (chunk 2).
// When set, a presented ContextKeyCapabilityToken is verified and consumed;
// any verification failure DENYs with CAPABILITY_TOKEN_INVALID.
func WithCapabilityTokenVerifier(v *capability.TokenVerifier) GuardianOption {
	return func(g *Guardian) { g.capabilityVerifier = v }
}

// SetCapabilityTokenVerifier attaches or replaces the token verifier.
func (g *Guardian) SetCapabilityTokenVerifier(v *capability.TokenVerifier) {
	g.capabilityVerifier = v
}

// resolveCapabilityGate implements chunk-1 registry resolution. It returns
// (decision, true) when the request is short-circuited (unknown capability or
// manifest drift); otherwise it enriches req.Context and returns (nil, false).
// When no registry is configured or the request carries no capability_id,
// behavior is unchanged from before this feature existed.
func (g *Guardian) resolveCapabilityGate(span trace.Span, req *DecisionRequest) (*contracts.DecisionRecord, bool) {
	if g.capabilityRegistry == nil {
		return nil, false
	}
	capabilityID, ok := stringFromContext(req.Context, ContextKeyCapabilityID)
	if !ok || capabilityID == "" {
		return nil, false
	}

	span.SetAttributes(attribute.String("capability.id", capabilityID))

	entry := g.capabilityRegistry.Resolve(capabilityID)
	if entry == nil {
		// capability-registry.md: unknown capability = fail closed (quarantine).
		decision := &contracts.DecisionRecord{
			ID:           newDecisionID(),
			Timestamp:    g.clock.Now(),
			Verdict:      string(contracts.VerdictEscalate),
			ReasonCode:   string(contracts.ReasonCapabilityUnknown),
			Reason:       fmt.Sprintf("%s: capability %q is not registered; quarantined for review", contracts.ReasonCapabilityUnknown, capabilityID),
			InputContext: req.Context,
		}
		span.SetAttributes(attribute.Bool("capability.registered", false))
		if signErr := g.signer.SignDecision(decision); signErr != nil {
			return nil, false
		}
		g.appendCapabilityAudit("CAPABILITY_UNKNOWN_QUARANTINE", decision)
		return decision, true
	}

	span.SetAttributes(
		attribute.Bool("capability.registered", true),
		attribute.String("capability.manifest_hash", entry.Hash),
		attribute.String("capability.effect_class", string(entry.Manifest.EffectClass)),
	)

	// Manifest drift: caller pinned a revision the registry no longer serves.
	if pinned, hasPin := stringFromContext(req.Context, ContextKeyCapabilityManifestHash); hasPin && pinned != "" && pinned != entry.Hash {
		decision := &contracts.DecisionRecord{
			ID:           newDecisionID(),
			Timestamp:    g.clock.Now(),
			Verdict:      string(contracts.VerdictDeny),
			ReasonCode:   string(contracts.ReasonCapabilityManifestDrift),
			Reason:       fmt.Sprintf("%s: capability %q manifest drift: caller pinned %s, registry serves %s", contracts.ReasonCapabilityManifestDrift, capabilityID, pinned, entry.Hash),
			InputContext: req.Context,
		}
		if signErr := g.signer.SignDecision(decision); signErr != nil {
			return nil, false
		}
		g.appendCapabilityAudit("CAPABILITY_MANIFEST_DRIFT_DENY", decision)
		return decision, true
	}

	// Enrich the decision context with manifest facts so downstream policy,
	// PDP, and receipt surfaces evaluate against the same registered truth.
	if req.Context == nil {
		req.Context = make(map[string]interface{})
	}
	req.Context["capability_manifest_hash"] = entry.Hash
	req.Context["capability_effect_class"] = string(entry.Manifest.EffectClass)
	req.Context["capability_reversibility"] = string(entry.Manifest.Reversibility)
	req.Context["capability_data_boundary"] = string(entry.Manifest.DataBoundary)
	req.Context["capability_risk_score"] = entry.Manifest.RiskScore
	req.Context["capability_required_permit_level"] = string(entry.Manifest.RequiredPermitLevel)
	if entry.Manifest.Routing.MinModelTier != "" {
		req.Context["capability_min_model_tier"] = entry.Manifest.Routing.MinModelTier
	}

	// Chunk 2: when a capability token is presented and a verifier is
	// configured, verify it (signature, lifecycle, task binding, manifest
	// drift, constraints) and consume one use. Any failure denies fail closed.
	if g.capabilityVerifier != nil {
		if rawToken, present := req.Context[ContextKeyCapabilityToken]; present {
			taskID, _ := stringFromContext(req.Context, ContextKeyTaskID)
			token, tokenErr := g.verifyCapabilityToken(rawToken, taskID, req)
			if tokenErr != nil {
				decision := &contracts.DecisionRecord{
					ID:           newDecisionID(),
					Timestamp:    g.clock.Now(),
					Verdict:      string(contracts.VerdictDeny),
					ReasonCode:   string(contracts.ReasonCapabilityTokenInvalid),
					Reason:       fmt.Sprintf("%s: %s", contracts.ReasonCapabilityTokenInvalid, tokenErr.Error()),
					InputContext: req.Context,
				}
				span.SetAttributes(attribute.Bool("capability.token_valid", false))
				if signErr := g.signer.SignDecision(decision); signErr != nil {
					return nil, false
				}
				g.appendCapabilityAudit("CAPABILITY_TOKEN_INVALID_DENY", decision)
				return decision, true
			}
			span.SetAttributes(
				attribute.Bool("capability.token_valid", true),
				attribute.String("capability.token_id", token.TokenID),
			)
			req.Context["capability_token_id"] = token.TokenID
		}
	}
	return nil, false
}

// verifyCapabilityToken decodes and verifies a presented token. Dispatch
// arguments are taken from req.Context["arguments"] when present (map form)
// for args_digest constraint checking.
func (g *Guardian) verifyCapabilityToken(rawToken interface{}, taskID string, req *DecisionRequest) (*capability.Token, error) {
	token, err := capability.DecodeToken(rawToken)
	if err != nil {
		return nil, err
	}
	var args map[string]interface{}
	if rawArgs, ok := req.Context["arguments"].(map[string]interface{}); ok {
		args = rawArgs
	}
	return g.capabilityVerifier.Verify(capability.VerifyRequest{
		Presented: token,
		TaskID:    taskID,
		Args:      args,
	})
}

func (g *Guardian) appendCapabilityAudit(action string, decision *contracts.DecisionRecord) {
	if g.auditLog == nil {
		return
	}
	decisionBytes, err := canonicalize.JCS(decision)
	if err != nil {
		return
	}
	_, _ = g.auditLog.Append("guardian", action, decision.ID, string(decisionBytes))
}

func stringFromContext(ctx map[string]interface{}, key string) (string, bool) {
	if ctx == nil {
		return "", false
	}
	v, ok := ctx[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
