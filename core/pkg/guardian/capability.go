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
	return nil, false
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
