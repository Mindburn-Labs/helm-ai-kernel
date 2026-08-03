// Package guardian capability registry gate.
//
// The registry is optional for backward compatibility. When injected, requests
// that name capability_id resolve to a content-addressed manifest before PRG or
// PDP evaluation; unknown and drifted references cannot silently dispatch.
package guardian

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capability"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	// ContextKeyCapabilityID names the registered capability being dispatched.
	ContextKeyCapabilityID = "capability_id"
	// ContextKeyCapabilityManifestHash optionally pins the manifest revision
	// expected by the caller. A non-empty mismatch denies fail closed.
	ContextKeyCapabilityManifestHash = "capability_manifest_hash"
)

// WithCapabilityRegistry attaches the governed capability registry. Requests
// that carry ContextKeyCapabilityID resolve before PRG/PDP evaluation, after
// policy-snapshot and SafeDep preconditions.
func WithCapabilityRegistry(reg *capability.Registry) GuardianOption {
	return func(g *Guardian) { g.capabilityRegistry = reg }
}

// SetCapabilityRegistry replaces the capability registry.
// Deprecated: configure WithCapabilityRegistry at construction so the roster
// hash accurately describes the running gate composition.
func (g *Guardian) SetCapabilityRegistry(reg *capability.Registry) {
	g.capabilityRegistry = reg
}

// CapabilityRegistry returns the attached registry, or nil.
func (g *Guardian) CapabilityRegistry() *capability.Registry {
	return g.capabilityRegistry
}

// resolveCapabilityGate resolves the registry entry and enriches req.Context
// for the downstream policy/PDP path. A non-nil decision is a signed,
// fail-closed terminal result; a nil decision lets the normal pipeline
// continue unchanged.
func (g *Guardian) resolveCapabilityGate(
	span trace.Span,
	req *DecisionRequest,
	activeSnapshot *policyreconcile.EffectivePolicySnapshot,
	policyVersion string,
) (*contracts.DecisionRecord, error) {
	if g.capabilityRegistry == nil || req.Context == nil {
		return nil, nil
	}

	rawID, present := req.Context[ContextKeyCapabilityID]
	if !present {
		return nil, nil
	}
	capabilityID, validID := rawID.(string)
	if !validID || capabilityID == "" {
		return g.capabilityShortCircuit(
			span,
			req,
			activeSnapshot,
			policyVersion,
			contracts.VerdictEscalate,
			contracts.ReasonCapabilityUnknown,
			fmt.Sprintf("%s: capability_id must be a non-empty string", contracts.ReasonCapabilityUnknown),
			"CAPABILITY_UNKNOWN_QUARANTINE",
		)
	}

	span.SetAttributes(attribute.String("capability.id", capabilityID))
	entry := g.capabilityRegistry.Resolve(capabilityID)
	if entry == nil {
		span.SetAttributes(attribute.Bool("capability.registered", false))
		return g.capabilityShortCircuit(
			span,
			req,
			activeSnapshot,
			policyVersion,
			contracts.VerdictEscalate,
			contracts.ReasonCapabilityUnknown,
			fmt.Sprintf("%s: capability %q is not registered; quarantined for review", contracts.ReasonCapabilityUnknown, capabilityID),
			"CAPABILITY_UNKNOWN_QUARANTINE",
		)
	}

	span.SetAttributes(
		attribute.Bool("capability.registered", true),
		attribute.String("capability.manifest_hash", entry.Hash),
		attribute.String("capability.effect_class", string(entry.Manifest.EffectClass)),
	)

	if rawPin, pinned := req.Context[ContextKeyCapabilityManifestHash]; pinned {
		pin, validPin := rawPin.(string)
		if !validPin || (pin != "" && pin != entry.Hash) {
			return g.capabilityShortCircuit(
				span,
				req,
				activeSnapshot,
				policyVersion,
				contracts.VerdictDeny,
				contracts.ReasonCapabilityManifestDrift,
				fmt.Sprintf("%s: capability %q is not pinned to the registry manifest revision", contracts.ReasonCapabilityManifestDrift, capabilityID),
				"CAPABILITY_MANIFEST_DRIFT_DENY",
			)
		}
	}

	// Enrich the same request context that downstream PRG/PDP evaluation sees,
	// binding policy decisions to the registry facts rather than caller claims.
	req.Context[ContextKeyCapabilityManifestHash] = entry.Hash
	req.Context["capability_effect_class"] = string(entry.Manifest.EffectClass)
	req.Context["capability_reversibility"] = string(entry.Manifest.Reversibility)
	req.Context["capability_data_boundary"] = string(entry.Manifest.DataBoundary)
	req.Context["capability_risk_score"] = entry.Manifest.RiskScore
	req.Context["capability_required_permit_level"] = string(entry.Manifest.RequiredPermitLevel)
	if entry.Manifest.Routing.MinModelTier != "" {
		req.Context["capability_min_model_tier"] = entry.Manifest.Routing.MinModelTier
	}
	return nil, nil
}

func (g *Guardian) capabilityShortCircuit(
	span trace.Span,
	req *DecisionRequest,
	activeSnapshot *policyreconcile.EffectivePolicySnapshot,
	policyVersion string,
	verdict contracts.Verdict,
	code contracts.ReasonCode,
	reason string,
	auditAction string,
) (*contracts.DecisionRecord, error) {
	decision := &contracts.DecisionRecord{
		ID:             newDecisionID(),
		Timestamp:      g.clock.Now(),
		Verdict:        string(verdict),
		ReasonCode:     string(code),
		Reason:         reason,
		InputContext:   req.Context,
		GateRosterHash: g.gateRosterHash,
	}
	bindRuntimePolicyDecision(decision, activeSnapshot, policyVersion)
	span.SetAttributes(attribute.String("capability.short_circuit", string(code)))

	if g.signer == nil {
		return nil, fmt.Errorf("sign capability decision: signer is not configured")
	}
	if err := g.signer.SignDecision(decision); err != nil {
		return nil, fmt.Errorf("sign capability decision: %w", err)
	}
	g.appendCapabilityAudit(auditAction, decision)
	return decision, nil
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
