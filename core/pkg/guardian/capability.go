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
	// ContextKeyCapabilityToken carries a task-bound signed grant. It is
	// removed from request context before any receipt or audit record is built.
	ContextKeyCapabilityToken = "capability_token"
	// ContextKeyTaskID binds a presented token to the current task.
	ContextKeyTaskID = "task_id"
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

// WithCapabilityTokenVerifier attaches the signed task-token gate. A
// presented token is verified and consumed before downstream policy/PDP
// evaluation; an absent token leaves registry-only capability dispatch intact.
func WithCapabilityTokenVerifier(verifier *capability.TokenVerifier) GuardianOption {
	return func(g *Guardian) { g.capabilityVerifier = verifier }
}

// SetCapabilityTokenVerifier replaces the task-token verifier.
// Deprecated: configure WithCapabilityTokenVerifier at construction so the
// roster hash accurately describes the running gate composition.
func (g *Guardian) SetCapabilityTokenVerifier(verifier *capability.TokenVerifier) {
	g.capabilityVerifier = verifier
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

	if rawToken, presented := req.Context[ContextKeyCapabilityToken]; presented {
		// Capability tokens are bearer credentials. Never bind the raw token
		// into a signed DecisionRecord or an audit entry, including on denial.
		delete(req.Context, ContextKeyCapabilityToken)
		if g.capabilityVerifier == nil {
			return g.capabilityShortCircuit(
				span,
				req,
				activeSnapshot,
				policyVersion,
				contracts.VerdictDeny,
				contracts.ReasonCapabilityTokenInvalid,
				fmt.Sprintf("%s: a capability token was presented but no verifier is configured", contracts.ReasonCapabilityTokenInvalid),
				"CAPABILITY_TOKEN_INVALID_DENY",
			)
		}
		taskID, _ := req.Context[ContextKeyTaskID].(string)
		var args map[string]interface{}
		if rawArgs, ok := req.Context["arguments"].(map[string]interface{}); ok {
			args = rawArgs
		}
		presented, decodeErr := capability.DecodeToken(rawToken)
		if decodeErr != nil {
			return g.capabilityShortCircuit(
				span,
				req,
				activeSnapshot,
				policyVersion,
				contracts.VerdictDeny,
				contracts.ReasonCapabilityTokenInvalid,
				fmt.Sprintf("%s: malformed token", contracts.ReasonCapabilityTokenInvalid),
				"CAPABILITY_TOKEN_INVALID_DENY",
			)
		}
		token, err := g.capabilityVerifier.Verify(capability.VerifyRequest{
			Presented:    presented,
			TaskID:       taskID,
			CapabilityID: entry.Manifest.CapabilityID,
			ManifestHash: entry.Hash,
			Args:         args,
		})
		if err != nil {
			return g.capabilityShortCircuit(
				span,
				req,
				activeSnapshot,
				policyVersion,
				contracts.VerdictDeny,
				contracts.ReasonCapabilityTokenInvalid,
				fmt.Sprintf("%s: %s", contracts.ReasonCapabilityTokenInvalid, err),
				"CAPABILITY_TOKEN_INVALID_DENY",
			)
		}
		req.Context["capability_token_id"] = token.TokenID
		span.SetAttributes(
			attribute.Bool("capability.token_valid", true),
			attribute.String("capability.token_id", token.TokenID),
		)
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
