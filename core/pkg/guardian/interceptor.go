package guardian

import (
	"context"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/threatscan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

const (
	ContextSecurityTrusted = "security_context_trusted"
	ContextCredentialHash  = "credential_hash"
	ContextSessionID       = "session_id"
	ContextSourceChannel   = "source_channel"
	ContextTrustLevel      = "trust_level"
	ContextDestination     = "destination"
)

// IsReservedSecurityContextKey identifies context keys whose values must be
// bound by a trusted transport or adapter boundary, never by caller arguments.
func IsReservedSecurityContextKey(key string) bool {
	switch strings.TrimSpace(key) {
	case ContextSecurityTrusted, ContextCredentialHash, ContextSessionID, ContextSourceChannel, ContextTrustLevel, ContextDestination:
		return true
	default:
		return false
	}
}

// EvaluationContext encapsulates all parameter inputs and transient state
// for a single evaluation transaction across the interceptor boundary.
type EvaluationContext struct {
	Request        DecisionRequest
	ActiveSnapshot *policyreconcile.EffectivePolicySnapshot
	PolicyVersion  string
	ActiveGraph    *prg.Graph
	ActivePDP      pdp.PolicyDecisionPoint
	Tainted        bool
	Decisions      []*contracts.DecisionRecord

	// Transient state populated by interceptors
	Intervention        *contracts.InterventionMetadata
	ThreatScanResult    *contracts.ThreatScanResult
	SessionRiskSnapshot *SessionRiskSnapshot

	// PDP metadata
	PDPBackend      string
	PDPHash         string
	PDPDecisionHash string
}

// Handler represents the next callback in the chain execution sequence.
type Handler func(ctx context.Context, evalCtx *EvaluationContext) (*contracts.DecisionRecord, error)

// BoundaryInterceptor defines the interface for separate evaluation steps.
type BoundaryInterceptor interface {
	Evaluate(ctx context.Context, evalCtx *EvaluationContext, next Handler) (*contracts.DecisionRecord, error)
}

// InterceptorChain coordinates a slice of interceptors wrapped around a final handler.
type InterceptorChain struct {
	interceptors []BoundaryInterceptor
	finalHandler Handler
}

// NewInterceptorChain initializes a new chain.
func NewInterceptorChain(interceptors []BoundaryInterceptor, finalHandler Handler) *InterceptorChain {
	return &InterceptorChain{
		interceptors: interceptors,
		finalHandler: finalHandler,
	}
}

// Execute triggers execution of the pluggable filters in sequence.
func (c *InterceptorChain) Execute(ctx context.Context, evalCtx *EvaluationContext) (*contracts.DecisionRecord, error) {
	var buildChain func(int) Handler
	buildChain = func(index int) Handler {
		if index >= len(c.interceptors) {
			return c.finalHandler
		}
		return func(ctx context.Context, eCtx *EvaluationContext) (*contracts.DecisionRecord, error) {
			return c.interceptors[index].Evaluate(ctx, eCtx, buildChain(index+1))
		}
	}
	return buildChain(0)(ctx, evalCtx)
}

// signDecisionWithContext binds runtime policy details and signs a DecisionRecord using the Guardian's signer.
func (g *Guardian) signDecisionWithContext(decision *contracts.DecisionRecord, evalCtx *EvaluationContext) error {
	bindRuntimePolicyDecision(decision, evalCtx.ActiveSnapshot, evalCtx.PolicyVersion)
	return g.signer.SignDecision(decision)
}

// ── TemporalInterceptor ──

type TemporalInterceptor struct {
	g *Guardian
}

func NewTemporalInterceptor(g *Guardian) *TemporalInterceptor {
	return &TemporalInterceptor{g: g}
}

func (t *TemporalInterceptor) Evaluate(ctx context.Context, evalCtx *EvaluationContext, next Handler) (*contracts.DecisionRecord, error) {
	if t.g.temporal != nil {
		resp := t.g.temporal.Evaluate(ctx)
		if resp.Level >= ResponseInterrupt {
			now := t.g.clock.Now()
			intervention := &contracts.InterventionMetadata{
				Type:         responseToIntervention(resp.Level),
				ReasonCode:   string(contracts.ReasonTemporalIntervene),
				WaitDuration: resp.Duration,
			}

			// Build effect and its digest
			effect := &contracts.Effect{
				EffectID:   fmt.Sprintf("eff-%d", t.g.clock.Now().UnixNano()),
				EffectType: evalCtx.Request.Action,
				Params:     evalCtx.Request.Context,
				Taint:      contracts.TaintLabelsFromContext(evalCtx.Request.Context),
			}
			if evalCtx.Request.Action == "EXECUTE_TOOL" {
				if effect.Params == nil {
					effect.Params = make(map[string]interface{})
				}
				effect.Params["tool_name"] = evalCtx.Request.Resource
			}
			effectDigest, err := canonicalEffectDigest(effect)
			if err != nil {
				return nil, fmt.Errorf("canonicalize effect digest: %w", err)
			}

			envFP := t.g.envFprint
			if envFP == "" {
				envFP = "sha256:unconfigured"
			}

			decision := &contracts.DecisionRecord{
				ID:             newDecisionID(),
				Timestamp:      now,
				Verdict:        string(contracts.VerdictEscalate),
				ReasonCode:     string(contracts.ReasonTemporalIntervene),
				Reason:         fmt.Sprintf("Temporal Intervention: %s (%s)", intervention.Type, intervention.ReasonCode),
				Intervention:   intervention,
				EffectDigest:   effectDigest,
				InputContext:   evalCtx.Request.Context,
				EnvFingerprint: envFP,
				PolicyVersion:  evalCtx.PolicyVersion,
			}
			if err := t.g.signDecisionWithContext(decision, evalCtx); err != nil {
				return nil, fmt.Errorf("failed to sign temporal-deny decision: %w", err)
			}

			if t.g.auditLog != nil {
				decisionBytes, _ := canonicalize.JCS(decision)
				_, _ = t.g.auditLog.Append("guardian", "DECISION_MADE", decision.ID, string(decisionBytes))
			}
			return decision, nil
		} else if resp.Level == ResponseThrottle {
			evalCtx.Intervention = &contracts.InterventionMetadata{
				Type:         contracts.InterventionThrottle,
				ReasonCode:   string(contracts.ReasonTemporalThrottle),
				WaitDuration: resp.Duration,
			}
		}
	}
	return next(ctx, evalCtx)
}

// ── FreezeInterceptor ──

type FreezeInterceptor struct {
	g *Guardian
}

func NewFreezeInterceptor(g *Guardian) *FreezeInterceptor {
	return &FreezeInterceptor{g: g}
}

func (f *FreezeInterceptor) Evaluate(ctx context.Context, evalCtx *EvaluationContext, next Handler) (*contracts.DecisionRecord, error) {
	// Gate 0: Global freeze check — if frozen, deny everything immediately
	if f.g.freezeCtrl != nil && f.g.freezeCtrl.IsFrozen() {
		now := f.g.clock.Now()
		decision := &contracts.DecisionRecord{
			ID:         newDecisionID(),
			Timestamp:  now,
			Verdict:    string(contracts.VerdictDeny),
			Reason:     string(contracts.ReasonSystemFrozen),
			ReasonCode: string(contracts.ReasonSystemFrozen),
		}
		if err := f.g.signDecisionWithContext(decision, evalCtx); err != nil {
			return nil, fmt.Errorf("failed to sign freeze-deny decision: %w", err)
		}
		return decision, nil
	}

	// Gate 0.5: Per-agent kill switch — if agent is killed, deny immediately
	if f.g.agentKillSwitch != nil && f.g.agentKillSwitch.IsKilled(evalCtx.Request.Principal) {
		now := f.g.clock.Now()
		decision := &contracts.DecisionRecord{
			ID:         newDecisionID(),
			Timestamp:  now,
			Verdict:    string(contracts.VerdictDeny),
			Reason:     string(contracts.ReasonAgentKilled),
			ReasonCode: string(contracts.ReasonAgentKilled),
		}
		if err := f.g.signDecisionWithContext(decision, evalCtx); err != nil {
			return nil, fmt.Errorf("failed to sign agent-killed decision: %w", err)
		}
		return decision, nil
	}

	// Gate 1: Context mismatch guard — deny if environment fingerprint changed
	if f.g.contextGuard != nil {
		if err := f.g.contextGuard.ValidateCurrent(); err != nil {
			now := f.g.clock.Now()
			decision := &contracts.DecisionRecord{
				ID:         newDecisionID(),
				Timestamp:  now,
				Verdict:    string(contracts.VerdictDeny),
				Reason:     fmt.Sprintf("CONTEXT_MISMATCH: %v", err),
				ReasonCode: string(contracts.ReasonContextMismatch),
			}
			if err := f.g.signDecisionWithContext(decision, evalCtx); err != nil {
				return nil, fmt.Errorf("failed to sign context-mismatch decision: %w", err)
			}
			return decision, nil
		}
	}

	return next(ctx, evalCtx)
}

// ── PDPInterceptor ──

type PDPInterceptor struct {
	g *Guardian
}

func NewPDPInterceptor(g *Guardian) *PDPInterceptor {
	return &PDPInterceptor{g: g}
}

func (p *PDPInterceptor) Evaluate(ctx context.Context, evalCtx *EvaluationContext, next Handler) (*contracts.DecisionRecord, error) {
	// Gate 2: Agent identity isolation — deny if credential reuse detected
	if p.g.isolationChecker != nil && evalCtx.Request.Principal != "" {
		credHash, ok := trustedContextString(evalCtx.Request.Context, ContextCredentialHash)
		if !ok {
			decision, err := p.deny(evalCtx, contracts.ReasonIdentityIsolationViolation, "IDENTITY_ISOLATION_VIOLATION: missing trusted credential_hash")
			if err != nil {
				return nil, fmt.Errorf("failed to sign isolation-violation decision: %w", err)
			}
			return decision, nil
		}
		sessionID, _ := trustedContextString(evalCtx.Request.Context, ContextSessionID)
		if err := p.g.isolationChecker.ValidateAgentIdentity(evalCtx.Request.Principal, credHash, sessionID); err != nil {
			decision, signErr := p.deny(evalCtx, contracts.ReasonIdentityIsolationViolation, fmt.Sprintf("IDENTITY_ISOLATION_VIOLATION: %v", err))
			if signErr != nil {
				return nil, fmt.Errorf("failed to sign isolation-violation decision: %w", signErr)
			}
			return decision, nil
		}
	}

	// Gate 4: Threat signal scan — scan untrusted textual inputs
	if p.g.threatScanner != nil {
		channel, trustLevel := trustedInputProvenance(evalCtx.Request.Context)

		var textToScan string
		if input, ok := evalCtx.Request.Context["user_input"].(string); ok {
			textToScan = input
		} else if input, ok := evalCtx.Request.Context["text"].(string); ok {
			textToScan = input
		} else if input, ok := evalCtx.Request.Context["content"].(string); ok {
			textToScan = input
		}

		if textToScan != "" {
			scanResult := p.g.threatScanner.ScanInput(textToScan, channel, trustLevel)
			evalCtx.ThreatScanResult = scanResult

			if scanResult.FindingCount > 0 && trustLevel.IsTainted() && threatscan.ContainsHighRiskFindings(scanResult) {
				now := p.g.clock.Now()
				reasonCode := contracts.ReasonTaintedInputDeny
				for _, f := range scanResult.Findings {
					switch f.Class {
					case contracts.ThreatClassPromptInjection:
						reasonCode = contracts.ReasonPromptInjectionDetected
					case contracts.ThreatClassUnicodeObfuscation:
						reasonCode = contracts.ReasonUnicodeObfuscationDetected
					case contracts.ThreatClassCredentialExposure:
						reasonCode = contracts.ReasonTaintedCredentialDeny
					case contracts.ThreatClassSoftwarePublish:
						reasonCode = contracts.ReasonTaintedPublishDeny
					case contracts.ThreatClassSuspiciousFetch:
						reasonCode = contracts.ReasonTaintedEgressDeny
					}
				}

				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					ReasonCode: string(reasonCode),
					Reason:     fmt.Sprintf("%s: %d findings (max=%s) from %s source", reasonCode, scanResult.FindingCount, scanResult.MaxSeverity, trustLevel),
					InputContext: map[string]any{
						"threat_scan": scanResult.Ref(),
					},
				}
				if err := p.g.signDecisionWithContext(decision, evalCtx); err != nil {
					return nil, fmt.Errorf("failed to sign threat-deny decision: %w", err)
				}
				if p.g.auditLog != nil {
					decisionBytes, _ := canonicalize.JCS(decision)
					_, _ = p.g.auditLog.Append("guardian", "THREAT_DENY", decision.ID, string(decisionBytes))
				}
				p.g.recordBehavioralEvent(evalCtx.Request.Principal, trust.EventThreatDetected, fmt.Sprintf("threat scan: %d findings", scanResult.FindingCount))
				return decision, nil
			}
		}
	}

	// Gate 5: Delegation session validation — if principal is a delegate, validate session
	if p.g.delegationStore != nil {
		if sessionID, ok := evalCtx.Request.Context["delegation_session_id"].(string); ok && sessionID != "" {
			now := p.g.clock.Now()
			session, loadErr := p.g.delegationStore.Load(sessionID)
			if loadErr != nil {
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					Reason:     fmt.Sprintf("DELEGATION_INVALID: %v", loadErr),
					ReasonCode: string(contracts.ReasonDelegationInvalid),
				}
				if err := p.g.signDecisionWithContext(decision, evalCtx); err != nil {
					return nil, fmt.Errorf("failed to sign delegation-invalid decision: %w", err)
				}
				return decision, nil
			}
			if session == nil {
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					Reason:     "DELEGATION_INVALID: session not found",
					ReasonCode: string(contracts.ReasonDelegationInvalid),
				}
				if err := p.g.signDecisionWithContext(decision, evalCtx); err != nil {
					return nil, fmt.Errorf("failed to sign delegation-invalid decision: %w", err)
				}
				return decision, nil
			}

			verifier, _ := evalCtx.Request.Context["delegation_verifier"].(string)
			nonceChecker := p.g.delegationStore.IsNonceUsed
			if validErr := identity.ValidateSession(session, verifier, now, nonceChecker); validErr != nil {
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					Reason:     fmt.Sprintf("DELEGATION_INVALID: %v", validErr),
					ReasonCode: string(contracts.ReasonDelegationInvalid),
				}
				if err := p.g.signDecisionWithContext(decision, evalCtx); err != nil {
					return nil, fmt.Errorf("failed to sign delegation-invalid decision: %w", err)
				}
				return decision, nil
			}

			// Gate 5.1: Principal binding — the requesting principal must be the
			// session's delegate. A valid session issued for one delegate must not be
			// usable by a different principal even when the requested tool and action
			// are within the session's scope.
			if evalCtx.Request.Principal != session.DelegatePrincipal {
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					Reason:     fmt.Sprintf("DELEGATION_PRINCIPAL_MISMATCH: requesting principal %q does not match delegated principal %q", evalCtx.Request.Principal, session.DelegatePrincipal),
					ReasonCode: string(contracts.ReasonDelegationPrincipalMismatch),
				}
				if err := p.g.signDecisionWithContext(decision, evalCtx); err != nil {
					return nil, fmt.Errorf("failed to sign delegation-principal-mismatch decision: %w", err)
				}
				if p.g.auditLog != nil {
					decisionBytes, _ := canonicalize.JCS(decision)
					_, _ = p.g.auditLog.Append("guardian", "DELEGATION_PRINCIPAL_MISMATCH", decision.ID, string(decisionBytes))
				}
				return decision, nil
			}

			p.g.delegationStore.MarkNonceUsed(session.SessionNonce)

			if evalCtx.Request.Resource != "" && !session.IsToolAllowed(evalCtx.Request.Resource) {
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					Reason:     fmt.Sprintf("DELEGATION_SCOPE_VIOLATION: tool %q not in session scope", evalCtx.Request.Resource),
					ReasonCode: string(contracts.ReasonDelegationScopeViolation),
				}
				if err := p.g.signDecisionWithContext(decision, evalCtx); err != nil {
					return nil, fmt.Errorf("failed to sign delegation-scope decision: %w", err)
				}
				if p.g.auditLog != nil {
					decisionBytes, _ := canonicalize.JCS(decision)
					_, _ = p.g.auditLog.Append("guardian", "DELEGATION_SCOPE_DENY", decision.ID, string(decisionBytes))
				}
				return decision, nil
			}

			if evalCtx.Request.Resource != "" && evalCtx.Request.Action != "" && len(session.Capabilities) > 0 {
				if !session.IsActionAllowed(evalCtx.Request.Resource, evalCtx.Request.Action) {
					decision := &contracts.DecisionRecord{
						ID:         newDecisionID(),
						Timestamp:  now,
						Verdict:    string(contracts.VerdictDeny),
						Reason:     fmt.Sprintf("DELEGATION_SCOPE_VIOLATION: action %q on %q not granted", evalCtx.Request.Action, evalCtx.Request.Resource),
						ReasonCode: string(contracts.ReasonDelegationScopeViolation),
					}
					if err := p.g.signDecisionWithContext(decision, evalCtx); err != nil {
						return nil, fmt.Errorf("failed to sign delegation-scope decision: %w", err)
					}
					if p.g.auditLog != nil {
						decisionBytes, _ := canonicalize.JCS(decision)
						_, _ = p.g.auditLog.Append("guardian", "DELEGATION_SCOPE_DENY", decision.ID, string(decisionBytes))
					}
					return decision, nil
				}
			}

			if evalCtx.Request.Context == nil {
				evalCtx.Request.Context = make(map[string]interface{})
			}
			evalCtx.Request.Context["delegation_validated"] = true
			evalCtx.Request.Context["delegation_delegator"] = session.DelegatorPrincipal
			evalCtx.Request.Context["delegation_delegate"] = session.DelegatePrincipal
		}
	}

	// Active PDP Evaluation (Gate 2.5)
	if evalCtx.ActivePDP != nil {
		pdpReq := &pdp.DecisionRequest{
			Principal: evalCtx.Request.Principal,
			Action:    evalCtx.Request.Action,
			Resource:  evalCtx.Request.Resource,
			Context:   evalCtx.Request.Context,
			Timestamp: p.g.clock.Now(),
		}
		pdpResp, pdpErr := evalCtx.ActivePDP.Evaluate(ctx, pdpReq)
		if pdpErr != nil {
			decision := &contracts.DecisionRecord{
				ID:             newDecisionID(),
				Timestamp:      p.g.clock.Now(),
				Verdict:        string(contracts.VerdictDeny),
				ReasonCode:     string(contracts.ReasonPDPError),
				Reason:         fmt.Sprintf("%s: %v", contracts.ReasonPDPError, pdpErr),
				PolicyBackend:  string(evalCtx.ActivePDP.Backend()),
				InputContext:   evalCtx.Request.Context,
				EnvFingerprint: p.g.envFprint,
			}
			if err := p.g.signDecisionWithContext(decision, evalCtx); err != nil {
				return nil, fmt.Errorf("failed to sign PDP-error decision: %w", err)
			}
			return decision, nil
		}

		evalCtx.PDPBackend = string(evalCtx.ActivePDP.Backend())
		if evalCtx.ActiveSnapshot == nil {
			evalCtx.PDPHash = evalCtx.ActivePDP.PolicyHash()
		}
		evalCtx.PDPDecisionHash = pdpResp.DecisionHash

		if !pdpResp.Allow {
			reasonCode := pdpResp.ReasonCode
			if reasonCode == "" {
				reasonCode = string(contracts.ReasonPDPDeny)
			}
			decision := &contracts.DecisionRecord{
				ID:                 newDecisionID(),
				Timestamp:          p.g.clock.Now(),
				Verdict:            string(contracts.VerdictDeny),
				ReasonCode:         reasonCode,
				Reason:             fmt.Sprintf("%s (ref=%s)", reasonCode, pdpResp.PolicyRef),
				PolicyBackend:      evalCtx.PDPBackend,
				InputContext:       evalCtx.Request.Context,
				EnvFingerprint:     p.g.envFprint,
				PolicyContentHash:  evalCtx.PDPHash,
				PolicyDecisionHash: evalCtx.PDPDecisionHash,
			}
			if err := p.g.signDecisionWithContext(decision, evalCtx); err != nil {
				return nil, fmt.Errorf("failed to sign PDP-deny decision: %w", err)
			}
			if p.g.auditLog != nil {
				decisionBytes, _ := canonicalize.JCS(decision)
				_, _ = p.g.auditLog.Append("guardian", "PDP_DENY", decision.ID, string(decisionBytes))
			}
			return decision, nil
		}
	}

	return next(ctx, evalCtx)
}

func (p *PDPInterceptor) deny(evalCtx *EvaluationContext, reasonCode contracts.ReasonCode, reason string) (*contracts.DecisionRecord, error) {
	now := p.g.clock.Now()
	decision := &contracts.DecisionRecord{
		ID:         newDecisionID(),
		Timestamp:  now,
		Verdict:    string(contracts.VerdictDeny),
		Reason:     reason,
		ReasonCode: string(reasonCode),
	}
	if err := p.g.signDecisionWithContext(decision, evalCtx); err != nil {
		return nil, err
	}
	return decision, nil
}

func trustedSecurityContext(ctx map[string]interface{}) bool {
	if ctx == nil {
		return false
	}
	trusted, _ := ctx[ContextSecurityTrusted].(bool)
	return trusted
}

func trustedContextString(ctx map[string]interface{}, key string) (string, bool) {
	if !trustedSecurityContext(ctx) {
		return "", false
	}
	value, ok := ctx[key].(string)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

func trustedInputProvenance(ctx map[string]interface{}) (contracts.SourceChannel, contracts.InputTrustLevel) {
	channel := contracts.SourceChannelUnknown
	trustLevel := contracts.InputTrustExternalUntrusted
	if !trustedSecurityContext(ctx) {
		return channel, trustLevel
	}
	if ch, ok := trustedContextString(ctx, ContextSourceChannel); ok {
		channel = contracts.SourceChannel(ch)
	}
	if tl, ok := trustedContextString(ctx, ContextTrustLevel); ok {
		switch contracts.InputTrustLevel(tl) {
		case contracts.InputTrustTrusted, contracts.InputTrustInternalUnverified, contracts.InputTrustExternalUntrusted, contracts.InputTrustTainted:
			trustLevel = contracts.InputTrustLevel(tl)
		default:
			trustLevel = contracts.InputTrustExternalUntrusted
		}
	}
	return channel, trustLevel
}

// ── TaintEgressInterceptor ──

type TaintEgressInterceptor struct {
	g *Guardian
}

func NewTaintEgressInterceptor(g *Guardian) *TaintEgressInterceptor {
	return &TaintEgressInterceptor{g: g}
}

func (t *TaintEgressInterceptor) Evaluate(ctx context.Context, evalCtx *EvaluationContext, next Handler) (*contracts.DecisionRecord, error) {
	// Gate 3: Egress control — deny if destination is blocked
	if t.g.egressChecker != nil {
		if dest, ok := trustedContextString(evalCtx.Request.Context, ContextDestination); ok && dest != "" {
			var payloadSize int64
			if ps, ok := evalCtx.Request.Context["payload_size"].(float64); ok {
				payloadSize = int64(ps)
			}
			result := t.g.egressChecker.CheckEgress(dest, "https", payloadSize)
			if !result.Allowed {
				now := t.g.clock.Now()
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					Reason:     fmt.Sprintf("DATA_EGRESS_BLOCKED: %s", result.ReasonCode),
					ReasonCode: string(contracts.ReasonDataEgressBlocked),
				}
				if err := t.g.signDecisionWithContext(decision, evalCtx); err != nil {
					return nil, fmt.Errorf("failed to sign egress-blocked decision: %w", err)
				}
				t.g.recordBehavioralEvent(evalCtx.Request.Principal, trust.EventEgressBlocked, fmt.Sprintf("egress blocked: %s", result.ReasonCode))
				return decision, nil
			}
		}
	}

	// Taint checks
	taintLabels := contracts.TaintLabelsFromContext(evalCtx.Request.Context)
	if len(taintLabels) > 0 {
		if evalCtx.Request.Context == nil {
			evalCtx.Request.Context = make(map[string]interface{})
		}
		evalCtx.Request.Context["taint"] = taintLabels
		evalCtx.Tainted = true
	}
	if taintTrackingEnabled() && taintedEgressDenied(evalCtx.Request.Context, taintLabels) {
		now := t.g.clock.Now()
		decision := &contracts.DecisionRecord{
			ID:         newDecisionID(),
			Timestamp:  now,
			Verdict:    string(contracts.VerdictDeny),
			Reason:     "TAINTED_DATA_EGRESS_DENY: sensitive taint cannot leave the trust boundary without explicit approval",
			ReasonCode: string(contracts.ReasonTaintedEgressDeny),
			InputContext: map[string]any{
				"taint": taintLabels,
			},
		}
		if err := t.g.signDecisionWithContext(decision, evalCtx); err != nil {
			return nil, fmt.Errorf("failed to sign tainted-egress decision: %w", err)
		}
		t.g.recordBehavioralEvent(evalCtx.Request.Principal, trust.EventEgressBlocked, "tainted egress blocked")
		return decision, nil
	}

	return next(ctx, evalCtx)
}

// ── SandboxAllocationInterceptor ──

type SandboxAllocationInterceptor struct {
	g *Guardian
}

func NewSandboxAllocationInterceptor(g *Guardian) *SandboxAllocationInterceptor {
	return &SandboxAllocationInterceptor{g: g}
}

func (s *SandboxAllocationInterceptor) Evaluate(ctx context.Context, evalCtx *EvaluationContext, next Handler) (*contracts.DecisionRecord, error) {
	if s.g.warmLeaseMgr != nil && evalCtx.Request.Action == "EXECUTE_TOOL" {
		spec := &sandbox.SandboxSpec{
			Image: "sha256:default-pinned-digest",
		}
		if img, ok := evalCtx.Request.Context["image"].(string); ok && img != "" {
			spec.Image = img
		}

		runner, err := s.g.warmLeaseMgr.Acquire(ctx, spec)
		if err != nil {
			now := s.g.clock.Now()
			decision := &contracts.DecisionRecord{
				ID:         newDecisionID(),
				Timestamp:  now,
				Verdict:    string(contracts.VerdictDeny),
				Reason:     fmt.Sprintf("SANDBOX_ACQUISITION_FAILED: %v", err),
				ReasonCode: "SANDBOX_ACQUISITION_FAILED",
			}
			if err := s.g.signDecisionWithContext(decision, evalCtx); err != nil {
				return nil, fmt.Errorf("failed to sign sandbox-acquisition-failed decision: %w", err)
			}
			return decision, nil
		}

		if evalCtx.Request.Context == nil {
			evalCtx.Request.Context = make(map[string]interface{})
		}
		leaseID := fmt.Sprintf("lease-%d", s.g.clock.Now().UnixNano())
		evalCtx.Request.Context["sandbox_lease_id"] = leaseID

		// Release the warm sandbox back to pool
		s.g.warmLeaseMgr.Release(runner)
	}

	return next(ctx, evalCtx)
}
