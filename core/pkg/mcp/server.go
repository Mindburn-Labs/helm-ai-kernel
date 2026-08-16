package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/correlation"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/events"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

// ToolExecutionRequest represents a request to execute a tool via MCP.
type ToolExecutionRequest struct {
	ToolName  string                 `json:"tool_name"`
	Arguments map[string]interface{} `json:"arguments"`
	SessionID string                 `json:"session_id"`

	// Delegation-aware fields (defense-in-depth, complements Guardian Gate 5).
	// When DelegationSessionID is set, the firewall enforces tool scope
	// before the request reaches the Guardian policy evaluation.
	DelegationSessionID    string   `json:"delegation_session_id,omitempty"`
	DelegationVerifier     string   `json:"delegation_verifier,omitempty"`
	DelegationAllowedTools []string `json:"delegation_allowed_tools,omitempty"`

	// OAuth-aware fields are populated by the MCP gateway after bearer-token
	// validation so Guardian decisions can retain the scope/resource evidence.
	RequiredScopes []string `json:"required_scopes,omitempty"`
	OAuthScopes    []string `json:"oauth_scopes,omitempty"`
	OAuthResources []string `json:"oauth_resources,omitempty"`
}

// ToolExecutionResponse represents the result of a tool execution.
type ToolExecutionResponse struct {
	Content           string            `json:"content"`
	ContentItems      []ToolContentItem `json:"content_items,omitempty"`
	StructuredContent map[string]any    `json:"structured_content,omitempty"`
	IsError           bool              `json:"is_error"`
	Evaluated         bool              `json:"evaluated"` // Whether policy was evaluated
	ReceiptID         string            `json:"receipt_id,omitempty"`

	// These fields are runtime-only anchors for the lifecycle wrapper. They are
	// intentionally excluded from every MCP response serialization: the signed
	// receipt is projected into lifecycle events, while the public response
	// continues to carry only the established tool result contract.
	ExecutionReceipt        *contracts.Receipt `json:"-"`
	DispatchState           string             `json:"-"`
	ApprovalHash            string             `json:"-"`
	ApproverID              string             `json:"-"`
	DispatchAdmissionExpiry time.Time          `json:"-"`
}

// PolicyEvaluator abstracts the governance decision evaluation.
// This allows the GovernanceFirewall to be tested without a full Guardian.
type PolicyEvaluator interface {
	EvaluateDecision(ctx context.Context, req guardian.DecisionRequest) (*contracts.DecisionRecord, error)
}

// GovernanceFirewall intercepts tool calls and enforces Guardian policies.
type GovernanceFirewall struct {
	evaluator    PolicyEvaluator
	catalog      *ToolCatalog
	publisher    events.Publisher
	lifecycleEnv string
}

const lifecycleSourceRef = "MCP"

// GovernanceFirewallOption configures optional runtime seams.
type GovernanceFirewallOption func(*GovernanceFirewall)

// WithLifecyclePublisher injects a lifecycle capture/publisher. Publication
// stays disabled unless the trusted runtime explicitly supplies one.
func WithLifecyclePublisher(publisher events.Publisher) GovernanceFirewallOption {
	return func(f *GovernanceFirewall) {
		if publisher != nil {
			f.publisher = publisher
		}
	}
}

// WithLifecycleEnvironment records the trusted process data class used for
// lifecycle publication. The command runtime supplies this from its exact
// HELM_ENV configuration; it is not derived from a request or tenant.
func WithLifecycleEnvironment(env string) GovernanceFirewallOption {
	return func(f *GovernanceFirewall) {
		if env != "" {
			f.lifecycleEnv = env
		}
	}
}

// NewGovernanceFirewall creates a new firewall instance.
// The guardian.Guardian satisfies the PolicyEvaluator interface.
func NewGovernanceFirewall(evaluator PolicyEvaluator, catalog *ToolCatalog, opts ...GovernanceFirewallOption) *GovernanceFirewall {
	lifecycleEnv := os.Getenv("HELM_ENV")
	if lifecycleEnv == "" {
		lifecycleEnv = events.EnvProduction
	}
	f := &GovernanceFirewall{
		evaluator:    evaluator,
		catalog:      catalog,
		lifecycleEnv: lifecycleEnv,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// InterceptToolExecution checks if a tool execution is allowed by the Guardian.
// If allowed, it returns nil. If blocked, it returns an error.
//
// When DelegationAllowedTools is set, tool scope is checked BEFORE the
// Guardian evaluation (defense-in-depth — see ARCHITECTURE.md §2.1).
func (f *GovernanceFirewall) InterceptToolExecution(ctx context.Context, req ToolExecutionRequest) error {
	decision, err := f.evaluateToolExecution(ctx, req)
	if err != nil {
		return err
	}
	return decisionError(decision)
}

func (f *GovernanceFirewall) evaluateToolExecution(ctx context.Context, req ToolExecutionRequest) (*contracts.DecisionRecord, error) {
	decisionCtx, err := f.prepareToolExecution(req)
	if err != nil {
		return nil, err
	}
	return f.evaluatePreparedToolExecution(ctx, req, decisionCtx)
}

func (f *GovernanceFirewall) prepareToolExecution(req ToolExecutionRequest) (map[string]interface{}, error) {
	if f.evaluator == nil {
		return nil, fmt.Errorf("governance evaluator is required")
	}

	// Pre-Guardian delegation scope check.
	// This runs before the full policy evaluation so that a delegated agent
	// cannot even attempt to call tools outside its session scope.
	if len(req.DelegationAllowedTools) > 0 {
		allowed := false
		for _, t := range req.DelegationAllowedTools {
			if t == req.ToolName {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("delegation scope violation: tool %q not in session scope", req.ToolName)
		}
	}

	// Build Guardian decision context, forwarding delegation metadata.
	decisionCtx := make(map[string]interface{})
	for k, v := range req.Arguments {
		if guardian.IsReservedSecurityContextKey(k) {
			return nil, fmt.Errorf("reserved security context argument %q must be supplied by the transport boundary", k)
		}
		decisionCtx[k] = v
	}
	decisionCtx[guardian.ContextSecurityTrusted] = true
	decisionCtx[guardian.ContextSessionID] = req.SessionID
	decisionCtx[guardian.ContextSourceChannel] = string(contracts.SourceChannelMCPClient)
	decisionCtx[guardian.ContextTrustLevel] = string(contracts.InputTrustExternalUntrusted)
	if req.DelegationSessionID != "" {
		decisionCtx["delegation_session_id"] = req.DelegationSessionID
		decisionCtx["delegation_verifier"] = req.DelegationVerifier
	}
	if len(req.RequiredScopes) > 0 {
		decisionCtx["mcp_required_scopes"] = append([]string(nil), req.RequiredScopes...)
	}
	if len(req.OAuthScopes) > 0 {
		decisionCtx["oauth_scopes"] = append([]string(nil), req.OAuthScopes...)
	}
	if len(req.OAuthResources) > 0 {
		decisionCtx["oauth_resources"] = append([]string(nil), req.OAuthResources...)
	}
	return decisionCtx, nil
}

func (f *GovernanceFirewall) evaluatePreparedToolExecution(ctx context.Context, req ToolExecutionRequest, decisionCtx map[string]interface{}) (*contracts.DecisionRecord, error) {
	decision, err := f.evaluator.EvaluateDecision(ctx, guardian.DecisionRequest{
		Principal: req.SessionID,
		Action:    "EXECUTE_TOOL",
		Resource:  req.ToolName,
		Context:   decisionCtx,
	})
	if err != nil {
		return nil, fmt.Errorf("governance check failed: %w", err)
	}
	if decision == nil {
		return nil, fmt.Errorf("governance returned empty decision")
	}

	return decision, nil
}

func decisionError(decision *contracts.DecisionRecord) error {
	if decision == nil {
		return fmt.Errorf("governance returned empty decision")
	}

	// Enforce Decision — use canonical verdict constants
	switch decision.Verdict {
	case string(contracts.VerdictAllow):
		return nil
	case string(contracts.VerdictDeny):
		return fmt.Errorf("governance blocked execution: %s", decision.Reason)
	case string(contracts.VerdictEscalate), "PENDING":
		return fmt.Errorf("governance requires approval: %s", decision.Reason)
	default:
		return fmt.Errorf("governance returned non-canonical verdict %q", decision.Verdict)
	}
}

// WrapToolHandler wraps a standard tool handler with the firewall.
type ToolHandler func(ctx context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error)

// GovernedExecutor is an opaque executor produced by GovernanceFirewall.
type GovernedExecutor struct {
	execute ToolExecutor
}

// Execute runs the policy-wrapped tool handler.
func (e GovernedExecutor) Execute(ctx context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error) {
	if e.execute == nil {
		return ToolExecutionResponse{}, fmt.Errorf("governed executor is not configured")
	}
	return e.execute(ctx, req)
}

// GovernedExecutor wraps a handler and marks it as policy-enforced for Gateway.
func (f *GovernanceFirewall) GovernedExecutor(handler ToolHandler) GovernedExecutor {
	return GovernedExecutor{execute: ToolExecutor(f.WrapToolHandler(handler))}
}

func (f *GovernanceFirewall) WrapToolHandler(handler ToolHandler) ToolHandler {
	return func(ctx context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error) {
		startedAt := time.Now()
		ctx, baseMeta := lifecycleContext(ctx, req, f.lifecycleEnv)
		sequence := make([]events.LifecycleEvent, 0, len(events.LifecycleEventTypes()))
		emit := func(event events.LifecycleEvent) {
			sequence = append(sequence, event)
			if f.publisher == nil || event.Meta.Env != events.EnvSynthetic {
				return
			}
			if err := f.publisher(ctx, event); err != nil {
				// Publication must not change the established MCP response contract.
				slog.Warn("governance_firewall: lifecycle publication rejected", "event_type", event.Meta.EventType)
			}
		}
		finish := func() {
			if err := events.ValidateRequestSequence(sequence); err != nil {
				slog.Error("governance_firewall: lifecycle sequence invalid", "event_count", len(sequence))
			}
		}
		meta := func() events.EventMeta { return nextLifecycleMeta(baseMeta) }
		emitFailure := func(reasonCode, failureClass string) {
			emit(events.NewRequestFailed(
				meta(), reasonCode, 0,
				events.LifecycleEnrichment{
					FailureClass: failureClass,
					AttemptID:    attemptRef(baseMeta, req),
				},
			))
			finish()
		}
		actorRef := events.StableRef(req.SessionID)
		emit(events.NewRequestReceived(
			meta(), "EXECUTE_TOOL", req.ToolName,
			events.LifecycleEnrichment{
				ActorRef: actorRef,
				Surface:  string(contracts.SourceChannelMCPClient),
				Tool:     req.ToolName,
			},
		))
		decisionCtx, preflightErr := f.prepareToolExecution(req)
		if preflightErr != nil {
			emitFailure(string(preflightReasonCode(f, req)), "preflight")
			return deniedResponse(preflightErr), nil
		}

		effectClass, riskTier, classificationErr := classifyTool(f.catalog, req.ToolName)
		if classificationErr != nil {
			emitFailure(string(contracts.ReasonSchemaViolation), "classification")
			return deniedResponse(classificationErr), nil
		}
		emit(events.NewRequestClassified(
			meta(), effectClass, string(riskTier),
			events.LifecycleEnrichment{
				Action:               "EXECUTE_TOOL",
				Resource:             req.ToolName,
				EffectContext:        "pep_catalog",
				ClassificationSource: "pep_catalog",
			},
		))

		decisionStarted := time.Now()
		decision, evalErr := f.evaluatePreparedToolExecution(ctx, req, decisionCtx)
		decisionLatency := time.Since(decisionStarted).Milliseconds()
		if evalErr != nil {
			emitFailure(string(contracts.ReasonPDPError), "evaluator")
			return deniedResponse(evalErr), nil
		}

		emit(events.NewPolicyApplied(meta(), *decision, nil))
		emit(events.NewDecisionMade(meta(), *decision, events.LifecycleEnrichment{
			DecisionLatencyMs: decisionLatency,
		}))

		switch decision.Verdict {
		case string(contracts.VerdictDeny):
			emitFailure(decisionReasonCode(decision, contracts.ReasonPDPDeny), "policy")
			return deniedResponse(decisionError(decision)), nil
		case string(contracts.VerdictEscalate), "PENDING":
			escalationDecision := *decision
			if escalationDecision.Verdict == "PENDING" {
				escalationDecision.Verdict = string(contracts.VerdictEscalate)
			}
			if event, err := events.NewEscalationTriggered(meta(), escalationDecision); err == nil {
				emit(event)
			} else {
				slog.Error("governance_firewall: escalation projection failed")
			}
			emitFailure(decisionReasonCode(decision, contracts.ReasonApprovalRequired), "escalation")
			return deniedResponse(decisionError(decision)), nil
		case string(contracts.VerdictAllow):
			// Continue to the handler and the catalog audit below.
		default:
			emitFailure(string(contracts.ReasonPDPError), "evaluator")
			return deniedResponse(decisionError(decision)), nil
		}

		var resp ToolExecutionResponse
		var handlerErr error
		if handler == nil {
			handlerErr = fmt.Errorf("tool handler is required")
		} else {
			resp, handlerErr = handler(ctx, req)
		}

		var receipt ToolCallReceipt
		var auditErr error
		if f.catalog != nil {
			receipt, auditErr = f.catalog.AuditToolCall(req.ToolName, req.Arguments, resp.Content)
			if auditErr != nil {
				slog.Error("governance_firewall: audit logging failed")
			} else {
				slog.Info("governance_firewall: tool execution audited", "receipt_id", receipt.ID)
				resp.ReceiptID = receipt.ID
			}
		}

		resp.Evaluated = true
		if handlerErr != nil || resp.IsError {
			emitFailure(string(contracts.ReasonVerification), "handler")
			return resp, handlerErr
		}
		if auditErr != nil {
			emitFailure(string(contracts.ReasonVerification), "audit")
			return resp, nil
		}

		if resp.ExecutionReceipt != nil {
			// Only the authoritative receipt returned by the governed runtime can
			// claim that a dispatch completed. ToolCatalog's audit receipt is an
			// unpersisted observation and remains a response-only audit field.
			emit(events.NewDispatchCompleted(
				meta(), *resp.ExecutionReceipt, "",
				events.LifecycleEnrichment{
					EffectContext:    resp.DispatchState,
					ApprovalRef:      events.StableRef(resp.ApprovalHash),
					ApproverRef:      events.StableRef(resp.ApproverID),
					ApprovalExpiryMs: lifecycleExpiryMs(resp.DispatchAdmissionExpiry),
				},
			))
		}
		emit(events.NewMCPRequestCompleted(
			meta(), events.MCPHandlerCompletion{
				ExecutionID: events.StableRef(string(baseMeta.CorrelationID) + ":mcp-handler"),
				Status:      "success",
				DurationMs:  time.Since(startedAt).Milliseconds(),
				Outcome:     "success",
			},
		))
		finish()
		return resp, nil
	}
}

func deniedResponse(err error) ToolExecutionResponse {
	return ToolExecutionResponse{
		Content:   fmt.Sprintf("Access Denied: %v", err),
		IsError:   true,
		Evaluated: true,
	}
}

func lifecycleContext(ctx context.Context, req ToolExecutionRequest, lifecycleEnv string) (context.Context, events.EventMeta) {
	if ctx == nil {
		ctx = context.Background()
	}
	corr, ok := correlation.From(ctx)
	if !ok || !correlation.IsValid(string(corr)) {
		corr = correlation.New()
		ctx = correlation.With(ctx, corr)
	}
	spanContext := trace.SpanContextFromContext(ctx)
	if lifecycleEnv == "" {
		lifecycleEnv = events.EnvProduction
	}
	if lifecycleEnv == events.EnvSynthetic {
		if tenantID, err := auth.GetTenantID(ctx); err == nil && tenantID != "" {
			// A tenant-bearing request is not synthetic even when the process
			// was started with the synthetic switch; do not relabel it.
			lifecycleEnv = events.EnvCustomerHosted
		}
	}
	runIdentity := req.SessionID
	if runIdentity == "" {
		runIdentity = "synthetic:" + string(corr)
	}
	meta := events.EventMeta{
		EventID:       uuid.NewString(),
		TimestampMs:   time.Now().UnixMilli(),
		CorrelationID: string(corr),
		RunID:         events.StableRef(runIdentity),
		TenantID:      lifecycleTenantRef(ctx, corr, req.SessionID),
		SourceRef:     lifecycleSourceRef,
		Env:           lifecycleEnv,
		SchemaVersion: events.EventSchemaVersion,
	}
	if spanContext.IsValid() {
		meta.TraceID = spanContext.TraceID().String()
		meta.SpanID = spanContext.SpanID().String()
	}
	return ctx, meta
}

func lifecycleTenantRef(ctx context.Context, corr correlation.ID, sessionID string) string {
	if tenantID, err := auth.GetTenantID(ctx); err == nil && tenantID != "" {
		return events.StableRef(tenantID)
	}
	if sessionID != "" {
		return events.StableRef("synthetic:" + sessionID)
	}
	return events.StableRef("synthetic:" + string(corr))
}

func nextLifecycleMeta(base events.EventMeta) events.EventMeta {
	base.EventID = uuid.NewString()
	base.TimestampMs = time.Now().UnixMilli()
	return base
}

func attemptRef(meta events.EventMeta, req ToolExecutionRequest) string {
	return events.StableRef(string(meta.CorrelationID) + ":" + req.ToolName)
}

func lifecycleExpiryMs(expiry time.Time) int64 {
	if expiry.IsZero() {
		return 0
	}
	return expiry.UnixMilli()
}

func decisionReasonCode(decision *contracts.DecisionRecord, fallback contracts.ReasonCode) string {
	if decision != nil && contracts.IsCanonicalReasonCode(decision.ReasonCode) {
		return decision.ReasonCode
	}
	return string(fallback)
}

func preflightReasonCode(f *GovernanceFirewall, req ToolExecutionRequest) contracts.ReasonCode {
	if f.evaluator == nil {
		return contracts.ReasonPDPError
	}
	if len(req.DelegationAllowedTools) > 0 {
		allowed := false
		for _, tool := range req.DelegationAllowedTools {
			if tool == req.ToolName {
				allowed = true
				break
			}
		}
		if !allowed {
			return contracts.ReasonDelegationScopeViolation
		}
	}
	for key := range req.Arguments {
		if guardian.IsReservedSecurityContextKey(key) {
			return contracts.ReasonSchemaViolation
		}
	}
	return contracts.ReasonPDPError
}

func classifyTool(catalog *ToolCatalog, name string) (string, contracts.RiskTier, error) {
	if catalog == nil {
		return "", "", fmt.Errorf("tool classification is unavailable")
	}
	ref, ok := catalog.Lookup(name)
	if !ok {
		return "", "", fmt.Errorf("tool %q is not classified in the PEP catalog", name)
	}
	if !validEffectClass(ref.EffectClass) {
		return "", "", fmt.Errorf("tool %q has invalid PEP effect classification", name)
	}
	if !validRiskTier(ref.RiskTier) {
		return "", "", fmt.Errorf("tool %q has invalid PEP risk tier", name)
	}
	if expected := riskTierForEffectClass(ref.EffectClass); ref.RiskTier != expected {
		return "", "", fmt.Errorf("tool %q has mismatched PEP effect class and risk tier", name)
	}
	return ref.EffectClass, ref.RiskTier, nil
}

func validEffectClass(effectClass string) bool {
	switch effectClass {
	case "E0", "E1", "E2", "E3", "E4":
		return true
	default:
		return false
	}
}

func validRiskTier(riskTier contracts.RiskTier) bool {
	switch riskTier {
	case contracts.RiskTierLow, contracts.RiskTierMedium, contracts.RiskTierHigh:
		return true
	default:
		return false
	}
}

func riskTierForEffectClass(effectClass string) contracts.RiskTier {
	switch effectClass {
	case "E0", "E1":
		return contracts.RiskTierLow
	case "E2":
		return contracts.RiskTierMedium
	case "E3", "E4":
		return contracts.RiskTierHigh
	default:
		return ""
	}
}

// ToolExecutionPlan represents a sequence of tool calls to be executed.
type ToolExecutionPlan struct {
	PlanID string                 `json:"plan_id"`
	Steps  []ToolExecutionRequest `json:"steps"`
}

// PlanDecision represents the governance decision for an entire plan.
type PlanDecision struct {
	PlanID    string                      `json:"plan_id"`
	Decisions []*contracts.DecisionRecord `json:"decisions"`
	Status    string                      `json:"status"` // ALLOW, DENY, ESCALATE
}

// InterceptPlan evaluates a proposed plan against governance policies.
// It returns a PlanDecision indicating which steps are allowed, blocked, or pending approval.
func (f *GovernanceFirewall) InterceptPlan(ctx context.Context, plan ToolExecutionPlan) (*PlanDecision, error) {
	decisions := make([]*contracts.DecisionRecord, 0, len(plan.Steps))
	overallStatus := string(contracts.VerdictAllow)

	for _, step := range plan.Steps {
		// Evaluate each step
		decision, err := f.evaluator.EvaluateDecision(ctx, guardian.DecisionRequest{
			Principal: step.SessionID,
			Action:    "EXECUTE_TOOL",
			Resource:  step.ToolName,
			Context:   step.Arguments,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate step %s: %w", step.ToolName, err)
		}
		if decision == nil {
			return nil, fmt.Errorf("failed to evaluate step %s: empty governance decision", step.ToolName)
		}
		if !isCanonicalToolVerdict(decision.Verdict) && decision.Verdict != "PENDING" {
			return nil, fmt.Errorf("failed to evaluate step %s: non-canonical governance verdict %q", step.ToolName, decision.Verdict)
		}

		// Aggregate Status
		if decision.Verdict == string(contracts.VerdictDeny) {
			overallStatus = string(contracts.VerdictDeny)
		} else if decision.Verdict == string(contracts.VerdictEscalate) && overallStatus != string(contracts.VerdictDeny) {
			overallStatus = string(contracts.VerdictEscalate)
		}

		decisions = append(decisions, decision)
	}

	return &PlanDecision{
		PlanID:    plan.PlanID,
		Decisions: decisions,
		Status:    overallStatus,
	}, nil
}

func isCanonicalToolVerdict(verdict string) bool {
	return verdict == string(contracts.VerdictAllow) ||
		verdict == string(contracts.VerdictDeny) ||
		verdict == string(contracts.VerdictEscalate)
}
