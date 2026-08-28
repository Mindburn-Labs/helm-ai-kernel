package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/correlation"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/events"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/privacy"
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

	// ingressFailureReasonCode is set only by the trusted Gateway after it has
	// rejected a syntactically valid tool call before policy evaluation. Keeping
	// it private prevents callers from bypassing governance through the wire
	// contract while allowing the lifecycle wrapper to close the request.
	ingressFailureReasonCode string
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
	// excluded from automatic JSON serialization; the gateway explicitly projects
	// only ProtectedArgsHash as the safe proof anchor alongside the audit receipt.
	ExecutionReceipt        *contracts.Receipt `json:"-"`
	DispatchState           string             `json:"-"`
	ApprovalHash            string             `json:"-"`
	ApproverID              string             `json:"-"`
	DispatchAdmissionExpiry time.Time          `json:"-"`
	ProtectedArgsHash       string             `json:"-"`
	runtimeReasonCode       contracts.ReasonCode
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
	privacy      *privacy.StandardPrivacyManager
}

const (
	lifecycleSourceRef  = "MCP"
	maxMCPResponseItems = 10000
	// MaxResponseBytes bounds every serialized MCP response, including its
	// transport envelope and trailing newline.
	MaxResponseBytes = 4 << 20
)

var (
	errGovernanceCheckFailed      = errors.New("governance check failed")
	errGovernanceDecisionEmpty    = errors.New("governance returned empty decision")
	errGovernanceNonCanonical     = errors.New("governance returned non-canonical verdict")
	errGovernanceBlocked          = errors.New("governance blocked execution: policy violation")
	errGovernanceApprovalRequired = errors.New("governance requires approval")
	errDelegationScopeViolation   = errors.New("delegation scope violation")
	errReservedSecurityArgument   = errors.New("reserved security context argument rejected")
	errClassificationFailed       = errors.New("tool classification failed")
	errPlanEvaluationFailed       = errors.New("failed to evaluate plan step")
	errPlanDecisionEgressBlocked  = fmt.Errorf("%w: plan decision rejected", privacy.ErrDataEgressBlocked)
	errToolHandlerFailed          = errors.New("TOOL_HANDLER_FAILED")
	errAuditDenied                = errors.New("audit denied")
)

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
		privacy:      privacy.NewPrivacyManager(),
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
	protectedReq, decisionCtx, findings, err := f.prepareToolExecutionRequest(ctx, req)
	if err != nil {
		return err
	}
	// This API returns only a verdict, not the protected request. Allowing a
	// redaction here would let a caller execute the original value after Guardian
	// evaluated a different payload, so direct interception must fail closed.
	if len(findings) > 0 {
		return privacy.ErrDataEgressBlocked
	}
	decision, err := f.evaluatePreparedToolExecution(ctx, protectedReq, decisionCtx)
	if err != nil {
		return err
	}
	return f.decisionError(decision)
}

// prepareToolExecutionRequest creates the protected request and the trusted
// Guardian context from the same sanitized argument map. This is the single
// admission boundary used by direct interception, wrapped handlers, and plans.
func (f *GovernanceFirewall) prepareToolExecutionRequest(ctx context.Context, req ToolExecutionRequest) (ToolExecutionRequest, map[string]interface{}, []string, error) {
	if f.evaluator == nil {
		return ToolExecutionRequest{}, nil, nil, fmt.Errorf("governance evaluator is required")
	}
	// Preserve the transport-boundary contract for security context keys. This
	// check precedes value inspection so a caller cannot turn a reserved-key
	// violation into a different privacy verdict.
	for key := range req.Arguments {
		if guardian.IsReservedSecurityContextKey(key) {
			return ToolExecutionRequest{}, nil, nil, errReservedSecurityArgument
		}
	}

	manager := f.privacy
	if manager == nil {
		manager = privacy.NewPrivacyManager()
	}
	protected, findings, err := manager.Protect(ctx, req.Arguments)
	if err != nil {
		return ToolExecutionRequest{}, nil, nil, privacy.ErrDataEgressBlocked
	}
	protectedArguments, ok := protected.(map[string]interface{})
	if !ok && protected != nil {
		return ToolExecutionRequest{}, nil, nil, privacy.ErrDataEgressBlocked
	}
	protectedReq := req
	protectedReq.Arguments = protectedArguments

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
			return ToolExecutionRequest{}, nil, nil, errDelegationScopeViolation
		}
	}

	// Build Guardian decision context, forwarding delegation metadata.
	decisionCtx := make(map[string]interface{})
	for k, v := range protectedReq.Arguments {
		if guardian.IsReservedSecurityContextKey(k) {
			return ToolExecutionRequest{}, nil, nil, errReservedSecurityArgument
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
	return protectedReq, decisionCtx, findings, nil
}

func (f *GovernanceFirewall) evaluatePreparedToolExecution(ctx context.Context, req ToolExecutionRequest, decisionCtx map[string]interface{}) (*contracts.DecisionRecord, error) {
	decision, err := f.evaluator.EvaluateDecision(ctx, guardian.DecisionRequest{
		Principal: req.SessionID,
		Action:    "EXECUTE_TOOL",
		Resource:  req.ToolName,
		Context:   decisionCtx,
	})
	if err != nil {
		return nil, errGovernanceCheckFailed
	}
	if decision == nil {
		return nil, errGovernanceDecisionEmpty
	}

	return decision, nil
}

func (f *GovernanceFirewall) decisionError(decision *contracts.DecisionRecord) error {
	if decision == nil {
		return errGovernanceDecisionEmpty
	}

	// Enforce Decision — use canonical verdict constants
	switch decision.Verdict {
	case string(contracts.VerdictAllow):
		return nil
	case string(contracts.VerdictDeny):
		return errGovernanceBlocked
	case string(contracts.VerdictEscalate), "PENDING":
		return errGovernanceApprovalRequired
	default:
		return errGovernanceNonCanonical
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
		protectedArgsHash := ""
		anchorResponse := func(response ToolExecutionResponse) ToolExecutionResponse {
			response.ProtectedArgsHash = protectedArgsHash
			return response
		}
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
		emitDispatch := func(response ToolExecutionResponse) {
			if response.ExecutionReceipt == nil {
				return
			}
			receipt := f.protectDispatchReceipt(ctx, *response.ExecutionReceipt)
			// Only the authoritative receipt returned by the governed runtime can
			// claim that a dispatch completed. ToolCatalog's audit receipt is an
			// unpersisted observation and remains a response-only audit field.
			emit(events.NewDispatchCompleted(
				meta(), receipt, "",
				events.LifecycleEnrichment{
					EffectContext:    f.protectDispatchString(ctx, response.DispatchState),
					ApprovalRef:      events.StableRef(response.ApprovalHash),
					ApproverRef:      events.StableRef(response.ApproverID),
					ApprovalExpiryMs: lifecycleExpiryMs(response.DispatchAdmissionExpiry),
				},
			))
		}
		publicToolName := f.publicLifecycleToolName(ctx, req.ToolName)
		actorRef := events.StableRef(req.SessionID)
		emit(events.NewRequestReceived(
			meta(), "EXECUTE_TOOL", publicToolName,
			events.LifecycleEnrichment{
				ActorRef: actorRef,
				Surface:  string(contracts.SourceChannelMCPClient),
				Tool:     publicToolName,
			},
		))
		if req.ingressFailureReasonCode != "" {
			emitFailure(req.ingressFailureReasonCode, "ingress")
			return deniedResponse(fmt.Errorf("MCP ingress rejected: %s", req.ingressFailureReasonCode)), nil
		}
		protectedReq, decisionCtx, _, preflightErr := f.prepareToolExecutionRequest(ctx, req)
		if preflightErr != nil {
			reasonCode := preflightReasonCode(f, req)
			if errors.Is(preflightErr, privacy.ErrDataEgressBlocked) || errors.Is(preflightErr, privacy.ErrDataEgressInvalid) {
				reasonCode = contracts.ReasonDataEgressBlocked
			}
			emitFailure(string(reasonCode), "preflight")
			return deniedResponse(preflightErr), nil
		}
		tool, classificationErr := classifyTool(f.catalog, req.ToolName)
		if classificationErr != nil {
			emitFailure(string(contracts.ReasonSchemaViolation), "classification")
			return anchorResponse(deniedResponse(errClassificationFailed)), nil
		}
		var hashErr error
		protectedArgsHash, hashErr = ValidateToolArguments(tool, protectedReq.Arguments)
		if hashErr != nil {
			emitFailure(string(contracts.ReasonDataEgressBlocked), "preflight")
			return anchorResponse(deniedResponse(privacy.ErrDataEgressBlocked)), nil
		}

		effectClass, riskTier := tool.EffectClass, tool.RiskTier
		emit(events.NewRequestClassified(
			meta(), effectClass, string(riskTier),
			events.LifecycleEnrichment{
				Action:               "EXECUTE_TOOL",
				Resource:             publicToolName,
				EffectContext:        "pep_catalog",
				ClassificationSource: "pep_catalog",
			},
		))

		decisionStarted := time.Now()
		decision, evalErr := f.evaluatePreparedToolExecution(ctx, protectedReq, decisionCtx)
		decisionLatency := time.Since(decisionStarted).Milliseconds()
		if evalErr != nil {
			emitFailure(string(contracts.ReasonPDPError), "evaluator")
			return anchorResponse(deniedResponse(evalErr)), nil
		}

		publicDecision := f.publicDecisionProjection(ctx, *decision)
		emit(events.NewPolicyApplied(meta(), publicDecision, nil))
		emit(events.NewDecisionMade(meta(), publicDecision, events.LifecycleEnrichment{
			DecisionLatencyMs: decisionLatency,
		}))

		switch decision.Verdict {
		case string(contracts.VerdictDeny):
			emitFailure(decisionReasonCode(decision, contracts.ReasonPDPDeny), "policy")
			return anchorResponse(deniedResponse(f.decisionError(decision))), nil
		case string(contracts.VerdictEscalate), "PENDING":
			escalationDecision := f.publicDecisionProjection(ctx, *decision)
			if escalationDecision.Verdict == "PENDING" {
				escalationDecision.Verdict = string(contracts.VerdictEscalate)
			}
			if event, err := events.NewEscalationTriggered(meta(), escalationDecision); err == nil {
				emit(event)
			} else {
				slog.Error("governance_firewall: escalation projection failed")
			}
			emitFailure(decisionReasonCode(decision, contracts.ReasonApprovalRequired), "escalation")
			return anchorResponse(deniedResponse(f.decisionError(decision))), nil
		case string(contracts.VerdictAllow):
			// Continue to the handler and the catalog audit below.
		default:
			emitFailure(string(contracts.ReasonPDPError), "evaluator")
			return anchorResponse(deniedResponse(f.decisionError(decision))), nil
		}

		var resp ToolExecutionResponse
		var handlerErr error
		if handler == nil {
			handlerErr = fmt.Errorf("tool handler is required")
		} else {
			resp, handlerErr = handler(ctx, protectedReq)
		}
		if resp.ExecutionReceipt != nil && resp.ExecutionReceipt.ArgsHash != protectedArgsHash {
			emitFailure(string(contracts.ReasonVerification), "receipt")
			return anchorResponse(deniedResponse(errToolHandlerFailed)), errToolHandlerFailed
		}
		resp.runtimeReasonCode = ""
		resp.ProtectedArgsHash = protectedArgsHash

		protectedResp, protectErr := f.protectToolExecutionResponse(ctx, resp)
		if protectErr != nil {
			emitDispatch(resp)
			emitFailure(string(contracts.ReasonDataEgressBlocked), "egress")
			denied := anchorResponse(deniedResponse(privacy.ErrDataEgressBlocked))
			if resp.ExecutionReceipt != nil {
				receipt := f.protectDispatchReceipt(ctx, *resp.ExecutionReceipt)
				denied.ReceiptID = receipt.ReceiptID
				if denied.ReceiptID == "" {
					denied.ReceiptID = receipt.ID
				}
			}
			return denied, nil
		}
		resp = protectedResp
		resp.Evaluated = true
		if handlerErr != nil {
			resp.IsError = true
		}
		if resp.IsError {
			resp.runtimeReasonCode = contracts.ReasonVerification
		}

		var receipt ToolCallReceipt
		var auditErr error
		if f.catalog != nil {
			// ToolExecutionResponse's runtime-only receipt anchor and dispatch
			// metadata are json:"-". Auditing the full response therefore covers
			// every public MCP representation without copying signed metadata into
			// the audit payload.
			receipt, auditErr = f.catalog.AuditToolCall(protectedReq.ToolName, protectedReq.Arguments, resp)
			if auditErr != nil {
				slog.Error("governance_firewall: audit logging failed")
			} else {
				slog.Info("governance_firewall: tool execution audited", "receipt_id", receipt.ID)
				resp.ReceiptID = receipt.ID
			}
		}

		if handlerErr != nil || resp.IsError {
			emitDispatch(resp)
			emitFailure(string(contracts.ReasonVerification), "handler")
			if handlerErr != nil {
				return resp, errToolHandlerFailed
			}
			return resp, nil
		}
		if auditErr != nil {
			emitDispatch(resp)
			emitFailure(string(contracts.ReasonVerification), "audit")
			return anchorResponse(deniedResponse(errAuditDenied)), nil
		}

		emitDispatch(resp)
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

// protectDispatchReceipt sanitizes only the telemetry projection. The
// authoritative receipt returned by the governed runtime is never mutated;
// lifecycle fields are a public export and must not become an egress channel
// for a malicious handler/provider.
func (f *GovernanceFirewall) protectDispatchReceipt(ctx context.Context, receipt contracts.Receipt) contracts.Receipt {
	receipt.ReceiptID = f.protectDispatchString(ctx, receipt.ReceiptID)
	receipt.ID = f.protectDispatchString(ctx, receipt.ID)
	receipt.Status = f.protectDispatchString(ctx, receipt.Status)
	receipt.ArgsHash = f.protectDispatchString(ctx, receipt.ArgsHash)
	receipt.EffectID = f.protectDispatchString(ctx, receipt.EffectID)
	receipt.EffectType = f.protectDispatchString(ctx, receipt.EffectType)
	return receipt
}

func (f *GovernanceFirewall) protectDispatchString(ctx context.Context, value string) string {
	if value == "" {
		return ""
	}
	manager := f.privacy
	if manager == nil {
		manager = privacy.NewPrivacyManager()
	}
	protected, _, err := manager.Protect(ctx, value)
	if err == nil {
		if protectedString, ok := protected.(string); ok {
			if protectedString == value {
				return value
			}
			return events.StableRef(value)
		}
	}
	// A restricted or unsupported projection cannot be emitted verbatim. A
	// deterministic one-way reference retains correlation without exporting the
	// receipt/provider value or the cause of a privacy failure.
	return events.StableRef(value)
}

func (f *GovernanceFirewall) publicLifecycleToolName(ctx context.Context, name string) string {
	if name == "" {
		return ""
	}
	if f.catalog != nil {
		if _, known := f.catalog.Lookup(name); known {
			return f.protectDispatchString(ctx, name)
		}
	}
	// Unknown names are untrusted request data. Keep lifecycle correlation
	// possible without exporting a caller-controlled name.
	return events.StableRef(name)
}

func (f *GovernanceFirewall) publicDecisionProjection(ctx context.Context, decision contracts.DecisionRecord) contracts.DecisionRecord {
	decision.ID = f.protectDispatchString(ctx, decision.ID)
	decision.Verdict = f.protectDispatchString(ctx, decision.Verdict)
	decision.PolicyBackend = f.protectDispatchString(ctx, decision.PolicyBackend)
	decision.PolicyVersion = f.protectDispatchString(ctx, decision.PolicyVersion)
	decision.PolicyContentHash = f.protectDispatchString(ctx, decision.PolicyContentHash)
	decision.PolicyEpoch = f.protectDispatchString(ctx, decision.PolicyEpoch)
	decision.PolicyDecisionHash = f.protectDispatchString(ctx, decision.PolicyDecisionHash)
	decision.ReasonCode = f.protectDispatchString(ctx, decision.ReasonCode)
	decision.Action = f.protectDispatchString(ctx, decision.Action)
	decision.Resource = f.protectDispatchString(ctx, decision.Resource)
	return decision
}

// protectToolExecutionResponse copies every public response representation
// before audit, lifecycle completion, or returning it through the gateway.
// ExecutionReceipt and the other runtime-only anchors are deliberately not
// traversed or mutated.
func (f *GovernanceFirewall) protectToolExecutionResponse(ctx context.Context, resp ToolExecutionResponse) (ToolExecutionResponse, error) {
	if !responseWithinPrivacyBudget(resp, false) {
		return ToolExecutionResponse{}, privacy.ErrDataEgressInvalid
	}
	manager := f.privacy
	if manager == nil {
		manager = privacy.NewPrivacyManager()
	}
	content, _, err := manager.Protect(ctx, resp.Content)
	if err != nil {
		return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
	}
	protectedContent, ok := content.(string)
	if !ok {
		return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
	}

	var protectedItems []ToolContentItem
	if resp.ContentItems != nil {
		protectedItems = make([]ToolContentItem, len(resp.ContentItems))
	}
	for index, item := range resp.ContentItems {
		protectedItems[index] = item
		var protectErr error
		protectedItems[index].Type, protectErr = protectResponseString(ctx, manager, item.Type)
		if protectErr != nil {
			return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
		}
		protectedItems[index].Text, protectErr = protectResponseString(ctx, manager, item.Text)
		if protectErr != nil {
			return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
		}
		protectedItems[index].URI, protectErr = protectResponseString(ctx, manager, item.URI)
		if protectErr != nil {
			return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
		}
		protectedItems[index].MimeType, protectErr = protectResponseString(ctx, manager, item.MimeType)
		if protectErr != nil {
			return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
		}
		protectedItems[index].Name, protectErr = protectResponseString(ctx, manager, item.Name)
		if protectErr != nil {
			return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
		}
	}

	structured, _, err := manager.Protect(ctx, resp.StructuredContent)
	if err != nil {
		return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
	}
	var protectedStructured map[string]any
	if structured != nil {
		var mapOK bool
		protectedStructured, mapOK = structured.(map[string]any)
		if !mapOK {
			return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
		}
	}
	receiptID, protectErr := protectResponseString(ctx, manager, resp.ReceiptID)
	if protectErr != nil {
		return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
	}

	resp.Content = protectedContent
	resp.ContentItems = protectedItems
	resp.StructuredContent = protectedStructured
	resp.ReceiptID = receiptID
	if !responseWithinPrivacyBudget(resp, true) {
		return ToolExecutionResponse{}, privacy.ErrDataEgressInvalid
	}
	return resp, nil
}

func responseWithinPrivacyBudget(resp ToolExecutionResponse, includeStructured bool) bool {
	if len(resp.ContentItems) > maxMCPResponseItems {
		return false
	}
	if includeStructured {
		encodedResponse, responseErr := json.Marshal(resp)
		encodedToolResult, resultErr := json.Marshal(ToolResultPayload(resp))
		return responseErr == nil && resultErr == nil &&
			len(encodedResponse)+1 <= MaxResponseBytes && len(encodedToolResult)+1 <= MaxResponseBytes
	}
	total := 0
	add := func(size int) bool {
		if size < 0 || size > MaxResponseBytes-total {
			return false
		}
		total += size
		return true
	}
	if !add(len(resp.Content)) || !add(len(resp.ReceiptID)) {
		return false
	}
	for _, item := range resp.ContentItems {
		if !add(len(item.Type)) || !add(len(item.Text)) || !add(len(item.URI)) ||
			!add(len(item.MimeType)) || !add(len(item.Name)) {
			return false
		}
	}
	return true
}

func protectResponseString(ctx context.Context, manager *privacy.StandardPrivacyManager, value string) (string, error) {
	protected, _, err := manager.Protect(ctx, value)
	if err != nil {
		return "", err
	}
	protectedString, ok := protected.(string)
	if !ok {
		return "", privacy.ErrDataEgressBlocked
	}
	return protectedString, nil
}

func deniedResponse(err error) ToolExecutionResponse {
	message := "GOVERNANCE_DENIED"
	reasonCode := contracts.ReasonPolicyViolation
	switch {
	case errors.Is(err, privacy.ErrDataEgressBlocked), errors.Is(err, privacy.ErrDataEgressInvalid):
		message = string(contracts.ReasonDataEgressBlocked)
		reasonCode = contracts.ReasonDataEgressBlocked
	case errors.Is(err, errDelegationScopeViolation):
		message = errDelegationScopeViolation.Error()
		reasonCode = contracts.ReasonDelegationScopeViolation
	case errors.Is(err, errReservedSecurityArgument):
		message = errReservedSecurityArgument.Error()
		reasonCode = contracts.ReasonSchemaViolation
	case errors.Is(err, errGovernanceCheckFailed):
		message = errGovernanceCheckFailed.Error()
		reasonCode = contracts.ReasonPDPError
	case errors.Is(err, errGovernanceBlocked):
		message = errGovernanceBlocked.Error()
		reasonCode = contracts.ReasonPDPDeny
	case errors.Is(err, errGovernanceApprovalRequired):
		message = errGovernanceApprovalRequired.Error()
		reasonCode = contracts.ReasonApprovalRequired
	case errors.Is(err, errGovernanceNonCanonical):
		message = errGovernanceNonCanonical.Error()
		reasonCode = contracts.ReasonPDPError
	case errors.Is(err, errClassificationFailed):
		reasonCode = contracts.ReasonSchemaViolation
	case errors.Is(err, errAuditDenied), errors.Is(err, errToolHandlerFailed):
		reasonCode = contracts.ReasonVerification
	}
	return ToolExecutionResponse{
		Content:           "Access Denied: " + message,
		IsError:           true,
		Evaluated:         true,
		runtimeReasonCode: reasonCode,
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
		if tenantID, err := auth.GetTenantID(ctx); err == nil && tenantID != "" && tenantID != auth.SystemTenantID {
			// A tenant-bearing request is not synthetic even when the process
			// was started with the synthetic switch; do not relabel it. HELM's
			// own system pseudo-tenant carries no customer tenancy and remains
			// eligible for the explicitly enabled synthetic lane.
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

func classifyTool(catalog *ToolCatalog, name string) (ToolRef, error) {
	if catalog == nil {
		return ToolRef{}, fmt.Errorf("tool classification is unavailable")
	}
	ref, ok := catalog.Lookup(name)
	if !ok {
		return ToolRef{}, fmt.Errorf("tool %q is not classified in the PEP catalog", name)
	}
	if !validEffectClass(ref.EffectClass) {
		return ToolRef{}, fmt.Errorf("tool %q has invalid PEP effect classification", name)
	}
	if !validRiskTier(ref.RiskTier) {
		return ToolRef{}, fmt.Errorf("tool %q has invalid PEP risk tier", name)
	}
	if expected := riskTierForEffectClass(ref.EffectClass); ref.RiskTier != expected {
		return ToolRef{}, fmt.Errorf("tool %q has mismatched PEP effect class and risk tier", name)
	}
	return ref, nil
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
	if err := f.validatePlanPublicValue(ctx, plan.PlanID); err != nil {
		return nil, err
	}
	if len(plan.Steps) > maxMCPResponseItems {
		return nil, errPlanDecisionEgressBlocked
	}
	decisions := make([]*contracts.DecisionRecord, 0, len(plan.Steps))
	overallStatus := string(contracts.VerdictAllow)
	totalDecisionBytes := 0

	for _, step := range plan.Steps {
		// Plans use the same protected admission boundary as direct tool
		// execution. This prevents a plan from becoming a raw-arguments side
		// channel around the firewall.
		protectedStep, decisionCtx, _, err := f.prepareToolExecutionRequest(ctx, step)
		if err != nil {
			return nil, err
		}
		decision, err := f.evaluatePreparedToolExecution(ctx, protectedStep, decisionCtx)
		if err != nil {
			return nil, errPlanEvaluationFailed
		}
		if decision == nil {
			return nil, errPlanEvaluationFailed
		}
		if !isCanonicalToolVerdict(decision.Verdict) && decision.Verdict != "PENDING" {
			return nil, errPlanEvaluationFailed
		}
		decisionBytes, err := f.validatePlanDecision(ctx, decision)
		if err != nil {
			return nil, err
		}
		if decisionBytes > MaxResponseBytes-totalDecisionBytes {
			return nil, errPlanDecisionEgressBlocked
		}
		totalDecisionBytes += decisionBytes

		// Aggregate Status. PENDING is a legacy spelling of an escalation;
		// normalize only the plan aggregate and never mutate the signed record.
		switch decision.Verdict {
		case string(contracts.VerdictDeny):
			overallStatus = string(contracts.VerdictDeny)
		case string(contracts.VerdictEscalate), "PENDING":
			if overallStatus != string(contracts.VerdictDeny) {
				overallStatus = string(contracts.VerdictEscalate)
			}
		}

		decisions = append(decisions, decision)
	}

	result := &PlanDecision{
		PlanID:    plan.PlanID,
		Decisions: decisions,
		Status:    overallStatus,
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > MaxResponseBytes {
		return nil, errPlanDecisionEgressBlocked
	}
	return result, nil
}

func (f *GovernanceFirewall) validatePlanPublicValue(ctx context.Context, value string) error {
	manager := f.privacy
	if manager == nil {
		manager = privacy.NewPrivacyManager()
	}
	protected, findings, err := manager.Protect(ctx, value)
	if err != nil || len(findings) > 0 {
		return errPlanDecisionEgressBlocked
	}
	if protectedString, ok := protected.(string); !ok || protectedString != value {
		return errPlanDecisionEgressBlocked
	}
	return nil
}

func (f *GovernanceFirewall) validatePlanDecision(ctx context.Context, decision *contracts.DecisionRecord) (int, error) {
	if decision == nil {
		return 0, errPlanEvaluationFailed
	}
	encoded, err := json.Marshal(decision)
	if err != nil || len(encoded) > MaxResponseBytes {
		return 0, errPlanDecisionEgressBlocked
	}
	manager := f.privacy
	if manager == nil {
		manager = privacy.NewPrivacyManager()
	}
	_, findings, err := manager.Protect(ctx, json.RawMessage(encoded))
	if err != nil || len(findings) > 0 {
		return 0, errPlanDecisionEgressBlocked
	}
	return len(encoded), nil
}

func isCanonicalToolVerdict(verdict string) bool {
	return verdict == string(contracts.VerdictAllow) ||
		verdict == string(contracts.VerdictDeny) ||
		verdict == string(contracts.VerdictEscalate)
}
