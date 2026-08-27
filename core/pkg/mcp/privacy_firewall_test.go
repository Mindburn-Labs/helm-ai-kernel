package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/events"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/privacy"
	"github.com/stretchr/testify/require"
)

type privacyRecordingEvaluator struct {
	mu       sync.Mutex
	calls    int
	contexts []map[string]any
	verdict  string
}

func (e *privacyRecordingEvaluator) EvaluateDecision(_ context.Context, request guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	e.contexts = append(e.contexts, request.Context)
	return &contracts.DecisionRecord{ID: "privacy-test-decision", Verdict: e.verdict}, nil
}

func (e *privacyRecordingEvaluator) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

func (e *privacyRecordingEvaluator) firstContext() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.contexts) == 0 {
		return nil
	}
	return e.contexts[0]
}

func privacyCatalog(t *testing.T) *ToolCatalog {
	t.Helper()
	catalog := NewToolCatalog()
	require.NoError(t, catalog.Register(context.Background(), ToolRef{
		Name: "privacy-tool", EffectClass: "E0", RiskTier: contracts.RiskTierLow,
	}))
	return catalog
}

func TestGovernanceFirewallProtectsInputBeforeEvaluatorAndHandler(t *testing.T) {
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	catalog := privacyCatalog(t)
	firewall := NewGovernanceFirewall(evaluator, catalog)
	var handlerArguments map[string]any
	response, err := firewall.WrapToolHandler(func(_ context.Context, request ToolExecutionRequest) (ToolExecutionResponse, error) {
		handlerArguments = request.Arguments
		return ToolExecutionResponse{Content: "accepted"}, nil
	})(context.Background(), ToolExecutionRequest{
		ToolName:  "privacy-tool",
		SessionID: "session-privacy",
		Arguments: map[string]any{
			"email": "person@example.com",
			"phone": "+1 (415) 555-2671",
			"nested": map[string]string{
				"email": "nested@example.com",
			},
			"values": []string{"+44 20 7946 0958", "2026-08-27"},
		},
	})
	require.NoError(t, err)
	require.False(t, response.IsError)
	require.NotNil(t, handlerArguments)
	assertProtectedJSON(t, evaluator.firstContext(), "person@example.com", "+1 (415) 555-2671", "nested@example.com", "+44 20 7946 0958")
	assertProtectedJSON(t, handlerArguments, "person@example.com", "+1 (415) 555-2671", "nested@example.com", "+44 20 7946 0958")
	if got := handlerArguments["values"].([]string)[1]; got != "2026-08-27" {
		t.Fatalf("clean date changed at handler boundary: %q", got)
	}
}

func TestGovernanceFirewallRestrictedInputHasZeroDispatch(t *testing.T) {
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	firewall := NewGovernanceFirewall(evaluator, privacyCatalog(t))
	handlerCalls := 0
	response, err := firewall.WrapToolHandler(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		handlerCalls++
		return ToolExecutionResponse{Content: "must not run"}, nil
	})(context.Background(), ToolExecutionRequest{
		ToolName:  "privacy-tool",
		SessionID: "session-privacy",
		Arguments: map[string]any{"card": "4111 1111 1111 1111"},
	})
	require.NoError(t, err)
	require.True(t, response.IsError)
	require.Equal(t, 0, handlerCalls)
	require.Equal(t, 0, evaluator.callCount())
	require.Contains(t, response.Content, "Access Denied")
	require.NotContains(t, response.Content, "4111")
}

func TestGovernanceFirewallProtectsAllPublicOutputRepresentationsAndAudit(t *testing.T) {
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	catalog := privacyCatalog(t)
	firewall := NewGovernanceFirewall(evaluator, catalog)
	response, err := firewall.WrapToolHandler(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{
			Content:      "contact person@example.com",
			ReceiptID:    "person@example.com",
			ContentItems: []ToolContentItem{{Type: "person@example.com", Text: "+1 (415) 555-2671", URI: "https://example.test/person@example.com", MimeType: "+44 20 7946 0958", Name: "person@example.com"}},
			StructuredContent: map[string]any{
				"email": "nested@example.com",
				"items": []string{"+44 20 7946 0958"},
			},
		}, nil
	})(context.Background(), ToolExecutionRequest{ToolName: "privacy-tool", SessionID: "session-privacy"})
	require.NoError(t, err)
	require.False(t, response.IsError)
	assertProtectedJSON(t, response, "person@example.com", "+1 (415) 555-2671", "nested@example.com", "+44 20 7946 0958")
	require.Contains(t, response.Content, "REDACTED_EMAIL")
	require.Contains(t, response.ContentItems[0].Text, "REDACTED_PHONE")
	require.Contains(t, response.ContentItems[0].URI, "REDACTED_EMAIL")
	require.Contains(t, response.ContentItems[0].Type, "REDACTED_EMAIL")
	require.Contains(t, response.ContentItems[0].MimeType, "REDACTED_PHONE")
	require.Contains(t, response.ContentItems[0].Name, "REDACTED_EMAIL")

	receipt, err := catalog.AuditToolCall("privacy-tool", map[string]any{"ok": true}, response)
	require.NoError(t, err)
	assertNoRaw(t, receipt.Outputs, "person@example.com", "+1 (415) 555-2671", "nested@example.com", "+44 20 7946 0958")
	require.Contains(t, receipt.Outputs, "REDACTED_EMAIL")
	require.Contains(t, receipt.Outputs, "REDACTED_PHONE")
	require.NotContains(t, receipt.Outputs, "person@example.com")
	// The signed runtime receipt is excluded by ToolExecutionResponse's
	// json:"-" fields; audit output remains the public MCP representation.
	response.ExecutionReceipt = &contracts.Receipt{ReceiptID: "signed", Metadata: map[string]any{"secret": "must-not-be-audited"}}
	receipt, err = catalog.AuditToolCall("privacy-tool", map[string]any{}, response)
	require.NoError(t, err)
	require.NotContains(t, receipt.Outputs, "must-not-be-audited")
	require.NotEmpty(t, response.ProtectedArgsHash)
	require.NotContains(t, receipt.Outputs, response.ProtectedArgsHash)
}

func TestGovernanceFirewallRestrictedOutputIsNotReturnedOrAudited(t *testing.T) {
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	firewall := NewGovernanceFirewall(evaluator, privacyCatalog(t))
	response, err := firewall.WrapToolHandler(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: "SSN 123-45-6789"}, nil
	})(context.Background(), ToolExecutionRequest{ToolName: "privacy-tool", SessionID: "session-privacy"})
	require.NoError(t, err)
	require.True(t, response.IsError)
	require.Empty(t, response.ReceiptID)
	require.NotContains(t, response.Content, "123-45-6789")
	require.Equal(t, 1, evaluator.callCount())
}

func TestGovernanceFirewallRejectsAggregateOutputBudget(t *testing.T) {
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	firewall := NewGovernanceFirewall(evaluator, privacyCatalog(t))
	large := strings.Repeat("safe output ", 512*1024/len("safe output "))
	items := make([]ToolContentItem, 9)
	for index := range items {
		items[index] = ToolContentItem{Type: "text", Text: large}
	}
	handlerCalls := 0
	response, err := firewall.WrapToolHandler(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		handlerCalls++
		return ToolExecutionResponse{ContentItems: items}, nil
	})(context.Background(), ToolExecutionRequest{ToolName: "privacy-tool", SessionID: "session-privacy"})
	require.NoError(t, err)
	require.True(t, response.IsError)
	require.Equal(t, 1, handlerCalls)
	require.NotContains(t, response.Content, "safe output")
	require.Equal(t, 1, evaluator.callCount())
}

func TestGatewayHTTPSessionIDIsOpaqueAndOmitsRemoteAddress(t *testing.T) {
	const remoteAddress = "203.0.113.7:4567"
	transportCatalog := NewInMemoryCatalog()
	require.NoError(t, transportCatalog.Register(context.Background(), ToolRef{
		Name: "privacy-tool", Schema: map[string]any{"type": "object"},
	}))
	governanceCatalog := privacyCatalog(t)
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	var handlerSessionID string
	var lifecycle []events.LifecycleEvent
	firewall := NewGovernanceFirewall(
		evaluator,
		governanceCatalog,
		WithLifecycleEnvironment(events.EnvSynthetic),
		WithLifecyclePublisher(func(_ context.Context, event events.LifecycleEvent) error {
			lifecycle = append(lifecycle, event)
			return nil
		}),
	)
	gateway := NewGateway(transportCatalog, GatewayConfig{}, WithGovernedExecutor(firewall.GovernedExecutor(func(_ context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error) {
		handlerSessionID = req.SessionID
		return ToolExecutionResponse{Content: "ok"}, nil
	})))
	defer gateway.sessions.Stop()

	body := []byte(`{"method":"privacy-tool","params":{}}`)
	request := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(body))
	request.RemoteAddr = remoteAddress
	recorder := httptest.NewRecorder()
	gateway.handleExecute(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.NotEmpty(t, handlerSessionID)
	require.NotEqual(t, remoteAddress, handlerSessionID)
	require.NotContains(t, handlerSessionID, remoteAddress)
	contextValue := evaluator.firstContext()[guardian.ContextSessionID]
	require.NotNil(t, contextValue)
	require.NotContains(t, contextValue, remoteAddress)
	serialized := recorder.Body.String()
	require.NotContains(t, serialized, remoteAddress)
	for _, event := range lifecycle {
		require.NotContains(t, string(mustJSON(t, event)), remoteAddress)
	}

	unknownBody := []byte(`{"method":"person@example.com","params":{}}`)
	unknown := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(unknownBody))
	unknown.RemoteAddr = remoteAddress
	unknownRecorder := httptest.NewRecorder()
	gateway.handleExecute(unknownRecorder, unknown)
	require.Equal(t, http.StatusNotFound, unknownRecorder.Code)
	require.NotContains(t, unknownRecorder.Body.String(), "person@example.com")
	for _, event := range lifecycle[4:] {
		require.NotContains(t, string(mustJSON(t, event)), "person@example.com")
	}

	second := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(body))
	second.RemoteAddr = remoteAddress
	secondRequest := toolExecutionRequestFromHTTP(second, "privacy-tool", nil)
	require.NotEqual(t, handlerSessionID, secondRequest.SessionID)
}

func TestGatewayJSONRPCBindsValidatedAndLegacyOpaqueSessionIDs(t *testing.T) {
	catalog := privacyCatalog(t)
	var evaluatorSessions []string
	evaluator := &capturingEvaluator{
		verdict: string(contracts.VerdictAllow),
		capture: func(request guardian.DecisionRequest) {
			evaluatorSessions = append(evaluatorSessions, request.Principal)
		},
	}
	var handlerSessions []string
	var lifecycle []events.LifecycleEvent
	firewall := NewGovernanceFirewall(
		evaluator,
		catalog,
		WithLifecycleEnvironment(events.EnvSynthetic),
		WithLifecyclePublisher(func(_ context.Context, event events.LifecycleEvent) error {
			lifecycle = append(lifecycle, event)
			return nil
		}),
	)
	gateway := NewGateway(catalog, GatewayConfig{}, WithGovernedExecutor(firewall.GovernedExecutor(func(_ context.Context, request ToolExecutionRequest) (ToolExecutionResponse, error) {
		handlerSessions = append(handlerSessions, request.SessionID)
		return ToolExecutionResponse{Content: "ok"}, nil
	})))
	defer gateway.sessions.Stop()
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)

	initialize := func() string {
		body, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params":  map[string]any{"protocolVersion": LatestProtocolVersion},
		})
		require.NoError(t, err)
		request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		request.RemoteAddr = "198.51.100.10:1000"
		recorder := httptest.NewRecorder()
		gateway.handleTransportPOST(recorder, request)
		require.Equal(t, http.StatusOK, recorder.Code)
		sessionID := recorder.Header().Get("MCP-Session-Id")
		require.NotEmpty(t, sessionID)
		return sessionID
	}

	firstSession := initialize()
	secondSession := initialize()
	require.NotEqual(t, firstSession, secondSession)

	call := func(sessionID, remoteAddress string) {
		body, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      2,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "privacy-tool",
				"arguments": map[string]any{},
			},
		})
		require.NoError(t, err)
		request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		request.RemoteAddr = remoteAddress
		request.Header.Set("MCP-Protocol-Version", LatestProtocolVersion)
		if sessionID != "" {
			request.Header.Set("MCP-Session-Id", sessionID)
		}
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		require.Equal(t, http.StatusOK, recorder.Code)
		require.NotContains(t, recorder.Body.String(), remoteAddress)
	}

	call(firstSession, "203.0.113.7:4567")
	call(secondSession, "203.0.113.7:4567")
	call("", "203.0.113.7:4567")
	call("", "203.0.113.7:4567")

	require.Equal(t, []string{firstSession, secondSession}, handlerSessions[:2])
	require.Len(t, handlerSessions, 4)
	require.NotEmpty(t, handlerSessions[2])
	require.NotEmpty(t, handlerSessions[3])
	require.NotEqual(t, handlerSessions[2], handlerSessions[3])
	require.NotEqual(t, firstSession, handlerSessions[2])
	require.Len(t, evaluatorSessions, 4)
	require.Equal(t, handlerSessions, evaluatorSessions)
	for _, sessionID := range handlerSessions {
		require.NotContains(t, sessionID, "203.0.113.7:4567")
	}
	for _, event := range lifecycle {
		require.NotContains(t, string(mustJSON(t, event)), "203.0.113.7:4567")
	}
}

func TestGovernanceFirewallHandlerErrorIsValueFree(t *testing.T) {
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	firewall := NewGovernanceFirewall(evaluator, privacyCatalog(t))
	handlerErr := errors.New("provider rejected person@example.com: SSN 123-45-6789")
	response, err := firewall.WrapToolHandler(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: "person@example.com"}, handlerErr
	})(context.Background(), ToolExecutionRequest{ToolName: "privacy-tool", SessionID: "session-privacy"})
	require.Error(t, err)
	require.Equal(t, errToolHandlerFailed, err)
	require.Nil(t, errors.Unwrap(err))
	require.Equal(t, "TOOL_HANDLER_FAILED", err.Error())
	require.Contains(t, response.Content, "REDACTED_EMAIL")
	require.True(t, response.IsError)
	require.Equal(t, contracts.ReasonVerification, response.RuntimeReasonCode)
	require.NotEmpty(t, response.ProtectedArgsHash)
	require.NotEmpty(t, response.ReceiptID)
	require.NotContains(t, err.Error(), "person@example.com")
	require.NotContains(t, err.Error(), "123-45-6789")
}

func TestGatewayPreservesGovernedHandlerErrorAnchorsAcrossTransports(t *testing.T) {
	catalog := privacyCatalog(t)
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	firewall := NewGovernanceFirewall(evaluator, catalog)
	gateway := NewGateway(catalog, GatewayConfig{}, WithGovernedExecutor(firewall.GovernedExecutor(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: "provider failed for person@example.com"}, errors.New("raw provider person@example.com")
	})))
	defer gateway.sessions.Stop()

	restBody := []byte(`{"method":"privacy-tool","params":{"message":"safe"}}`)
	recorder := httptest.NewRecorder()
	gateway.handleExecute(recorder, httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(restBody)))
	require.Equal(t, http.StatusOK, recorder.Code)
	var rest MCPToolCallResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &rest))
	require.Equal(t, string(contracts.ReasonVerification), rest.ReasonCode)
	require.NotEmpty(t, rest.ArgsHash)
	require.NotEmpty(t, rest.ReceiptID)
	require.Contains(t, rest.Error, "REDACTED_EMAIL")
	require.NotContains(t, recorder.Body.String(), "person@example.com")

	params := json.RawMessage(`{"name":"privacy-tool","arguments":{"message":"safe"}}`)
	response, write, status := gateway.handleJSONRPCRequestWithSession(
		context.Background(), 1, "tools/call", params, LatestProtocolVersion, "session-handler-error", nil,
	)
	require.True(t, write)
	require.Equal(t, http.StatusOK, status)
	result := response["result"].(map[string]any)
	require.Equal(t, true, result["isError"])
	require.NotEmpty(t, result["args_hash"])
	require.NotEmpty(t, result["receipt_id"])
	require.NotContains(t, string(mustJSON(t, response)), "person@example.com")
}

func TestGovernanceFirewallRejectsSerializedOutputBudget(t *testing.T) {
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	firewall := NewGovernanceFirewall(evaluator, privacyCatalog(t))
	raw := strings.Repeat("\x00", 800_000)
	response, err := firewall.WrapToolHandler(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: raw}, nil
	})(context.Background(), ToolExecutionRequest{ToolName: "privacy-tool", SessionID: "session-budget"})
	require.NoError(t, err)
	require.True(t, response.IsError)
	require.Equal(t, "Access Denied: "+string(contracts.ReasonDataEgressBlocked), response.Content)
}

func TestDirectInterceptionRejectsArgumentsThatNeedRedaction(t *testing.T) {
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	firewall := NewGovernanceFirewall(evaluator, privacyCatalog(t))
	err := firewall.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "privacy-tool",
		SessionID: "session-direct",
		Arguments: map[string]any{"message": "person@example.com"},
	})
	require.ErrorIs(t, err, privacy.ErrDataEgressBlocked)
	require.Equal(t, 0, evaluator.callCount())
}

func TestValidateToolArgumentsRejectsNonInteroperableNumbers(t *testing.T) {
	for _, literal := range []string{"1e2", "1.0", "-0", "9007199254740993"} {
		t.Run(literal, func(t *testing.T) {
			_, err := ValidateToolArguments(ToolRef{}, map[string]any{"value": json.Number(literal)})
			require.ErrorIs(t, err, canonicalize.ErrNonInteroperableNumber)
		})
	}
	_, err := ValidateToolArguments(ToolRef{}, map[string]any{"value": json.Number("100")})
	require.NoError(t, err)
}

func TestGovernanceFirewallNonCanonicalArgumentsFailBeforeHandler(t *testing.T) {
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	var lifecycle []events.LifecycleEvent
	firewall := NewGovernanceFirewall(
		evaluator,
		privacyCatalog(t),
		WithLifecycleEnvironment(events.EnvSynthetic),
		WithLifecyclePublisher(func(_ context.Context, event events.LifecycleEvent) error {
			lifecycle = append(lifecycle, event)
			return nil
		}),
	)
	handlerCalled := false
	response, err := firewall.WrapToolHandler(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		handlerCalled = true
		return ToolExecutionResponse{
			Content: "provider output must not be reported as successful",
			ExecutionReceipt: &contracts.Receipt{
				ReceiptID:  "audit-receipt",
				Status:     "SUCCESS",
				ArgsHash:   "sha256:audit",
				EffectID:   "audit-effect",
				EffectType: "TOOL_EXECUTION",
			},
		}, nil
	})(context.Background(), ToolExecutionRequest{
		ToolName:  "privacy-tool",
		SessionID: "session-privacy",
		Arguments: map[string]any{"unsupported": make(chan struct{})},
	})
	require.NoError(t, err)
	require.False(t, handlerCalled)
	require.True(t, response.IsError)
	require.True(t, response.Evaluated)
	require.Equal(t, "Access Denied: DATA_EGRESS_BLOCKED", response.Content)
	require.Equal(t, contracts.ReasonDataEgressBlocked, response.RuntimeReasonCode)
	require.Empty(t, response.ProtectedArgsHash)
	require.Empty(t, response.ReceiptID)
	require.NotContains(t, response.Content, "provider output")
	require.Equal(t, 0, evaluator.callCount())
	require.Equal(t, 0, countEvent(lifecycle, events.DispatchCompleted))
	require.Equal(t, 1, countTerminal(lifecycle))
	require.Equal(t, events.RequestFailed, lifecycle[len(lifecycle)-1].Meta.EventType)
	require.Equal(t, "preflight", fieldString(lifecycle, events.RequestFailed, "failure_class"))
}

func TestGovernanceFirewallDenialsAndLifecycleAreValueFree(t *testing.T) {
	const rawEmail = "decision-person@example.com"
	const rawSSN = "987-65-4321"
	for _, tc := range []struct {
		name      string
		evaluator PolicyEvaluator
		toolName  string
	}{
		{
			name: "evaluator error",
			evaluator: lifecycleEvaluator{err: errors.New(
				"provider policy error: " + rawEmail + " SSN " + rawSSN,
			)},
			toolName: "privacy-tool",
		},
		{
			name: "decision reason",
			evaluator: lifecycleEvaluator{decision: &contracts.DecisionRecord{
				ID:     "decision-privacy",
				Action: "EXECUTE_TOOL", Resource: "privacy-tool",
				Verdict:    string(contracts.VerdictDeny),
				Reason:     "denied " + rawEmail + " SSN " + rawSSN,
				ReasonCode: string(contracts.ReasonPolicyViolation),
			}},
			toolName: "privacy-tool",
		},
		{
			name:      "unknown tool name",
			evaluator: &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)},
			toolName:  rawEmail,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var captured []events.LifecycleEvent
			firewall := NewGovernanceFirewall(tc.evaluator, privacyCatalog(t), WithLifecycleEnvironment(events.EnvSynthetic), WithLifecyclePublisher(func(_ context.Context, event events.LifecycleEvent) error {
				captured = append(captured, event)
				return nil
			}))
			if tc.name == "unknown tool name" {
				firewall = NewGovernanceFirewall(tc.evaluator, nil, WithLifecycleEnvironment(events.EnvSynthetic), WithLifecyclePublisher(func(_ context.Context, event events.LifecycleEvent) error {
					captured = append(captured, event)
					return nil
				}))
			}
			response, err := firewall.WrapToolHandler(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
				return ToolExecutionResponse{Content: "must not run"}, nil
			})(context.Background(), ToolExecutionRequest{ToolName: tc.toolName, SessionID: "session-privacy"})
			require.NoError(t, err)
			require.True(t, response.IsError)
			encodedResponse := mustMarshal(t, response)
			assertNoRaw(t, encodedResponse, rawEmail, rawSSN)
			for _, event := range captured {
				assertNoRaw(t, string(mustJSON(t, event)), rawEmail, rawSSN)
			}
		})
	}
}

func TestGovernanceFirewallInterceptPlanUsesProtectedAdmission(t *testing.T) {
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	firewall := NewGovernanceFirewall(evaluator, nil)
	decision, err := firewall.InterceptPlan(context.Background(), ToolExecutionPlan{
		PlanID: "plan-privacy",
		Steps:  []ToolExecutionRequest{{ToolName: "privacy-tool", SessionID: "session-privacy", Arguments: map[string]any{"email": "person@example.com"}}},
	})
	require.NoError(t, err)
	require.Len(t, decision.Decisions, 1)
	assertProtectedJSON(t, evaluator.firstContext(), "person@example.com")

	blockedEvaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	blockedFirewall := NewGovernanceFirewall(blockedEvaluator, nil)
	_, err = blockedFirewall.InterceptPlan(context.Background(), ToolExecutionPlan{
		PlanID: "plan-blocked",
		Steps:  []ToolExecutionRequest{{ToolName: "privacy-tool", Arguments: map[string]any{"ssn": "123-45-6789"}}},
	})
	require.Error(t, err)
	require.Equal(t, 0, blockedEvaluator.callCount())
	require.NotContains(t, err.Error(), "123-45-6789")
}

func TestGovernanceFirewallInterceptPlanRejectsUnsafeDecisionProjection(t *testing.T) {
	const rawEmail = "plan-person@example.com"
	const rawSSN = "987-65-4321"
	evaluator := lifecycleEvaluator{decision: &contracts.DecisionRecord{
		ID:      "plan-decision",
		Verdict: string(contracts.VerdictAllow),
		Reason:  "allowing " + rawEmail,
		InputContext: map[string]any{
			"explanation": "SSN " + rawSSN,
		},
	}}
	firewall := NewGovernanceFirewall(evaluator, nil)
	decision, err := firewall.InterceptPlan(context.Background(), ToolExecutionPlan{
		PlanID: "plan-privacy",
		Steps:  []ToolExecutionRequest{{ToolName: "privacy-tool"}},
	})
	require.Error(t, err)
	require.Nil(t, decision)
	require.ErrorIs(t, err, privacy.ErrDataEgressBlocked)
	require.NotContains(t, err.Error(), rawEmail)
	require.NotContains(t, err.Error(), rawSSN)
}

func TestGovernanceFirewallInterceptPlanPendingNeverAggregatesToAllow(t *testing.T) {
	evaluator := &smartMockEvaluator{decisions: map[string]string{
		"allow":   string(contracts.VerdictAllow),
		"pending": "PENDING",
		"deny":    string(contracts.VerdictDeny),
	}}
	firewall := NewGovernanceFirewall(evaluator, nil)

	pendingPlan, err := firewall.InterceptPlan(context.Background(), ToolExecutionPlan{
		PlanID: "plan-pending",
		Steps: []ToolExecutionRequest{
			{ToolName: "allow"},
			{ToolName: "pending"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, string(contracts.VerdictEscalate), pendingPlan.Status)
	require.Equal(t, "PENDING", pendingPlan.Decisions[1].Verdict)

	denyPlan, err := firewall.InterceptPlan(context.Background(), ToolExecutionPlan{
		PlanID: "plan-deny",
		Steps: []ToolExecutionRequest{
			{ToolName: "allow"},
			{ToolName: "pending"},
			{ToolName: "deny"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, string(contracts.VerdictDeny), denyPlan.Status)
}

func TestGovernanceFirewallInterceptPlanRejectsAggregateDecisionBudget(t *testing.T) {
	firewall := NewGovernanceFirewall(lifecycleEvaluator{decision: &contracts.DecisionRecord{
		ID:      "large-decision",
		Verdict: string(contracts.VerdictAllow),
		Reason:  strings.Repeat("x", 700<<10),
	}}, nil)
	steps := make([]ToolExecutionRequest, 8)
	for index := range steps {
		steps[index] = ToolExecutionRequest{ToolName: "privacy-tool"}
	}
	decision, err := firewall.InterceptPlan(context.Background(), ToolExecutionPlan{
		PlanID: "aggregate-budget",
		Steps:  steps,
	})
	require.Nil(t, decision)
	require.ErrorIs(t, err, privacy.ErrDataEgressBlocked)
}

func TestGatewayGovernedHashBindsProtectedArgumentsAndReason(t *testing.T) {
	catalog := privacyCatalog(t)
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	var handlerArguments map[string]any
	firewall := NewGovernanceFirewall(evaluator, catalog)
	gateway := NewGateway(catalog, GatewayConfig{}, WithGovernedExecutor(firewall.GovernedExecutor(func(_ context.Context, request ToolExecutionRequest) (ToolExecutionResponse, error) {
		handlerArguments = request.Arguments
		if request.Arguments["restricted_output"] == true {
			return ToolExecutionResponse{Content: "4111 1111 1111 1111"}, nil
		}
		return ToolExecutionResponse{Content: "ok"}, nil
	})))
	defer gateway.sessions.Stop()

	rawArguments := map[string]any{"message": "person@example.com"}
	body, err := json.Marshal(MCPToolCallRequest{Method: "privacy-tool", Params: rawArguments})
	require.NoError(t, err)
	recorder := httptest.NewRecorder()
	gateway.handleExecute(recorder, httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(body)))
	require.Equal(t, http.StatusOK, recorder.Code)
	var allowed MCPToolCallResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &allowed))
	protectedHash, err := ValidateToolArguments(ToolRef{}, handlerArguments)
	require.NoError(t, err)
	rawHash, err := ValidateToolArguments(ToolRef{}, rawArguments)
	require.NoError(t, err)
	require.Equal(t, "[REDACTED_EMAIL]", handlerArguments["message"])
	require.Equal(t, protectedHash, allowed.ArgsHash)
	require.NotEqual(t, rawHash, allowed.ArgsHash)

	body, err = json.Marshal(MCPToolCallRequest{
		Method: "privacy-tool",
		Params: map[string]any{"restricted_output": true},
	})
	require.NoError(t, err)
	recorder = httptest.NewRecorder()
	gateway.handleExecute(recorder, httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(body)))
	require.Equal(t, http.StatusForbidden, recorder.Code)
	var denied MCPToolCallResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &denied))
	require.Equal(t, string(contracts.ReasonDataEgressBlocked), denied.ReasonCode)
}

func TestGatewayPreservesRestrictedNumericPrecisionAcrossTransports(t *testing.T) {
	catalog := privacyCatalog(t)
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	handlerCalls := 0
	firewall := NewGovernanceFirewall(evaluator, catalog)
	gateway := NewGateway(catalog, GatewayConfig{}, WithGovernedExecutor(firewall.GovernedExecutor(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		handlerCalls++
		return ToolExecutionResponse{Content: "must not run"}, nil
	})))
	defer gateway.sessions.Stop()

	restBody := []byte("{\"method\":\"privacy-tool\",\"params\":{\"pan\":4000000000000000006}}")
	recorder := httptest.NewRecorder()
	gateway.handleExecute(recorder, httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(restBody)))
	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.Contains(t, recorder.Body.String(), string(contracts.ReasonDataEgressBlocked))

	jsonRPCBody := []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"privacy-tool\",\"arguments\":{\"pan\":4000000000000000006}}}")
	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(jsonRPCBody))
	request.Header.Set("MCP-Protocol-Version", LatestProtocolVersion)
	gateway.handleTransportPOST(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), string(contracts.ReasonDataEgressBlocked))
	require.Equal(t, 0, handlerCalls)
	require.Equal(t, 0, evaluator.callCount())
}

func TestGovernanceFirewallEscapedValuesAreProtectedBeforeDispatch(t *testing.T) {
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	firewall := NewGovernanceFirewall(evaluator, privacyCatalog(t))
	doubleEscapedEmail := `\\u0070\\u0065\\u0072\\u0073\\u006f\\u006e\\u0040\\u0065\\u0078\\u0061\\u006d\\u0070\\u006c\\u0065\\u002e\\u0063\\u006f\\u006d`
	rawEmail, err := json.Marshal(doubleEscapedEmail)
	require.NoError(t, err)
	var handlerArguments map[string]any
	response, err := firewall.WrapToolHandler(func(_ context.Context, request ToolExecutionRequest) (ToolExecutionResponse, error) {
		handlerArguments = request.Arguments
		return ToolExecutionResponse{Content: "ok"}, nil
	})(context.Background(), ToolExecutionRequest{
		ToolName:  "privacy-tool",
		SessionID: "session-privacy",
		Arguments: map[string]any{"payload": json.RawMessage(rawEmail)},
	})
	require.NoError(t, err)
	require.False(t, response.IsError)
	assertNoRaw(t, mustMarshal(t, handlerArguments), "person@example.com")
	require.Contains(t, mustMarshal(t, handlerArguments), "REDACTED_EMAIL")

	blockedEvaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	blockedFirewall := NewGovernanceFirewall(blockedEvaluator, privacyCatalog(t))
	doubleEscapedSSN := `\\u0031\\u0032\\u0033\\u002d\\u0034\\u0035\\u002d\\u0036\\u0037\\u0038\\u0039`
	rawSSN, err := json.Marshal(doubleEscapedSSN)
	require.NoError(t, err)
	blocked, err := blockedFirewall.WrapToolHandler(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		t.Fatal("handler dispatched restricted escaped value")
		return ToolExecutionResponse{}, nil
	})(context.Background(), ToolExecutionRequest{ToolName: "privacy-tool", Arguments: map[string]any{"payload": json.RawMessage(rawSSN)}})
	require.NoError(t, err)
	require.True(t, blocked.IsError)
	require.Equal(t, 0, blockedEvaluator.callCount())
	require.NotContains(t, blocked.Content, "123-45-6789")
}

func TestGovernanceFirewallEscapedProviderOutputIsProtected(t *testing.T) {
	doubleEscapedEmail := `\\u0070\\u0065\\u0072\\u0073\\u006f\\u006e\\u0040\\u0065\\u0078\\u0061\\u006d\\u0070\\u006c\\u0065\\u002e\\u0063\\u006f\\u006d`
	doubleEscapedPhone := `\\u002b\\u0031\\u0020\\u0034\\u0031\\u0035\\u0020\\u0035\\u0035\\u0035\\u002d\\u0032\\u0036\\u0037\\u0031`
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	firewall := NewGovernanceFirewall(evaluator, privacyCatalog(t))
	response, err := firewall.WrapToolHandler(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: doubleEscapedEmail + " " + doubleEscapedPhone}, nil
	})(context.Background(), ToolExecutionRequest{ToolName: "privacy-tool", SessionID: "session-privacy"})
	require.NoError(t, err)
	require.False(t, response.IsError)
	require.Contains(t, response.Content, "REDACTED_EMAIL")
	require.Contains(t, response.Content, "REDACTED_PHONE")
	require.NotContains(t, response.Content, "\\\\u0070")

	for _, restricted := range []string{
		`\\u0031\\u0032\\u0033\\u002d\\u0034\\u0035\\u002d\\u0036\\u0037\\u0038\\u0039`,
		`\\u0034\\u0031\\u0031\\u0031\\u0020\\u0031\\u0031\\u0031\\u0031\\u0020\\u0031\\u0031\\u0031\\u0031\\u0020\\u0031\\u0031\\u0031\\u0031`,
		`\\u0047\\u0042\\u0038\\u0032\\u0020\\u0057\\u0045\\u0053\\u0054\\u0020\\u0031\\u0032\\u0033\\u0034\\u0020\\u0035\\u0036\\u0039\\u0038\\u0020\\u0037\\u0036\\u0035\\u0034\\u0020\\u0033\\u0032`,
		`\\u0061\\u0070\\u0069\\u005f\\u006b\\u0065\\u0079\\u003d\\u0073\\u006b\\u005f\\u006c\\u0069\\u0076\\u0065\\u005f\\u0031\\u0032\\u0033\\u0034\\u0035\\u0036\\u0037\\u0038\\u0039\\u0030`,
	} {
		blockedEvaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
		blockedFirewall := NewGovernanceFirewall(blockedEvaluator, privacyCatalog(t))
		blocked, err := blockedFirewall.WrapToolHandler(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
			return ToolExecutionResponse{Content: restricted}, nil
		})(context.Background(), ToolExecutionRequest{ToolName: "privacy-tool", SessionID: "session-privacy"})
		// The restricted value is returned by the provider, so Guardian still
		// evaluates once; the egress firewall must deny before audit/public return.
		require.NoError(t, err)
		require.True(t, blocked.IsError)
		require.Empty(t, blocked.ReceiptID)
		require.Equal(t, 1, blockedEvaluator.callCount())
		require.Equal(t, "Access Denied: DATA_EGRESS_BLOCKED", blocked.Content)
	}
}

func TestGovernanceFirewallDataEgressLifecycleReasonIsCanonical(t *testing.T) {
	evaluator := &privacyRecordingEvaluator{verdict: string(contracts.VerdictAllow)}
	var captured []events.LifecycleEvent
	firewall := NewGovernanceFirewall(evaluator, privacyCatalog(t), WithLifecycleEnvironment(events.EnvSynthetic), WithLifecyclePublisher(func(_ context.Context, event events.LifecycleEvent) error {
		captured = append(captured, event)
		return nil
	}))
	const rawReceiptEmail = "receipt-person@example.com"
	const rawEffectEmail = "effect-person@example.com"
	const rawReceiptSecret = "password=abc123"
	const rawReceiptSSN = "123-45-6789"
	response, err := firewall.WrapToolHandler(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{
			Content:       "4111 1111 1111 1111",
			DispatchState: "provider " + rawReceiptEmail,
			ExecutionReceipt: &contracts.Receipt{
				ReceiptID:  rawReceiptEmail,
				Status:     "SSN " + rawReceiptSSN,
				ArgsHash:   rawReceiptSecret,
				EffectID:   rawEffectEmail,
				EffectType: rawReceiptSecret,
			},
		}, nil
	})(context.Background(), ToolExecutionRequest{ToolName: "privacy-tool", SessionID: "session-privacy"})
	require.NoError(t, err)
	require.True(t, response.IsError)
	if len(captured) == 0 {
		t.Fatal("expected synthetic lifecycle events")
	}
	last := captured[len(captured)-1]
	require.Equal(t, events.RequestFailed, last.Meta.EventType)
	require.Equal(t, string(contracts.ReasonDataEgressBlocked), last.Fields["reason_code"])
	require.Equal(t, 1, countEvent(captured, events.DispatchCompleted))
	require.Equal(t, 1, countTerminal(captured))
	for _, event := range captured {
		encoded := string(mustJSON(t, event))
		for _, raw := range []string{rawReceiptEmail, rawEffectEmail, rawReceiptSecret, rawReceiptSSN} {
			require.NotContains(t, encoded, raw)
		}
		if event.Meta.EventType == events.DispatchCompleted {
			require.Contains(t, encoded, events.StableRef(rawReceiptEmail))
			require.Contains(t, encoded, events.StableRef(rawEffectEmail))
			require.NotContains(t, encoded, "[REDACTED_EMAIL]")
		}
	}
	dispatchIndex, failedIndex := -1, -1
	for index, event := range captured {
		switch event.Meta.EventType {
		case events.DispatchCompleted:
			dispatchIndex = index
		case events.RequestFailed:
			failedIndex = index
		}
	}
	require.Less(t, dispatchIndex, failedIndex)
}

func assertProtectedJSON(t *testing.T, value any, raw ...string) {
	t.Helper()
	encoded := mustMarshal(t, value)
	assertNoRaw(t, encoded, raw...)
}

func assertNoRaw(t *testing.T, value string, raw ...string) {
	t.Helper()
	for _, item := range raw {
		if strings.Contains(value, item) {
			t.Fatalf("raw sensitive fixture survived: %q in %s", item, value)
		}
	}
}

func mustMarshal(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal test value: %v", err)
	}
	return string(encoded)
}
