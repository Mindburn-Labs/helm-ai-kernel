// quantum_posture: signed proxy receipts use classical Ed25519 signatures and SHA-256 hashes.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/bridge"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	helmotel "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/otel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

func proxyStatusBlocksBody(status string) bool {
	switch status {
	case "DENIED", "PEP_VALIDATION_FAILED", "GOVERNANCE_ERROR", "PROXY_ITERATION_LIMIT", "PROXY_WALLCLOCK_LIMIT", "UNGOVERNABLE_RESPONSE":
		return true
	default:
		return false
	}
}

func deniedProxyResponseBody(status, reasonCode string, toolNames []string, correlationID string) []byte {
	if reasonCode == "" {
		reasonCode = status
	}
	helm := map[string]any{
		"status":      status,
		"reason_code": reasonCode,
		"tool_names":  append([]string(nil), toolNames...),
	}
	body := map[string]any{
		"error": map[string]any{
			"message": "HELM proxy blocked a governed tool call",
			"type":    "helm_governance_denied",
			"code":    reasonCode,
		},
		"helm": helm,
	}
	if correlationID != "" {
		helm["correlation_id"] = correlationID
	}
	data, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"error":{"message":"HELM proxy blocked a governed tool call","type":"helm_governance_denied","code":"DENIED"}}`)
	}
	return data
}

func containDeniedProxyResponse(resp *http.Response, status, reasonCode string, toolNames []string, correlationID string) []byte {
	body := deniedProxyResponseBody(status, reasonCode, toolNames, correlationID)
	if resp != nil {
		resp.StatusCode = http.StatusForbidden
		resp.Status = "403 Forbidden"
		resp.Header.Set("Content-Type", "application/json")
		resp.Header.Del("Content-Length")
		resp.Header.Del("Content-Encoding")
	}
	return body
}

type proxyResponseHandler struct {
	upstream    string
	tenantID    string
	genAISystem string
	proofPath   string
	fenceScope  emergencyStopScope
	graph       *proofgraph.Graph
	limits      *proxySessionLimits
	governance  *bridge.KernelBridge
	store       *receiptStore
	signer      *helmcrypto.Ed25519Signer
	tracer      *helmotel.GovernanceTracer
	jsonOutput  bool
	verbose     bool
}

func (processor proxyResponseHandler) modify(resp *http.Response) error {
	// The correlation ID is a client-visible join key for both regular
	// responses and SSE streams, which return before receipt creation.
	reqCtx := resp.Request.Context()
	correlationID, _ := reqCtx.Value(ctxKeyCorrelationID).(string)
	if correlationID != "" {
		resp.Header.Set("X-Helm-Correlation-ID", correlationID)
	}
	info, known := reqCtx.Value(ctxKeyRequestInfo).(proxyRequestInfo)
	if !known {
		info.toolsDeclared = true
	}

	// Detect SSE streaming response
	isSSE := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")
	if isSSE && !info.toolsDeclared {
		// No tools were offered, so the stream cannot carry a tool call.
		// It passes through unparsed and unreceipted, and says so.
		resp.Header.Set("X-Helm-SSE", "passthrough-no-tools")
		passMsg, _ := json.Marshal(map[string]any{
			"upstream": processor.upstream,
			"status":   "STREAM_PASSTHROUGH_NO_TOOLS",
		})
		_, _ = processor.graph.Append(proofgraph.NodeTypeEffect, passMsg, "helm-proxy", 0)
		return nil
	}

	// Everything else is read in full before any byte reaches the client.
	// A stream offered tools is not read at all: it is withheld below.
	var body []byte
	if isSSE {
		_ = resp.Body.Close()
	} else {
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		body = b
	}

	// Pull per-request governance state stashed by the handler and Director.
	requestModel := info.model
	traceparent, _ := reqCtx.Value(ctxKeyTraceparent).(string)
	sessionID, _ := reqCtx.Value(ctxKeySessionID).(string)
	credentialHash, _ := helmauth.AuthenticatedCredentialHash(reqCtx)

	// Extract OTel GenAI usage from response body.
	inputTokens, outputTokens, _, finishReason := extractGenAIUsage(body)

	// Parse for tool_calls + PEP validation
	calls, model, chatShape := extractChatToolCalls(body)
	toolCallCount := len(calls)
	var argsHashes []string
	var argsValid []bool
	var toolNames []string
	status := "APPROVED"
	var reasonCode string
	var decisionID string
	var pgNodeID string

	// Tools were offered, but the response is not one the proxy can
	// inspect: a stream, or a body that is not Chat Completions JSON. A
	// tool call could be inside it, so it is withheld (audit 03-02).
	// Non-2xx bodies carry errors, not executable tool calls.
	if isSSE || (info.toolsDeclared && !chatShape && resp.StatusCode >= 200 && resp.StatusCode < 300) {
		status = "UNGOVERNABLE_RESPONSE"
		reasonCode = "PROXY_UNGOVERNABLE_RESPONSE"
		log.Printf("[DENY] tools were offered but the upstream response (%s) cannot be governed", resp.Header.Get("Content-Type"))
	}

	for _, call := range calls {
		toolNames = append(toolNames, call.name)

		// PEP validation: validate + canonicalize + hash
		hash, valid := "", false
		if call.readable {
			hash, valid = validateToolCallArgs(call.arguments)
		}
		argsHashes = append(argsHashes, hash)
		argsValid = append(argsValid, valid)
		if !valid {
			status = "PEP_VALIDATION_FAILED"
			reasonCode = "SCHEMA_VIOLATION"
			log.Printf("[WARN] PEP validation failed for tool_call %q (missing name or malformed arguments)", call.name)
			continue
		}

		if limit := processor.limits.admit(sessionID); limit != "" {
			status = limit
			reasonCode = limit
			log.Printf("[DENY] tool=%s session=%s %s", call.name, sessionID, limit)
			continue
		}

		// KernelBridge governance. The binding carries the transport
		// identity the Guardian's isolation gate requires; without it
		// every tool call was denied before policy ran (audit 07-01).
		govResult, govErr := processor.governance.GovernBound(context.Background(), call.name, hash, nil, bridge.Binding{
			CredentialHash: credentialHash,
			SessionID:      sessionID,
			TenantID:       processor.fenceScope.TenantID,
			WorkspaceID:    processor.fenceScope.WorkspaceID,
		})
		if govErr != nil {
			status = "GOVERNANCE_ERROR"
			reasonCode = "PDP_ERROR"
			log.Printf("[ERROR] governance error: %v", govErr)
			continue
		}
		pgNodeID = govResult.NodeID
		if govResult.Decision != nil {
			decisionID = govResult.Decision.ID
		}
		if !govResult.Allowed {
			status = "DENIED"
			reasonCode = govResult.ReasonCode
			log.Printf("[DENY] tool=%s reason=%s node=%s", call.name, reasonCode, pgNodeID)
		}
	}

	// Choose the response-side model when available; the request side
	// (sent in the proxy body) is captured separately so we can record
	// both for routing audit (e.g. Azure deployment vs concrete model).
	responseModel := model
	if responseModel == "" {
		responseModel = requestModel
	}

	// Pick a representative tool name for the OTel GenAI span. When no
	// tool call is present, fall back to the operation kind.
	var spanToolName string
	if len(toolNames) > 0 {
		spanToolName = toolNames[0]
	}
	operationName := observability.GenAIOperationChat
	if toolCallCount > 0 {
		operationName = observability.GenAIOperationToolCall
	}

	// Decide a verdict label for the OTel span.
	verdict := "ALLOW"
	if proxyStatusBlocksBody(status) {
		verdict = "DENY"
		body = containDeniedProxyResponse(resp, status, reasonCode, toolNames, correlationID)
	}

	// Hash the body that will be delivered to the client.
	outHash := sha256.Sum256(body)
	outHashHex := "sha256:" + hex.EncodeToString(outHash[:])

	rcpt := &proxyReceipt{
		Timestamp:        time.Now().UTC().Format(time.RFC3339Nano),
		Upstream:         processor.upstream,
		Model:            model,
		OutputHash:       outHashHex,
		ToolCalls:        toolCallCount,
		ToolNames:        toolNames,
		ArgsHashes:       argsHashes,
		ArgsValid:        argsValid,
		Status:           status,
		ReasonCode:       reasonCode,
		DecisionID:       decisionID,
		ProofGraphNodeID: pgNodeID,

		// gen_ai.tool.call.id == helm correlation_id (single source of truth).
		CorrelationID:      correlationID,
		SessionID:          sessionID,
		GenAISystem:        processor.genAISystem,
		GenAIRequestModel:  requestModel,
		GenAIOperationName: operationName,
		GenAIToolCallID:    correlationID,
		GenAIInputTokens:   inputTokens,
		GenAIOutputTokens:  outputTokens,
		GenAIFinishReason:  finishReason,
		Traceparent:        traceparent,
	}

	// Persist receipt (JSONL, append-only, causal chain). The store
	// assigns the Lamport clock; the id and signature are sealed with it.
	// A response whose receipt cannot be written is not delivered.
	if storeErr := processor.store.Append(rcpt, func(r *proxyReceipt) error {
		r.ReceiptID = fmt.Sprintf("rcpt-proxy-%d-%d", time.Now().UnixNano(), r.LamportClock)
		if processor.signer == nil {
			return nil
		}
		payload := fmt.Sprintf("%s:%s:%s:%d", r.ReceiptID, r.OutputHash, r.Status, r.LamportClock)
		sig, signErr := processor.signer.Sign([]byte(payload))
		if signErr != nil {
			return fmt.Errorf("sign receipt: %w", signErr)
		}
		r.Signature = sig
		return nil
	}); storeErr != nil {
		log.Printf("[ERROR] receipt persist failed, failing the request: %v", storeErr)
		return fmt.Errorf("persist governance receipt: %w", storeErr)
	}

	// Emit OTel GenAI tool_call span. gen_ai.tool.call.id == helm
	// correlation_id so traces and receipts cross-reference 1:1.
	processor.tracer.TraceGenAIToolCall(reqCtx, helmotel.GenAIToolCallEvent{
		System:        processor.genAISystem,
		RequestModel:  requestModel,
		ResponseModel: responseModel,
		OperationName: operationName,
		ToolName:      spanToolName,
		ToolCallID:    correlationID,
		InputTokens:   inputTokens,
		OutputTokens:  outputTokens,
		FinishReason:  finishReason,
		Verdict:       verdict,
		ReasonCode:    reasonCode,
		PolicyID:      decisionID,
		ProofNodeID:   pgNodeID,
		CorrelationID: correlationID,
		ReceiptID:     rcpt.ReceiptID,
		TenantID:      processor.tenantID,
	})

	// Persist ProofGraph (JSON snapshot after each append)
	persistProofGraph(processor.graph, processor.proofPath)

	// Inject receipt headers
	resp.Header.Set("X-Helm-Receipt-ID", rcpt.ReceiptID)
	resp.Header.Set("X-Helm-Output-Hash", rcpt.OutputHash)
	resp.Header.Set("X-Helm-Lamport-Clock", fmt.Sprintf("%d", rcpt.LamportClock))
	resp.Header.Set("X-Helm-Status", rcpt.Status)
	if traceparent != "" {
		resp.Header.Set("traceparent", traceparent)
	}
	if rcpt.ReasonCode != "" {
		resp.Header.Set("X-Helm-Reason-Code", rcpt.ReasonCode)
	}
	if rcpt.DecisionID != "" {
		resp.Header.Set("X-Helm-Decision-ID", rcpt.DecisionID)
	}
	if rcpt.ProofGraphNodeID != "" {
		resp.Header.Set("X-Helm-ProofGraph-Node", rcpt.ProofGraphNodeID)
	}
	if toolCallCount > 0 {
		resp.Header.Set("X-Helm-Tool-Calls", fmt.Sprintf("%d", toolCallCount))
	}
	if rcpt.Signature != "" {
		resp.Header.Set("X-Helm-Signature", rcpt.Signature)
	}

	// Log receipt
	if processor.jsonOutput {
		rcptJSON, _ := json.Marshal(rcpt)
		log.Printf("%s", rcptJSON)
	} else if processor.verbose {
		log.Printf("[RECEIPT] %s | %s | tools=%d | status=%s | %s",
			rcpt.ReceiptID, rcpt.Model, rcpt.ToolCalls, rcpt.Status, rcpt.OutputHash[:30]+"…")
	}

	// Restore body
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	return nil
}

// persistProofGraph serializes the ProofGraph DAG to a JSON file.
func persistProofGraph(pg *proofgraph.Graph, path string) {
	nodes := pg.AllNodes()
	graphData := map[string]any{
		"version": "1.0",
		"nodes":   nodes,
		"heads":   pg.Heads(),
		"lamport": pg.LamportClock(),
		"count":   pg.Len(),
	}
	data, err := json.MarshalIndent(graphData, "", "  ")
	if err != nil {
		log.Printf("[WARN] failed to serialize ProofGraph: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		log.Printf("[WARN] failed to persist ProofGraph to %s: %v", path, err)
	}
}
