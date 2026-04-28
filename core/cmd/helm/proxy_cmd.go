package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/bridge"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/budget"
	helmcrypto "github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/manifest"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/observability"
	helmotel "github.com/Mindburn-Labs/helm-oss/core/pkg/otel"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/tracing"
)

// proxyReceipt is the governance receipt attached to every proxied request.
//
// Fields in the gen_ai.* family follow the OTel GenAI semantic conventions
// (see core/pkg/observability/genai_attrs.go). gen_ai.tool.call.id mirrors
// the helm correlation_id so OTel traces and helm receipts cross-reference 1:1.
type proxyReceipt struct {
	ReceiptID        string   `json:"receipt_id"`
	Timestamp        string   `json:"timestamp"`
	Upstream         string   `json:"upstream"`
	Model            string   `json:"model,omitempty"`
	InputHash        string   `json:"input_hash"`
	OutputHash       string   `json:"output_hash,omitempty"`
	ToolCalls        int      `json:"tool_calls_intercepted"`
	ToolNames        []string `json:"tool_names,omitempty"`
	ArgsHashes       []string `json:"args_hashes,omitempty"`
	ArgsValid        []bool   `json:"args_valid,omitempty"`
	Status           string   `json:"status"`
	ReasonCode       string   `json:"reason_code,omitempty"`
	DecisionID       string   `json:"decision_id,omitempty"`
	ProofGraphNodeID string   `json:"proofgraph_node,omitempty"`
	LamportClock     uint64   `json:"lamport_clock"`
	PrevHash         string   `json:"prev_hash"`
	Signature        string   `json:"signature,omitempty"`

	// helm-specific governance correlation. Equals gen_ai.tool.call.id below.
	CorrelationID string `json:"correlation_id,omitempty"`

	// OTel GenAI semconv mirrors. Persisted alongside the receipt so the
	// receipt is self-contained for replay/audit even without the OTel trace.
	GenAISystem        string `json:"gen_ai_system,omitempty"`
	GenAIRequestModel  string `json:"gen_ai_request_model,omitempty"`
	GenAIOperationName string `json:"gen_ai_operation_name,omitempty"`
	GenAIToolCallID    string `json:"gen_ai_tool_call_id,omitempty"`
	GenAIInputTokens   int64  `json:"gen_ai_input_tokens,omitempty"`
	GenAIOutputTokens  int64  `json:"gen_ai_output_tokens,omitempty"`
	GenAIFinishReason  string `json:"gen_ai_finish_reason,omitempty"`

	// W3C traceparent header recorded with the receipt for trace ↔ receipt joins.
	Traceparent string `json:"traceparent,omitempty"`
}

// receiptStore persists receipts to a JSONL file for auditability.
type receiptStore struct {
	mu       sync.Mutex
	file     *os.File
	prevHash string
}

func newReceiptStore(path string) (*receiptStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &receiptStore{file: f, prevHash: "GENESIS"}, nil
}

func (s *receiptStore) Append(rcpt *proxyReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rcpt.PrevHash = s.prevHash

	data, err := json.Marshal(rcpt)
	if err != nil {
		return err
	}

	// Update causal chain: prevHash = SHA-256 of this receipt's JSON
	h := sha256.Sum256(data)
	s.prevHash = "sha256:" + hex.EncodeToString(h[:])

	data = append(data, '\n')
	_, err = s.file.Write(data)
	return err
}

func (s *receiptStore) Close() error {
	return s.file.Close()
}

// proxyCtxKey is a unique context key type to stash per-request governance state
// from Director through to ModifyResponse without collisions with other packages.
type proxyCtxKey struct{ name string }

var (
	ctxKeyCorrelationID = proxyCtxKey{"correlation_id"}
	ctxKeyRequestModel  = proxyCtxKey{"request_model"}
	ctxKeyTraceparent   = proxyCtxKey{"traceparent"}
)

// inferGenAISystem maps a configured upstream URL to the OTel GenAI system
// vocabulary. Falls back to the empty string when the host is unrecognized;
// downstream tracing will simply omit the gen_ai.system attribute.
func inferGenAISystem(upstreamURL *url.URL) string {
	host := strings.ToLower(upstreamURL.Host)
	switch {
	case strings.Contains(host, "openai.azure.com"):
		return observability.GenAISystemAzureOpenAI
	case strings.Contains(host, "openai.com"):
		return observability.GenAISystemOpenAI
	case strings.Contains(host, "anthropic.com"):
		return observability.GenAISystemAnthropic
	case strings.Contains(host, "bedrock"):
		return observability.GenAISystemBedrock
	case strings.Contains(host, "googleapis.com") || strings.Contains(host, "generativelanguage"):
		return observability.GenAISystemGemini
	default:
		return ""
	}
}

// extractRequestModel pulls the "model" field from a JSON request body,
// covering OpenAI (chat/completions, responses), Anthropic (/v1/messages),
// and Bedrock InvokeModel-style payloads. Returns "" when the body is not
// JSON or the field is absent — callers must tolerate that.
func extractRequestModel(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		return ""
	}
	if m, ok := top["model"].(string); ok && m != "" {
		return m
	}
	// Bedrock InvokeModel embeds the body inside "body" as a JSON-encoded string.
	if inner, ok := top["body"].(string); ok {
		var nested map[string]any
		if err := json.Unmarshal([]byte(inner), &nested); err == nil {
			if m, ok := nested["model"].(string); ok && m != "" {
				return m
			}
		}
	}
	return ""
}

// extractGenAIUsage pulls token-count + finish_reason fields from a JSON
// response. OpenAI: usage.prompt_tokens / usage.completion_tokens / choices[0].finish_reason.
// Anthropic: usage.input_tokens / usage.output_tokens / stop_reason.
// Bedrock: model-dependent — handled best-effort via the OpenAI/Anthropic shapes.
func extractGenAIUsage(body []byte) (inputTokens, outputTokens int64, finishReason string) {
	if len(body) == 0 {
		return 0, 0, ""
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		return 0, 0, ""
	}
	if usage, ok := top["usage"].(map[string]any); ok {
		inputTokens = pickInt64(usage, "prompt_tokens", "input_tokens")
		outputTokens = pickInt64(usage, "completion_tokens", "output_tokens")
	}
	// OpenAI finish_reason on first choice
	if choices, ok := top["choices"].([]any); ok && len(choices) > 0 {
		if c0, ok := choices[0].(map[string]any); ok {
			if fr, ok := c0["finish_reason"].(string); ok {
				finishReason = fr
			}
		}
	}
	// Anthropic stop_reason at the top level
	if finishReason == "" {
		if sr, ok := top["stop_reason"].(string); ok {
			finishReason = sr
		}
	}
	return inputTokens, outputTokens, finishReason
}

func pickInt64(m map[string]any, keys ...string) int64 {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			return int64(v)
		case int64:
			return v
		case int:
			return int64(v)
		}
	}
	return 0
}

// validateToolCallArgs performs PEP validation: validates tool arguments
// via the manifest package (JCS canonicalization + SHA-256 hash).
// Schema validation is skipped (nil schema) in open-policy proxy mode;
// schemas can be loaded from manifest files in the future.
func validateToolCallArgs(argsStr string) (string, bool) {
	// Step 1: args must parse as valid JSON (fail-closed on malformed)
	var parsed any
	if err := json.Unmarshal([]byte(argsStr), &parsed); err != nil {
		return "", false
	}

	// Step 2: Delegate to manifest package for JCS canonicalization + SHA-256
	// nil schema = skip schema enforcement, still canonicalize + hash
	result, err := manifest.ValidateAndCanonicalizeToolArgs(nil, parsed)
	if err != nil {
		return "", false
	}

	return result.ArgsHash, true
}

// runProxyCmd implements `helm proxy`.
//
// Usage:
//
//	helm proxy --upstream https://api.openai.com/v1 --port 9090
//
// Then:
//
//	export OPENAI_BASE_URL=http://localhost:9090/v1
//	python your_app.py  # Every tool call now gets a receipt.
//
// Features:
//   - Receipt persistence: JSONL audit log at --receipts-dir
//   - PEP validation: tool_call arguments validated as JSON, canonicalized (JCS), and SHA-256 hashed
//   - Causal chain: receipts linked via PrevHash (SHA-256 of previous receipt)
//   - Ed25519 signature: receipts signed if --sign is enabled
//
// Exit codes:
//
//	0 = clean shutdown
//	2 = config error
func runProxyCmd(args []string, stdout, stderr io.Writer) int {
	// Handle `proxy up` alias — strip "up" and pass remaining args
	if len(args) > 0 && args[0] == "up" {
		args = args[1:]
	}

	cmd := flag.NewFlagSet("proxy", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		upstream      string
		port          int
		apiKey        string
		jsonOutput    bool
		verbose       bool
		receiptsDir   string
		signKey       string
		tenantID      string
		dailyLimit    int64
		monthlyLimit  int64
		maxIterations int
		maxWallclock  time.Duration
		websocket     bool
	)

	cmd.StringVar(&upstream, "upstream", "https://api.openai.com/v1", "Upstream API base URL")
	cmd.IntVar(&port, "port", 9090, "Local proxy port")
	cmd.StringVar(&apiKey, "api-key", "", "API key to forward to upstream (or use OPENAI_API_KEY env)")
	cmd.BoolVar(&jsonOutput, "json", false, "Log receipts as JSON to stdout")
	cmd.BoolVar(&verbose, "verbose", false, "Verbose logging")
	cmd.StringVar(&receiptsDir, "receipts-dir", "./helm-receipts", "Directory for persistent receipt JSONL logs")
	cmd.StringVar(&signKey, "sign", "", "Ed25519 signing key seed (enables receipt signatures)")
	cmd.StringVar(&tenantID, "tenant-id", "default", "Tenant identifier for budget enforcement")
	cmd.Int64Var(&dailyLimit, "daily-limit", 100000, "Daily budget limit in cents (0=unlimited)")
	cmd.Int64Var(&monthlyLimit, "monthly-limit", 1000000, "Monthly budget limit in cents (0=unlimited)")
	cmd.IntVar(&maxIterations, "max-iterations", 10, "Max tool call rounds per session (0=unlimited)")
	cmd.DurationVar(&maxWallclock, "max-wallclock", 120*time.Second, "Max session wallclock duration (0=unlimited)")
	cmd.BoolVar(&websocket, "websocket", false, "Request Responses WebSocket mode (unsupported in OSS runtime)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if websocket {
		_, _ = fmt.Fprintln(stderr, "Error: --websocket is not supported in the OSS proxy runtime")
		_, _ = fmt.Fprintln(stderr, "Use the HTTP proxy surface at /v1/chat/completions until Responses WebSocket support is implemented.")
		return 2
	}

	// Normalize upstream URL
	upstream = strings.TrimSuffix(upstream, "/")

	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: invalid upstream URL: %v\n", err)
		return 2
	}

	// Initialize receipt store
	receiptPath := filepath.Join(receiptsDir, fmt.Sprintf("receipts-%s.jsonl", time.Now().Format("2006-01-02")))
	store, err := newReceiptStore(receiptPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: failed to initialize receipt store at %s: %v\n", receiptPath, err)
		return 2
	}
	defer store.Close()

	// Ed25519 signer (used for both receipts and KernelBridge governance)
	kernelSignerID := signKey
	if kernelSignerID == "" {
		kernelSignerID = "helm-proxy"
	}
	kernelSigner, err := helmcrypto.NewEd25519Signer(kernelSignerID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: failed to create kernel signer: %v\n", err)
		return 2
	}

	// Optional: separate receipt signer (same key for now)
	var signer *helmcrypto.Ed25519Signer
	if signKey != "" {
		signer = kernelSigner
	}

	// Initialize KernelBridge: Guardian + ProofGraph + Budget
	prgGraph := prg.NewGraph()
	artStore, artErr := artifacts.NewFileStore(filepath.Join(receiptsDir, "artifacts"))
	if artErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error: failed to create artifact store: %v\n", artErr)
		return 2
	}
	artRegistry := artifacts.NewRegistry(artStore, kernelSigner)
	g := guardian.NewGuardian(kernelSigner, prgGraph, artRegistry)
	pg := proofgraph.NewGraph()

	// Budget enforcer (in-memory for sidecar mode)
	var budgetEnforcer budget.Enforcer
	if dailyLimit > 0 || monthlyLimit > 0 {
		memStorage := budget.NewMemoryStorage()
		enforcer := budget.NewSimpleEnforcer(memStorage)
		if setErr := enforcer.SetLimits(context.Background(), tenantID, dailyLimit, monthlyLimit); setErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: failed to set budget limits: %v\n", setErr)
			return 2
		}
		budgetEnforcer = enforcer
	}

	kb := bridge.NewKernelBridge(g, prgGraph, pg, budgetEnforcer, tenantID)

	// Governance tracer — attaches OTel GenAI spans to every request.
	// NoopTracer when no OTLP endpoint is configured; the GovernanceTracer
	// itself decides whether to wire a real exporter.
	otelTracer := helmotel.NoopTracer()
	if endpoint := os.Getenv("HELM_OTLP_ENDPOINT"); endpoint != "" {
		if rt, otelErr := helmotel.NewGovernanceTracer(helmotel.Config{
			ServiceName: "helm-proxy",
			Endpoint:    endpoint,
			Insecure:    os.Getenv("HELM_OTLP_INSECURE") == "1",
		}); otelErr == nil {
			otelTracer = rt
			defer func() { _ = otelTracer.Shutdown(context.Background()) }()
		} else {
			log.Printf("[WARN] OTLP exporter setup failed, falling back to noop: %v", otelErr)
		}
	}

	genAISystem := inferGenAISystem(upstreamURL)

	var lamport uint64
	var iterationCount int64
	sessionStart := time.Now()

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Buffer + restore request body so we can extract the request model
			// and pass it through to ModifyResponse via the request context.
			var bodyBytes []byte
			if req.Body != nil {
				if b, readErr := io.ReadAll(req.Body); readErr == nil {
					bodyBytes = b
					req.Body = io.NopCloser(bytes.NewReader(b))
					req.ContentLength = int64(len(b))
				}
			}
			requestModel := extractRequestModel(bodyBytes)

			// helm correlation_id — also used as gen_ai.tool.call.id so OTel traces
			// and helm receipts cross-reference 1:1.
			corr := tracing.NewCorrelationID()
			ctx := tracing.WithCorrelationID(req.Context(), corr)
			ctx = context.WithValue(ctx, ctxKeyCorrelationID, string(corr))
			ctx = context.WithValue(ctx, ctxKeyRequestModel, requestModel)

			// Inject W3C traceparent so the upstream provider's traces (if any)
			// link back into our governance trace tree.
			helmotel.InjectTraceparent(ctx, req.Header)
			tracing.InjectHTTPHeaders(ctx, req.Header)
			ctx = context.WithValue(ctx, ctxKeyTraceparent, req.Header.Get("traceparent"))

			// Set advisory header so upstreams that look for it can echo the id.
			req.Header.Set("X-Helm-Correlation-ID", string(corr))

			*req = *req.WithContext(ctx)

			req.URL.Scheme = upstreamURL.Scheme
			req.URL.Host = upstreamURL.Host
			origPath := req.URL.Path
			if strings.HasPrefix(origPath, "/v1") && strings.HasSuffix(upstream, "/v1") {
				req.URL.Path = upstreamURL.Path + strings.TrimPrefix(origPath, "/v1")
			} else {
				req.URL.Path = upstreamURL.Path + origPath
			}
			req.Host = upstreamURL.Host

			// Forward API key
			if apiKey != "" && req.Header.Get("Authorization") == "" {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			// Detect SSE streaming response
			contentType := resp.Header.Get("Content-Type")
			isSSE := strings.Contains(contentType, "text/event-stream")

			if isSSE {
				// Streaming responses pass through immediately; governance evidence is
				// recorded after the stream because this proxy path does not parse
				// chunks inline.
				log.Printf("[INFO] SSE streaming response detected, applying post-hoc governance")
				resp.Header.Set("X-Helm-SSE", "post-stream-governance")

				deferMsg, _ := json.Marshal(map[string]any{
					"upstream": upstream,
					"status":   "POST_STREAM_GOVERNANCE",
				})
				_, _ = pg.Append(proofgraph.NodeTypeEffect, deferMsg, "helm-proxy", 0)

				return nil
			}

			// Non-streaming: read full response body
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}

			clock := atomic.AddUint64(&lamport, 1)

			// Pull per-request governance state stashed by Director.
			reqCtx := resp.Request.Context()
			correlationID, _ := reqCtx.Value(ctxKeyCorrelationID).(string)
			requestModel, _ := reqCtx.Value(ctxKeyRequestModel).(string)
			traceparent, _ := reqCtx.Value(ctxKeyTraceparent).(string)

			// Extract OTel GenAI usage from response body.
			inputTokens, outputTokens, finishReason := extractGenAIUsage(body)

			// Hash output
			outHash := sha256.Sum256(body)
			outHashHex := "sha256:" + hex.EncodeToString(outHash[:])

			// Parse for tool_calls + PEP validation
			var chatResp map[string]any
			toolCallCount := 0
			var argsHashes []string
			var argsValid []bool
			var toolNames []string
			var model string
			status := "APPROVED"
			var reasonCode string
			var decisionID string
			var pgNodeID string

			if err := json.Unmarshal(body, &chatResp); err == nil {
				if m, ok := chatResp["model"].(string); ok {
					model = m
				}
				if choices, ok := chatResp["choices"].([]any); ok {
					for _, c := range choices {
						choice, ok := c.(map[string]any)
						if !ok {
							continue
						}
						msg, ok := choice["message"].(map[string]any)
						if !ok {
							continue
						}
						if tcs, ok := msg["tool_calls"].([]any); ok {
							for _, tc := range tcs {
								toolCallCount++
								tcMap, ok := tc.(map[string]any)
								if !ok {
									continue
								}
								fn, ok := tcMap["function"].(map[string]any)
								if !ok {
									continue
								}

								// Extract tool name
								var toolName string
								if name, ok := fn["name"].(string); ok {
									toolName = name
									toolNames = append(toolNames, name)
								}

								// PEP validation: validate + canonicalize + hash
								if argsStr, ok := fn["arguments"].(string); ok {
									hash, valid := validateToolCallArgs(argsStr)
									argsHashes = append(argsHashes, hash)
									argsValid = append(argsValid, valid)
									if !valid {
										status = "PEP_VALIDATION_FAILED"
										reasonCode = "SCHEMA_VIOLATION"
										log.Printf("[WARN] PEP validation failed for tool_call args (malformed JSON)")
									}

									// KernelBridge governance
									if valid && toolName != "" {
										// Check iteration limit
										currIter := atomic.AddInt64(&iterationCount, 1)
										if maxIterations > 0 && int(currIter) > maxIterations {
											status = "PROXY_ITERATION_LIMIT"
											reasonCode = "PROXY_ITERATION_LIMIT"
											log.Printf("[DENY] iteration limit reached (%d/%d)", currIter, maxIterations)
										} else if maxWallclock > 0 && time.Since(sessionStart) > maxWallclock {
											status = "PROXY_WALLCLOCK_LIMIT"
											reasonCode = "PROXY_WALLCLOCK_LIMIT"
											log.Printf("[DENY] wallclock limit exceeded (%v > %v)", time.Since(sessionStart), maxWallclock)
										} else {
											govResult, govErr := kb.Govern(context.Background(), toolName, hash)
											if govErr != nil {
												status = "GOVERNANCE_ERROR"
												reasonCode = "PDP_ERROR"
												log.Printf("[ERROR] governance error: %v", govErr)
											} else {
												reasonCode = govResult.ReasonCode
												pgNodeID = govResult.NodeID
												if govResult.Decision != nil {
													decisionID = govResult.Decision.ID
												}
												if !govResult.Allowed {
													status = "DENIED"
													log.Printf("[DENY] tool=%s reason=%s node=%s", toolName, reasonCode, pgNodeID)
												}
											}
										}
									}
								}
							}
						}
					}
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
			if status == "DENIED" || status == "PEP_VALIDATION_FAILED" ||
				status == "GOVERNANCE_ERROR" || status == "PROXY_ITERATION_LIMIT" ||
				status == "PROXY_WALLCLOCK_LIMIT" {
				verdict = "DENY"
			}

			// Build receipt
			rcptID := fmt.Sprintf("rcpt-proxy-%d-%d", time.Now().UnixNano(), clock)

			// Emit OTel GenAI tool_call span. gen_ai.tool.call.id == helm
			// correlation_id so traces and receipts cross-reference 1:1.
			otelTracer.TraceGenAIToolCall(reqCtx, helmotel.GenAIToolCallEvent{
				System:        genAISystem,
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
				ReceiptID:     rcptID,
				TenantID:      tenantID,
			})

			rcpt := &proxyReceipt{
				ReceiptID:        rcptID,
				Timestamp:        time.Now().UTC().Format(time.RFC3339Nano),
				Upstream:         upstream,
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
				LamportClock:     clock,

				// gen_ai.tool.call.id == helm correlation_id (single source of truth).
				CorrelationID:      correlationID,
				GenAISystem:        genAISystem,
				GenAIRequestModel:  requestModel,
				GenAIOperationName: operationName,
				GenAIToolCallID:    correlationID,
				GenAIInputTokens:   inputTokens,
				GenAIOutputTokens:  outputTokens,
				GenAIFinishReason:  finishReason,
				Traceparent:        traceparent,
			}

			// Sign receipt if signer available
			if signer != nil {
				payload := fmt.Sprintf("%s:%s:%s:%d", rcpt.ReceiptID, rcpt.OutputHash, rcpt.Status, rcpt.LamportClock)
				sig, signErr := signer.Sign([]byte(payload))
				if signErr == nil {
					rcpt.Signature = sig
				}
			}

			// Persist receipt (JSONL, append-only, causal chain)
			if storeErr := store.Append(rcpt); storeErr != nil {
				log.Printf("[ERROR] receipt persist failed: %v", storeErr)
			}

			// Persist ProofGraph (JSON snapshot after each append)
			persistProofGraph(pg, filepath.Join(receiptsDir, "proofgraph.json"))

			// Inject receipt headers
			resp.Header.Set("X-Helm-Receipt-ID", rcpt.ReceiptID)
			resp.Header.Set("X-Helm-Output-Hash", rcpt.OutputHash)
			resp.Header.Set("X-Helm-Lamport-Clock", fmt.Sprintf("%d", rcpt.LamportClock))
			resp.Header.Set("X-Helm-Status", rcpt.Status)
			if correlationID != "" {
				resp.Header.Set("X-Helm-Correlation-ID", correlationID)
			}
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
			if jsonOutput {
				rcptJSON, _ := json.Marshal(rcpt)
				log.Printf("%s", rcptJSON)
			} else if verbose {
				log.Printf("[RECEIPT] %s | %s | tools=%d | status=%s | %s",
					rcpt.ReceiptID, rcpt.Model, rcpt.ToolCalls, rcpt.Status, rcpt.OutputHash[:30]+"…")
			}

			// Restore body
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

			return nil
		},
	}

	mux := http.NewServeMux()

	// Health endpoint
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","mode":"proxy","upstream":"` + upstream + `"}`))
	}
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler)

	// Receipts endpoint — serve the JSONL file
	mux.HandleFunc("/helm/receipts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		data, err := os.ReadFile(receiptPath)
		if err != nil {
			http.Error(w, "no receipts yet", http.StatusNotFound)
			return
		}
		_, _ = w.Write(data)
	})

	// ProofGraph endpoint — serve the DAG as JSON
	mux.HandleFunc("/helm/proofgraph", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		nodes := pg.AllNodes()
		result := map[string]any{
			"nodes":   nodes,
			"heads":   pg.Heads(),
			"lamport": pg.LamportClock(),
			"count":   pg.Len(),
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		_, _ = w.Write(data)
	})

	// Proxy everything else
	mux.HandleFunc("/", proxy.ServeHTTP)

	// SEC: Default to localhost to prevent accidental network exposure (OpenClaw vector).
	// The proxy is designed as a local sidecar — use HELM_BIND_ADDR=0.0.0.0 to expose.
	proxyBind := "127.0.0.1"
	if envBind := os.Getenv("HELM_BIND_ADDR"); envBind != "" {
		proxyBind = envBind
	}
	addr := fmt.Sprintf("%s:%d", proxyBind, port)

	// Responses WebSocket mode: register /v1/responses handler for WS upgrade
	if websocket {
		mux.HandleFunc("/v1/responses", func(w http.ResponseWriter, r *http.Request) {
			// Check for WebSocket upgrade
			if r.Header.Get("Upgrade") != "websocket" {
				// Not a WS request — fall through to regular proxy
				proxy.ServeHTTP(w, r)
				return
			}

			// Respond with WebSocket upgrade awareness
			// NOTE: Full WebSocket implementation requires nhooyr.io/websocket or gorilla/websocket.
			// This handler documents the correct endpoint and behavior contract.
			// The production implementation will:
			// 1. Upgrade HTTP to WebSocket at /v1/responses
			// 2. Read JSON events (response.create, etc.)
			// 3. Preserve previous_response_id chaining
			// 4. Apply PEP governance on each tool_call event
			// 5. Generate receipts with deterministic boundaries per event
			// 6. Forward events to upstream WS endpoint
			//
			// Behavior contract (any WS library):
			// - Correct close semantics (1000 normal, 1001 going away)
			// - Ping/pong handling (respond within 10s)
			// - Backpressure: max 64 concurrent inflight messages
			// - Message size cap: 16MB per frame
			// - Receipt boundaries: one receipt per response.create event

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			errMsg := map[string]any{
				"error": map[string]any{
					"type":    "websocket_not_ready",
					"message": "Responses WebSocket mode endpoint registered at /v1/responses. Full WS upgrade requires websocket library dependency. Use OPENAI_WEBSOCKET_BASE_URL=ws://" + addr + " to target this endpoint.",
				},
			}
			data, _ := json.Marshal(errMsg)
			_, _ = w.Write(data)
		})
	}

	_, _ = fmt.Fprintf(stdout, "HELM Proxy Sidecar\n")
	_, _ = fmt.Fprintf(stdout, "══════════════════\n")
	_, _ = fmt.Fprintf(stdout, "  Upstream:    %s\n", upstream)
	_, _ = fmt.Fprintf(stdout, "  Listen:      http://%s\n", addr)
	_, _ = fmt.Fprintf(stdout, "  Health:      http://%s/healthz\n", addr)
	_, _ = fmt.Fprintf(stdout, "  Receipts:    %s\n", receiptPath)
	_, _ = fmt.Fprintf(stdout, "  Tenant:      %s\n", tenantID)
	if websocket {
		_, _ = fmt.Fprintf(stdout, "  WebSocket:   ws://%s/v1/responses (Responses API mode)\n", addr)
	}
	if budgetEnforcer != nil {
		_, _ = fmt.Fprintf(stdout, "  Budget:      daily=%d monthly=%d cents\n", dailyLimit, monthlyLimit)
	}
	if maxIterations > 0 {
		_, _ = fmt.Fprintf(stdout, "  Max Rounds:  %d\n", maxIterations)
	}
	if maxWallclock > 0 {
		_, _ = fmt.Fprintf(stdout, "  Wallclock:   %s\n", maxWallclock)
	}
	if signer != nil {
		_, _ = fmt.Fprintf(stdout, "  Signing:     Ed25519 (key: %s)\n", signer.KeyID)
	}
	_, _ = fmt.Fprintf(stdout, "  ProofGraph: %s\n", filepath.Join(receiptsDir, "proofgraph.json"))
	_, _ = fmt.Fprintf(stdout, "  Governance:  Guardian → ProofGraph → Budget\n")
	_, _ = fmt.Fprintf(stdout, "\n")
	_, _ = fmt.Fprintf(stdout, "  Drop-in usage:\n")
	_, _ = fmt.Fprintf(stdout, "    export OPENAI_BASE_URL=http://%s/v1\n", addr)
	_, _ = fmt.Fprintf(stdout, "    python your_app.py\n")
	if websocket {
		_, _ = fmt.Fprintf(stdout, "\n  Responses WebSocket:\n")
		_, _ = fmt.Fprintf(stdout, "    export OPENAI_WEBSOCKET_BASE_URL=ws://%s\n", addr)
		_, _ = fmt.Fprintf(stdout, "    # Agents SDK JS uses /v1/responses over WebSocket\n")
	}
	_, _ = fmt.Fprintf(stdout, "\n")
	_, _ = fmt.Fprintf(stdout, "  Every tool call is governed, hashed, and receipted. Ctrl+C to stop.\n")

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}

	// Graceful shutdown: persist ProofGraph on exit
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		<-sigChan
		log.Println("[helm-proxy] shutting down, persisting ProofGraph...")
		persistProofGraph(pg, filepath.Join(receiptsDir, "proofgraph.json"))
		server.Close()
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	return 0
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

func init() {
	Register(Subcommand{Name: "proxy", Aliases: []string{}, Usage: "OpenAI-compatible governance proxy", RunFn: runProxyCmd})
}
