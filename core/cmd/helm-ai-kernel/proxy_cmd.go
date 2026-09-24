// quantum_posture: the proxy signs governance receipts with the kernel's
// classical Ed25519 signer when --sign is enabled and hashes payloads with
// SHA-256; no post-quantum primitives are used in this file.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/bridge"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/correlation"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/manifest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	helmotel "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/otel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// proxyReceipt is the governance receipt attached to every proxied request.
//
// Fields in the gen_ai.* family follow the OTel GenAI semantic conventions
// (see core/pkg/observability/genai_attrs.go). gen_ai.tool.call.id mirrors
// the helm correlation_id so OTel traces and helm-ai-kernel receipts cross-reference 1:1.
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
	// SessionID keys the per-session iteration and wallclock limits.
	SessionID string `json:"session_id,omitempty"`

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
	mu          sync.Mutex
	file        *os.File
	prevHash    string
	lastLamport uint64
}

func newReceiptStore(path string) (*receiptStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	prevHash, lastLamport, err := recoverReceiptStoreState(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &receiptStore{file: f, prevHash: prevHash, lastLamport: lastLamport}, nil
}

func recoverReceiptStoreState(path string) (string, uint64, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return "GENESIS", 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	expectedPrevHash := "GENESIS"
	var lastLamport uint64
	reader := bufio.NewReader(f)
	for lineNo := 1; ; lineNo++ {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimRight(line, "\r\n")
			if len(bytes.TrimSpace(line)) == 0 {
				return "", 0, fmt.Errorf("receipt chain line %d is empty", lineNo)
			}
			var rcpt proxyReceipt
			if err := json.Unmarshal(line, &rcpt); err != nil {
				return "", 0, fmt.Errorf("receipt chain line %d is invalid JSON: %w", lineNo, err)
			}
			if rcpt.PrevHash != expectedPrevHash {
				return "", 0, fmt.Errorf("receipt chain line %d prev_hash %q does not match expected %q", lineNo, rcpt.PrevHash, expectedPrevHash)
			}
			if rcpt.LamportClock == 0 {
				return "", 0, fmt.Errorf("receipt chain line %d has zero lamport_clock", lineNo)
			}
			if lastLamport != 0 && rcpt.LamportClock != lastLamport+1 {
				return "", 0, fmt.Errorf("receipt chain line %d lamport_clock %d does not follow %d", lineNo, rcpt.LamportClock, lastLamport)
			}
			h := sha256.Sum256(line)
			expectedPrevHash = "sha256:" + hex.EncodeToString(h[:])
			lastLamport = rcpt.LamportClock
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", 0, fmt.Errorf("read receipt chain line %d: %w", lineNo, readErr)
		}
	}
	return expectedPrevHash, lastLamport, nil
}

// Append assigns the receipt's Lamport clock and chain link under the store
// lock, lets seal finish it (receipt id, signature) with those values, and
// writes it. Taking the clock here rather than in the request goroutine keeps
// the clock order and the file order identical under concurrent requests; a
// caller-assigned clock wedged the chain after one out-of-order completion
// (audit 03-01). A seal or write error leaves the chain where it was.
func (s *receiptStore) Append(rcpt *proxyReceipt, seal func(*proxyReceipt) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rcpt.LamportClock = s.lastLamport + 1
	rcpt.PrevHash = s.prevHash
	if seal != nil {
		if err := seal(rcpt); err != nil {
			return err
		}
	}

	data, err := json.Marshal(rcpt)
	if err != nil {
		return err
	}

	// Update causal chain: prevHash = SHA-256 of this receipt's JSON
	h := sha256.Sum256(data)
	nextPrevHash := "sha256:" + hex.EncodeToString(h[:])
	data = append(data, '\n')
	if _, err := s.file.Write(data); err != nil {
		return err
	}
	s.prevHash = nextPrevHash
	s.lastLamport = rcpt.LamportClock
	return nil
}

func (s *receiptStore) LastLamport() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastLamport
}

func (s *receiptStore) Close() error {
	return s.file.Close()
}

// proxyCtxKey is a unique context key type to stash per-request governance state
// from Director through to ModifyResponse without collisions with other packages.
type proxyCtxKey struct{ name string }

var (
	ctxKeyCorrelationID = proxyCtxKey{"correlation_id"}
	ctxKeyRequestInfo   = proxyCtxKey{"request_info"}
	ctxKeySessionID     = proxyCtxKey{"session_id"}
	ctxKeyTraceparent   = proxyCtxKey{"traceparent"}
)

// proxySessionHeader names the caller session that --max-iterations and
// --max-wallclock are counted against. It must be a canonical UUID; without a
// valid one the request's correlation ID is its session.
const proxySessionHeader = "X-Helm-Session-ID"

// proxyLocalCredential is the transport identity of an unauthenticated
// loopback sidecar, the proxy's analogue of `mcp serve --auth none`.
const proxyLocalCredential = "helm-proxy-local"

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
func extractGenAIUsage(body []byte) (inputTokens, outputTokens int64, usagePresent bool, finishReason string) {
	if len(body) == 0 {
		return 0, 0, false, ""
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		return 0, 0, false, ""
	}
	if usage, ok := top["usage"].(map[string]any); ok {
		usagePresent = true
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
	return inputTokens, outputTokens, usagePresent, finishReason
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

// proxyRequestInfo is what the proxy reads from a client request body before
// forwarding it.
type proxyRequestInfo struct {
	model string
	// stream is true when the body asks the upstream to stream its response.
	stream bool
	// toolsDeclared is true when the body offers the model tools, or when the
	// body is not a JSON object, so tools cannot be ruled out.
	toolsDeclared bool
}

func inspectProxyRequest(body []byte) proxyRequestInfo {
	info := proxyRequestInfo{model: extractRequestModel(body)}
	if len(bytes.TrimSpace(body)) == 0 {
		return info
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		info.toolsDeclared = true
		return info
	}
	info.stream, _ = top["stream"].(bool)
	info.toolsDeclared = declaresTools(top)
	// Bedrock InvokeModel embeds the provider body as a JSON-encoded string.
	if inner, ok := top["body"].(string); ok {
		var nested map[string]any
		if err := json.Unmarshal([]byte(inner), &nested); err != nil || declaresTools(nested) {
			info.toolsDeclared = true
		}
	}
	return info
}

// declaresTools reports whether a request body offers the model tools
// (`tools`, or the legacy OpenAI `functions`). A value that is present but not
// a list counts as declared.
func declaresTools(body map[string]any) bool {
	for _, key := range []string{"tools", "functions"} {
		value, ok := body[key]
		if !ok || value == nil {
			continue
		}
		if list, isList := value.([]any); !isList || len(list) > 0 {
			return true
		}
	}
	return false
}

// proxyToolCall is one tool call read from an OpenAI Chat Completions
// response. readable is false when its name or its string arguments are
// missing, so the call cannot be governed and must fail closed.
type proxyToolCall struct {
	name      string
	arguments string
	readable  bool
}

// extractChatToolCalls reads every tool call (tool_calls entries and the
// legacy function_call) from an OpenAI Chat Completions response. chatShape is
// false unless body is a JSON object with a choices array, the only response
// shape this proxy can govern.
func extractChatToolCalls(body []byte) (calls []proxyToolCall, model string, chatShape bool) {
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, "", false
	}
	model, _ = top["model"].(string)
	choices, ok := top["choices"].([]any)
	if !ok {
		return nil, model, false
	}
	for _, c := range choices {
		choice, _ := c.(map[string]any)
		msg, _ := choice["message"].(map[string]any)
		if raw, present := msg["tool_calls"]; present && raw != nil {
			entries, isList := raw.([]any)
			if !isList {
				calls = append(calls, proxyToolCall{})
			}
			for _, entry := range entries {
				tc, _ := entry.(map[string]any)
				fn, _ := tc["function"].(map[string]any)
				calls = append(calls, readProxyFunctionCall(fn))
			}
		}
		if raw, present := msg["function_call"]; present && raw != nil {
			fn, _ := raw.(map[string]any)
			calls = append(calls, readProxyFunctionCall(fn))
		}
	}
	return calls, model, true
}

func readProxyFunctionCall(fn map[string]any) proxyToolCall {
	name, _ := fn["name"].(string)
	arguments, isString := fn["arguments"].(string)
	return proxyToolCall{name: name, arguments: arguments, readable: name != "" && isString}
}

// maxProxySessions bounds the session table; client-chosen session IDs must
// not grow it without limit.
const maxProxySessions = 4096

// proxySessionLimits enforces --max-iterations and --max-wallclock per caller
// session instead of per process (audit 03-15). Sessions are named by the
// client, so these are loop guards for a cooperating agent, not an
// authorization boundary.
type proxySessionLimits struct {
	mu            sync.Mutex
	maxIterations int
	maxWallclock  time.Duration
	now           func() time.Time
	sessions      map[string]*proxySessionState
}

type proxySessionState struct {
	started    time.Time
	iterations int
}

func newProxySessionLimits(maxIterations int, maxWallclock time.Duration, now func() time.Time) *proxySessionLimits {
	return &proxySessionLimits{
		maxIterations: maxIterations,
		maxWallclock:  maxWallclock,
		now:           now,
		sessions:      make(map[string]*proxySessionState),
	}
}

// admit counts one governed tool call against sessionID and returns the limit
// status it trips, or "" when the call is within the session's limits. A
// session's wallclock starts at its first tool call.
func (l *proxySessionLimits) admit(sessionID string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	state, ok := l.sessions[sessionID]
	if !ok {
		if len(l.sessions) >= maxProxySessions {
			l.evictOldestLocked()
		}
		state = &proxySessionState{started: now}
		l.sessions[sessionID] = state
	}
	state.iterations++
	if l.maxIterations > 0 && state.iterations > l.maxIterations {
		return "PROXY_ITERATION_LIMIT"
	}
	if l.maxWallclock > 0 && now.Sub(state.started) > l.maxWallclock {
		return "PROXY_WALLCLOCK_LIMIT"
	}
	return ""
}

func (l *proxySessionLimits) evictOldestLocked() {
	var oldestID string
	var oldest time.Time
	for id, state := range l.sessions {
		if oldestID == "" || state.started.Before(oldest) {
			oldestID, oldest = id, state.started
		}
	}
	delete(l.sessions, oldestID)
}

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

// writeStreamingToolsRefusal answers a request that asks for a streamed
// response while offering tools. The proxy cannot parse a stream, so it cannot
// hold a streamed tool call for a decision; the request never reaches the
// upstream (audit 03-02).
func writeStreamingToolsRefusal(w http.ResponseWriter) {
	const reason = "PROXY_STREAMING_TOOLS_REFUSED"
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"message": `HELM proxy cannot govern tool calls in a streamed response; send requests that declare tools with "stream": false`,
			"type":    "helm_governance_denied",
			"code":    reason,
		},
		"helm": map[string]any{"status": "STREAMING_TOOLS_REFUSED", "reason_code": reason},
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Helm-Status", "STREAMING_TOOLS_REFUSED")
	w.Header().Set("X-Helm-Reason-Code", reason)
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(body)
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

// proxyConfig is the proxy's resolved configuration.
type proxyConfig struct {
	upstream      string
	apiKey        string
	jsonOutput    bool
	verbose       bool
	receiptsDir   string
	signKey       string
	tenantID      string
	policyGraph   *prg.Graph // nil: every tool call is denied
	maxIterations int
	maxWallclock  time.Duration
}

// proxyRuntime is a constructed proxy: the governed handler plus the state the
// sidecar's own endpoints and shutdown path read.
type proxyRuntime struct {
	handler     http.Handler
	upstream    string
	receiptPath string
	store       *receiptStore
	pg          *proofgraph.Graph
	signer      *helmcrypto.Ed25519Signer // nil unless --sign
	close       func()
}

// newProxyRuntime wires the receipt store, signer, Guardian bridge and the
// governed reverse proxy. runProxyCmd and the tests both build the proxy here,
// so the tests exercise the shipped wiring rather than a copy of it.
func newProxyRuntime(cfg proxyConfig, stderr io.Writer) (*proxyRuntime, error) {
	upstream := cfg.upstream
	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}
	tenantID := cfg.tenantID
	receiptsDir := cfg.receiptsDir

	// Initialize receipt store
	receiptPath := filepath.Join(receiptsDir, fmt.Sprintf("receipts-%s.jsonl", time.Now().Format("2006-01-02")))
	store, err := newReceiptStore(receiptPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize receipt store at %s: %w", receiptPath, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = store.Close()
		}
	}()

	// Ed25519 signer (used for both receipts and KernelBridge governance).
	//
	// --sign is documented as a signing seed. It previously became the signer's
	// key *id* while the actual keypair was generated at random, so receipts
	// were unverifiable after a restart and the seed was published in every
	// receipt's KeyID field (F-01).
	var kernelSigner *helmcrypto.Ed25519Signer
	if cfg.signKey != "" {
		var derivedFromPassphrase bool
		kernelSigner, derivedFromPassphrase, err = helmcrypto.NewEd25519SignerFromSecret(cfg.signKey, "helm-proxy")
		if err != nil {
			return nil, fmt.Errorf("failed to create kernel signer: %w", err)
		}
		if derivedFromPassphrase {
			_, _ = fmt.Fprintln(stderr,
				"Warning: --sign is not a 32-byte hex/base64 seed; deriving one by hashing it. "+
					"Supply a generated seed so receipts stay verifiable and the key is not guessable.")
		}
	} else {
		// No seed supplied: ephemeral identity. Receipts signed by it cannot be
		// verified once this process exits. Fails closed under HELM_PRODUCTION.
		kernelSigner, err = helmcrypto.NewEd25519Signer("helm-proxy")
		if err != nil {
			return nil, fmt.Errorf("failed to create kernel signer: %w", err)
		}
	}

	// Optional: separate receipt signer (same key for now)
	var signer *helmcrypto.Ed25519Signer
	if cfg.signKey != "" {
		signer = kernelSigner
	}

	// Initialize KernelBridge: Guardian + ProofGraph. The proxy passes no budget
	// enforcer: it cannot price a tool call (see runProxyCmd).
	prgGraph := cfg.policyGraph
	if prgGraph == nil {
		prgGraph = prg.NewGraph()
	}
	artStore, artErr := artifacts.NewFileStore(filepath.Join(receiptsDir, "artifacts"))
	if artErr != nil {
		return nil, fmt.Errorf("failed to create artifact store: %w", artErr)
	}
	artRegistry := artifacts.NewRegistry(artStore, kernelSigner)
	g, guardianErr := newProductionGuardian(kernelSigner, prgGraph, artRegistry, utcRuntimeClock{})
	if guardianErr != nil {
		return nil, fmt.Errorf("failed to initialize production Guardian: %w", guardianErr)
	}
	pg := proofgraph.NewGraph()
	kb := bridge.NewKernelBridge(g, prgGraph, pg, nil, tenantID)
	limits := newProxySessionLimits(cfg.maxIterations, cfg.maxWallclock, time.Now)
	proofPath := filepath.Join(receiptsDir, "proofgraph.json")

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
		} else {
			log.Printf("[WARN] OTLP exporter setup failed, falling back to noop: %v", otelErr)
		}
	}

	genAISystem := inferGenAISystem(upstreamURL)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// helm correlation_id — also used as gen_ai.tool.call.id so OTel traces
			// and helm-ai-kernel receipts cross-reference 1:1.
			// Adopt-or-mint (telemetry contract §2.2): a valid inbound
			// X-Helm-Correlation-ID is honoured so a caller can thread one
			// product identity through the whole request path; anything
			// else is replaced with a freshly minted ID.
			corr, _ := tracing.AdoptOrMintFromHeaders(req.Header)
			ctx := tracing.WithCorrelationID(req.Context(), corr)
			ctx = context.WithValue(ctx, ctxKeyCorrelationID, string(corr))
			sessionID := strings.TrimSpace(req.Header.Get(proxySessionHeader))
			if !correlation.IsValid(sessionID) {
				sessionID = string(corr)
			}
			ctx = context.WithValue(ctx, ctxKeySessionID, sessionID)

			// Stamp the product identity onto the edge server span so OTel
			// traces and receipts join 1:1 (HELM-333); same attribute the
			// governance tracer uses.
			oteltrace.SpanFromContext(ctx).SetAttributes(
				attribute.String(observability.HelmCorrelationID, string(corr)))

			// Inject W3C traceparent so the upstream provider's traces (if any)
			// link back into our governance trace tree. InjectHTTPHeaders also
			// sets the advisory X-Helm-Correlation-ID for upstreams that echo it.
			helmotel.InjectTraceparent(ctx, req.Header)
			tracing.InjectHTTPHeaders(ctx, req.Header)
			ctx = context.WithValue(ctx, ctxKeyTraceparent, req.Header.Get("traceparent"))

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

			// Let the transport negotiate compression itself so it decodes the
			// response before governance reads it. A client-chosen encoding would
			// reach ModifyResponse compressed, where no tool call can be parsed.
			req.Header.Del("Accept-Encoding")

			// Forward API key
			if cfg.apiKey != "" && req.Header.Get("Authorization") == "" {
				req.Header.Set("Authorization", "Bearer "+cfg.apiKey)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
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
					"upstream": upstream,
					"status":   "STREAM_PASSTHROUGH_NO_TOOLS",
				})
				_, _ = pg.Append(proofgraph.NodeTypeEffect, passMsg, "helm-proxy", 0)
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

				if limit := limits.admit(sessionID); limit != "" {
					status = limit
					reasonCode = limit
					log.Printf("[DENY] tool=%s session=%s %s", call.name, sessionID, limit)
					continue
				}

				// KernelBridge governance. The binding carries the transport
				// identity the Guardian's isolation gate requires; without it
				// every tool call was denied before policy ran (audit 07-01).
				govResult, govErr := kb.GovernBound(context.Background(), call.name, hash, nil, bridge.Binding{
					CredentialHash: credentialHash,
					SessionID:      sessionID,
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

				// gen_ai.tool.call.id == helm correlation_id (single source of truth).
				CorrelationID:      correlationID,
				SessionID:          sessionID,
				GenAISystem:        genAISystem,
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
			if storeErr := store.Append(rcpt, func(r *proxyReceipt) error {
				r.ReceiptID = fmt.Sprintf("rcpt-proxy-%d-%d", time.Now().UnixNano(), r.LamportClock)
				if signer == nil {
					return nil
				}
				payload := fmt.Sprintf("%s:%s:%s:%d", r.ReceiptID, r.OutputHash, r.Status, r.LamportClock)
				sig, signErr := signer.Sign([]byte(payload))
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
				ReceiptID:     rcpt.ReceiptID,
				TenantID:      tenantID,
			})

			// Persist ProofGraph (JSON snapshot after each append)
			persistProofGraph(pg, proofPath)

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
			if cfg.jsonOutput {
				rcptJSON, _ := json.Marshal(rcpt)
				log.Printf("%s", rcptJSON)
			} else if cfg.verbose {
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

	// The governed entry point reads the request once, refuses a streamed
	// request that offers tools before it reaches the upstream, and records the
	// transport identity the Guardian binds decisions to.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Body != nil {
			b, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				http.Error(w, "failed to read request body", http.StatusBadRequest)
				return
			}
			body = b
			r.Body = io.NopCloser(bytes.NewReader(b))
			r.ContentLength = int64(len(b))
		}
		info := inspectProxyRequest(body)
		if info.stream && info.toolsDeclared {
			slog.WarnContext(r.Context(), "proxy refused a streamed request that offers tools before the upstream call",
				"reason_code", "PROXY_STREAMING_TOOLS_REFUSED")
			writeStreamingToolsRefusal(w)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyRequestInfo, info)
		if _, authenticated := helmauth.AuthenticatedCredentialHash(ctx); !authenticated {
			ctx = helmauth.WithAuthenticatedCredential(ctx, proxyLocalCredential)
		}
		proxy.ServeHTTP(w, r.WithContext(ctx))
	})

	ok = true
	return &proxyRuntime{
		handler:     handler,
		upstream:    upstream,
		receiptPath: receiptPath,
		store:       store,
		pg:          pg,
		signer:      signer,
		close: func() {
			_ = otelTracer.Shutdown(context.Background())
			_ = store.Close()
		},
	}, nil
}

// runProxyCmd implements `helm-ai-kernel proxy`.
//
// Usage:
//
//	helm-ai-kernel proxy --upstream https://api.openai.com/v1 --port 9090 --policy ./helm.toml
//
// Then:
//
//	export OPENAI_BASE_URL=http://localhost:9090/v1
//	python your_app.py  # Every tool call now gets a verdict and a receipt.
//
// Features:
//   - Receipt persistence: JSONL audit log at --receipts-dir
//   - PEP validation: tool_call arguments validated as JSON, canonicalized (JCS), and SHA-256 hashed
//   - Policy: tool calls are decided by the Guardian against --policy; without it every tool call is denied
//   - Streaming: a request that offers tools must not stream; the proxy cannot parse a stream
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
		policyPath    string
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
	cmd.StringVar(&tenantID, "tenant-id", "default", "Tenant identifier recorded as the governing principal")
	cmd.StringVar(&policyPath, "policy", "", "Path to a serve policy file; without it every tool call is denied (fail-closed)")
	cmd.Int64Var(&dailyLimit, "daily-limit", 0, "Unsupported: the proxy has no monetary price for a tool call, so a non-zero budget is refused")
	cmd.Int64Var(&monthlyLimit, "monthly-limit", 0, "Unsupported: the proxy has no monetary price for a tool call, so a non-zero budget is refused")
	cmd.IntVar(&maxIterations, "max-iterations", 10, "Max tool calls per session (X-Helm-Session-ID) (0=unlimited)")
	cmd.DurationVar(&maxWallclock, "max-wallclock", 120*time.Second, "Max session duration from its first tool call (0=unlimited)")
	cmd.BoolVar(&websocket, "websocket", false, "Request Responses WebSocket mode (unsupported in OSS runtime)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if websocket {
		_, _ = fmt.Fprintln(stderr, "Error: --websocket is not supported in the OSS proxy runtime")
		_, _ = fmt.Fprintln(stderr, "Use the HTTP proxy surface at /v1/chat/completions until Responses WebSocket support is implemented.")
		return 2
	}
	// The budget gate charges cents, and the proxy only ever sees token counts.
	// A configured budget therefore denied every tool call with BUDGET_ERROR
	// before policy was consulted (audit 07-01); refuse it instead.
	if dailyLimit != 0 || monthlyLimit != 0 {
		_, _ = fmt.Fprintln(stderr, "Error: --daily-limit and --monthly-limit are not supported by the proxy: it sees token counts, not prices, so a budget would deny every tool call with BUDGET_ERROR")
		return 2
	}
	if helmcrypto.ProductionMode() {
		_, _ = fmt.Fprintln(stderr, "Error: helm proxy is disabled under HELM_PRODUCTION: request, response, and SSE payloads do not have verified inline personal-data inspection")
		return 2
	}

	// A serve policy compiles to the Guardian rule graph. Absent --policy the
	// graph stays empty, which denies every tool call (fail-closed default).
	var policyGraph *prg.Graph
	if policyPath != "" {
		runtimePolicy, err := loadServePolicyRuntime(policyPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: load serve policy %q: %v\n", policyPath, err)
			return 2
		}
		policyGraph = runtimePolicy.Graph
		if authorized := len(runtimePolicy.AllowMap()); authorized == 0 {
			_, _ = fmt.Fprintf(stderr, "Warning: serve policy %q authorizes 0 actions; every tool call will be denied\n", policyPath)
		} else {
			_, _ = fmt.Fprintf(stderr, "Serve policy %q authorizes %d action(s)\n", policyPath, authorized)
		}
	}

	rt, err := newProxyRuntime(proxyConfig{
		upstream:      strings.TrimSuffix(upstream, "/"),
		apiKey:        apiKey,
		jsonOutput:    jsonOutput,
		verbose:       verbose,
		receiptsDir:   receiptsDir,
		signKey:       signKey,
		tenantID:      tenantID,
		policyGraph:   policyGraph,
		maxIterations: maxIterations,
		maxWallclock:  maxWallclock,
	}, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	defer rt.close()
	upstream = rt.upstream
	receiptPath := rt.receiptPath
	pg := rt.pg
	signer := rt.signer

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
	mux.Handle("/", rt.handler)

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
				rt.handler.ServeHTTP(w, r)
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
	if policyPath != "" {
		_, _ = fmt.Fprintf(stdout, "  Policy:      %s\n", policyPath)
	} else {
		_, _ = fmt.Fprintf(stdout, "  Policy:      none (every tool call is denied)\n")
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
	_, _ = fmt.Fprintf(stdout, "  Governance:  Guardian → ProofGraph\n")
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
	_, _ = fmt.Fprintf(stdout, "  Tool calls are governed, hashed, and receipted; a request that offers tools\n")
	_, _ = fmt.Fprintf(stdout, "  must not stream, and a response the proxy cannot parse is withheld. Ctrl+C to stop.\n")

	server := &http.Server{
		Addr: addr,
		// The proxy is an external ingress edge: run every request inside an
		// otelhttp server span so an inbound W3C traceparent is continued
		// (HELM-333) before governance and upstream forwarding run.
		Handler:           tracing.WrapEdgeHandler(mux, "helm.proxy"),
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
