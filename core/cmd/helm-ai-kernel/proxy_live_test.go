//go:build live
// +build live

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLiveProxyChildProcess(t *testing.T) {
	if os.Getenv("HELM_PROXY_LIVE_CHILD") != "1" {
		t.Skip("child process helper only")
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("HELM_PROXY_LIVE_ARGS")), &args); err != nil {
		t.Fatalf("decode proxy args: %v", err)
	}
	if code := runProxyCmd(args, os.Stdout, os.Stderr); code != 0 {
		t.Fatalf("proxy exited with code %d", code)
	}
}

func TestLiveProxySmoke(t *testing.T) {
	if os.Getenv("HELM_LIVE_PROXY") != "1" {
		t.Skip("set HELM_LIVE_PROXY=1 to run live proxy smoke")
	}

	upstream := requiredEnv(t, "HELM_LIVE_PROXY_UPSTREAM")
	apiKey := requiredEnv(t, "HELM_LIVE_PROXY_API_KEY")
	model := requiredEnv(t, "HELM_LIVE_PROXY_MODEL")
	maxCostCents := requiredFloatEnv(t, "HELM_LIVE_PROXY_MAX_COST_CENTS")
	centsPer1KTokens := requiredFloatEnv(t, "HELM_LIVE_PROXY_CENTS_PER_1K_TOKENS")

	liveProxy := startLiveProxy(t, upstream, apiKey, "live-proxy-smoke")
	liveResp := postChatCompletion(t, liveProxy.baseURL, model, "Reply with exactly: HELM live smoke ok")
	if liveResp.statusCode != http.StatusOK {
		t.Fatalf("live proxy response status = %d", liveResp.statusCode)
	}
	assertReceiptHeaders(t, liveResp.headers, "APPROVED")

	liveReceipt := readLatestProxyReceipt(t, liveProxy.receiptsDir)
	if liveReceipt.ReceiptID != liveResp.headers.Get("X-Helm-Receipt-ID") {
		t.Fatalf("receipt id mismatch: file=%s header=%s", liveReceipt.ReceiptID, liveResp.headers.Get("X-Helm-Receipt-ID"))
	}
	if liveReceipt.CorrelationID == "" || liveReceipt.GenAIToolCallID == "" {
		t.Fatalf("live receipt missing correlation metadata: %+v", liveReceipt)
	}
	if liveReceipt.Status != "APPROVED" {
		t.Fatalf("live receipt status = %s", liveReceipt.Status)
	}

	totalTokens := liveResp.usage.totalTokens()
	if totalTokens <= 0 {
		t.Fatal("live response did not include token usage; cannot enforce explicit cost cap")
	}
	estimatedCostCents := (float64(totalTokens) / 1000.0) * centsPer1KTokens
	if estimatedCostCents > maxCostCents {
		t.Fatalf("estimated live request cost %.6f cents exceeds cap %.6f cents", estimatedCostCents, maxCostCents)
	}

	denyResult := runLocalDenyTamperProof(t)
	artifactPath := writeRedactedLiveProxyArtifact(t, redactedLiveProxyArtifact{
		SchemaVersion: "helm.live_proxy_smoke.v1",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		UpstreamHost:  hostOnly(upstream),
		Model:         model,
		LiveRequest: redactedLiveRequest{
			HTTPStatus:         liveResp.statusCode,
			ReceiptID:          liveReceipt.ReceiptID,
			OutputHash:         liveReceipt.OutputHash,
			HELMStatus:         liveReceipt.Status,
			CorrelationID:      liveReceipt.CorrelationID,
			LamportClock:       liveReceipt.LamportClock,
			PromptTokens:       liveResp.usage.PromptTokens,
			CompletionTokens:   liveResp.usage.CompletionTokens,
			TotalTokens:        totalTokens,
			EstimatedCostCents: estimatedCostCents,
			MaxCostCents:       maxCostCents,
			SignaturePresent:   liveReceipt.Signature != "",
		},
		DenyTamperProof: denyResult,
	})
	t.Logf("wrote redacted live proxy smoke artifact: %s", artifactPath)
}

type liveProxyProcess struct {
	baseURL     string
	receiptsDir string
}

func startLiveProxy(t *testing.T, upstream string, apiKey string, tenantID string) liveProxyProcess {
	t.Helper()

	port := freeTCPPort(t)
	receiptsDir := t.TempDir()
	args := []string{
		"--upstream", upstream,
		"--port", strconv.Itoa(port),
		"--api-key", apiKey,
		"--tenant-id", tenantID,
		"--daily-limit", "1",
		"--monthly-limit", "1",
		"--max-wallclock", "30s",
		"--receipts-dir", receiptsDir,
		"--sign", tenantID,
	}
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal proxy args: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestLiveProxyChildProcess")
	cmd.Env = append(os.Environ(),
		"HELM_PROXY_LIVE_CHILD=1",
		"HELM_PROXY_LIVE_ARGS="+string(argsJSON),
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start proxy child: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(20 * time.Second)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("proxy child exited before health check: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		default:
		}
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return liveProxyProcess{baseURL: baseURL, receiptsDir: receiptsDir}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("proxy child did not become healthy\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	return liveProxyProcess{}
}

type chatResponse struct {
	statusCode int
	headers    http.Header
	usage      tokenUsage
}

type tokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

func (u tokenUsage) totalTokens() int {
	if u.TotalTokens > 0 {
		return u.TotalTokens
	}
	return u.PromptTokens + u.CompletionTokens
}

func postChatCompletion(t *testing.T, baseURL string, model string, prompt string) chatResponse {
	t.Helper()

	body := map[string]any{
		"model":       model,
		"messages":    []map[string]string{{"role": "user", "content": prompt}},
		"max_tokens":  16,
		"temperature": 0,
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/chat/completions", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post through proxy: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	var parsed struct {
		Usage tokenUsage `json:"usage"`
	}
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatalf("decode successful response metadata: %v", err)
		}
	}
	return chatResponse{statusCode: resp.StatusCode, headers: resp.Header.Clone(), usage: parsed.Usage}
}

func runLocalDenyTamperProof(t *testing.T) redactedDenyTamperProof {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-helm-local-deny-fixture",
			"object":  "chat.completion",
			"created": 1778587200,
			"model":   "helm-local-tool-fixture",
			"choices": []map[string]any{{
				"index":         0,
				"finish_reason": "tool_calls",
				"message": map[string]any{
					"role": "assistant",
					"tool_calls": []map[string]any{{
						"id":   "call_helm_denied",
						"type": "function",
						"function": map[string]any{
							"name":      "credential_export",
							"arguments": `{"path":"/etc/passwd"}`,
						},
					}},
				},
			}},
			"usage": map[string]int{
				"prompt_tokens":     1,
				"completion_tokens": 1,
				"total_tokens":      2,
			},
		})
	}))
	defer upstream.Close()

	proxy := startLiveProxy(t, upstream.URL+"/v1", "fixture-key", "live-proxy-deny-fixture")
	reqBody := []byte(`{"model":"helm-local-tool-fixture","messages":[{"role":"user","content":"call a denied tool"}]}`)
	req, err := http.NewRequest(http.MethodPost, proxy.baseURL+"/v1/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("build deny request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("post deny fixture through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read deny response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("deny fixture status = %d", resp.StatusCode)
	}
	if bytes.Contains(body, []byte("tool_calls")) {
		t.Fatalf("denied response leaked executable tool_calls: %s", string(body))
	}
	assertReceiptHeaders(t, resp.Header, "DENIED")

	receipt := readLatestProxyReceipt(t, proxy.receiptsDir)
	if receipt.CorrelationID != resp.Header.Get("X-Helm-Correlation-ID") {
		t.Fatalf("correlation id mismatch: receipt=%s header=%s", receipt.CorrelationID, resp.Header.Get("X-Helm-Correlation-ID"))
	}
	if receipt.Status != "DENIED" {
		t.Fatalf("deny receipt status = %s", receipt.Status)
	}
	if receipt.ReasonCode == "" || receipt.ToolCalls != 1 {
		t.Fatalf("deny receipt missing reason/tool metadata: %+v", receipt)
	}

	originalHash := hashProxyReceipt(t, receipt)
	originalSignaturePayload := proxyReceiptSignaturePayload(receipt)
	tampered := receipt
	tampered.Status = "APPROVED"
	tamperedHash := hashProxyReceipt(t, tampered)
	tamperedSignaturePayload := proxyReceiptSignaturePayload(tampered)
	if originalHash == tamperedHash {
		t.Fatal("tampered receipt hash did not change")
	}
	if originalSignaturePayload == tamperedSignaturePayload {
		t.Fatal("tampered receipt signature payload did not change")
	}

	return redactedDenyTamperProof{
		HTTPStatus:                    resp.StatusCode,
		ReceiptID:                     receipt.ReceiptID,
		OutputHash:                    receipt.OutputHash,
		HELMStatus:                    receipt.Status,
		ReasonCode:                    receipt.ReasonCode,
		ToolCalls:                     receipt.ToolCalls,
		ExecutableToolCallsRedacted:   !bytes.Contains(body, []byte("tool_calls")),
		OriginalReceiptHash:           originalHash,
		TamperedReceiptHash:           tamperedHash,
		SignaturePayloadChanged:       originalSignaturePayload != tamperedSignaturePayload,
		SignaturePresent:              receipt.Signature != "",
		ReceiptHashChangedAfterTamper: originalHash != tamperedHash,
	}
}

func TestLiveProxyEchoesMintedCorrelationIDForSSE(t *testing.T) {
	// Handler goroutine → test goroutine handoff; a plain shared variable
	// here is a data race under -race.
	upstreamCorrelationIDs := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		select {
		case upstreamCorrelationIDs <- r.Header.Get("X-Helm-Correlation-ID"):
		default:
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-sse\"}\n\n"))
	}))
	defer upstream.Close()

	proxy := startLiveProxy(t, upstream.URL+"/v1", "fixture-key", "live-proxy-sse-fixture")
	req, err := http.NewRequest(http.MethodPost, proxy.baseURL+"/v1/chat/completions", strings.NewReader(`{"model":"helm-local-sse-fixture","stream":true}`))
	if err != nil {
		t.Fatalf("build SSE request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Helm-Correlation-ID", "not-a-canonical-uuid")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("post SSE fixture through proxy: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read SSE response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SSE fixture status = %d", resp.StatusCode)
	}
	correlationID := resp.Header.Get("X-Helm-Correlation-ID")
	if correlationID == "" || correlationID == "not-a-canonical-uuid" {
		t.Fatalf("SSE response did not echo a minted correlation id: %q", correlationID)
	}
	var upstreamCorrelationID string
	select {
	case upstreamCorrelationID = <-upstreamCorrelationIDs:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the chat completion request")
	}
	if correlationID != upstreamCorrelationID {
		t.Fatalf("SSE correlation id mismatch: response=%s upstream=%s", correlationID, upstreamCorrelationID)
	}
}

func assertReceiptHeaders(t *testing.T, headers http.Header, expectedStatus string) {
	t.Helper()
	required := []string{
		"X-Helm-Receipt-ID",
		"X-Helm-Output-Hash",
		"X-Helm-Lamport-Clock",
		"X-Helm-Status",
		"X-Helm-Correlation-ID",
	}
	for _, name := range required {
		if headers.Get(name) == "" {
			t.Fatalf("missing receipt header %s", name)
		}
	}
	if headers.Get("X-Helm-Status") != expectedStatus {
		t.Fatalf("X-Helm-Status = %s, want %s", headers.Get("X-Helm-Status"), expectedStatus)
	}
}

func readLatestProxyReceipt(t *testing.T, receiptsDir string) proxyReceipt {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(receiptsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasPrefix(filepath.Base(path), "receipts-") && strings.HasSuffix(path, ".jsonl") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk receipts dir: %v", err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("no receipt JSONL files under %s", receiptsDir)
	}
	data, err := os.ReadFile(paths[len(paths)-1])
	if err != nil {
		t.Fatalf("read receipt file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || lines[len(lines)-1] == "" {
		t.Fatalf("receipt file %s is empty", paths[len(paths)-1])
	}
	var receipt proxyReceipt
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &receipt); err != nil {
		t.Fatalf("decode receipt JSONL: %v", err)
	}
	return receipt
}

func hashProxyReceipt(t *testing.T, receipt proxyReceipt) string {
	t.Helper()
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func proxyReceiptSignaturePayload(receipt proxyReceipt) string {
	return fmt.Sprintf("%s:%s:%s:%d", receipt.ReceiptID, receipt.OutputHash, receipt.Status, receipt.LamportClock)
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func requiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required when HELM_LIVE_PROXY=1", name)
	}
	return value
}

func requiredFloatEnv(t *testing.T, name string) float64 {
	t.Helper()
	value := requiredEnv(t, name)
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed <= 0 {
		t.Fatalf("%s must be a positive number, got %q", name, value)
	}
	return parsed
}

func hostOnly(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "unparseable"
	}
	return parsed.Host
}

type redactedLiveProxyArtifact struct {
	SchemaVersion    string                  `json:"schema_version"`
	GeneratedAt      string                  `json:"generated_at"`
	UpstreamHost     string                  `json:"upstream_host"`
	Model            string                  `json:"model"`
	LiveRequest      redactedLiveRequest     `json:"live_request"`
	DenyTamperProof  redactedDenyTamperProof `json:"deny_tamper_proof"`
	RedactionSummary []string                `json:"redaction_summary"`
}

type redactedLiveRequest struct {
	HTTPStatus         int     `json:"http_status"`
	ReceiptID          string  `json:"receipt_id"`
	OutputHash         string  `json:"output_hash"`
	HELMStatus         string  `json:"helm_status"`
	CorrelationID      string  `json:"correlation_id"`
	LamportClock       uint64  `json:"lamport_clock"`
	PromptTokens       int     `json:"prompt_tokens"`
	CompletionTokens   int     `json:"completion_tokens"`
	TotalTokens        int     `json:"total_tokens"`
	EstimatedCostCents float64 `json:"estimated_cost_cents"`
	MaxCostCents       float64 `json:"max_cost_cents"`
	SignaturePresent   bool    `json:"signature_present"`
}

type redactedDenyTamperProof struct {
	HTTPStatus                    int    `json:"http_status"`
	ReceiptID                     string `json:"receipt_id"`
	OutputHash                    string `json:"output_hash"`
	HELMStatus                    string `json:"helm_status"`
	ReasonCode                    string `json:"reason_code"`
	ToolCalls                     int    `json:"tool_calls"`
	ExecutableToolCallsRedacted   bool   `json:"executable_tool_calls_redacted"`
	OriginalReceiptHash           string `json:"original_receipt_hash"`
	TamperedReceiptHash           string `json:"tampered_receipt_hash"`
	SignaturePayloadChanged       bool   `json:"signature_payload_changed"`
	SignaturePresent              bool   `json:"signature_present"`
	ReceiptHashChangedAfterTamper bool   `json:"receipt_hash_changed_after_tamper"`
}

func writeRedactedLiveProxyArtifact(t *testing.T, artifact redactedLiveProxyArtifact) string {
	t.Helper()
	artifact.RedactionSummary = []string{
		"no authorization headers",
		"no provider API keys",
		"no raw prompts",
		"no raw completions",
		"no raw receipt signatures",
	}
	data, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatalf("marshal redacted artifact: %v", err)
	}
	f, err := os.CreateTemp("", "helm-live-proxy-smoke-*.json")
	if err != nil {
		t.Fatalf("create artifact: %v", err)
	}
	path := f.Name()
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		t.Fatalf("write artifact: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close artifact: %v", err)
	}
	return path
}
