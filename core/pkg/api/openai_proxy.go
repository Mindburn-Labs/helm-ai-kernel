// Package api provides the OpenAI-compatible proxy endpoint for HELM. The
// served route applies its PEP boundary before this handler forwards requests
// with a server-owned upstream provider credential.
package api

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// OpenAIProxyConfig configures the OpenAI-compatible proxy.
type OpenAIProxyConfig struct {
	UpstreamURL  string `json:"upstream_url"`
	DefaultModel string `json:"default_model"`
}

// OpenAIMessage represents a message in the OpenAI chat format.
type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIChatRequest is the OpenAI-compatible request format.
// API-001/002: Includes tool_choice, parallel_tool_calls, and response_format
// for upstream provider pass-through.
type OpenAIChatRequest struct {
	Model             string          `json:"model"`
	Messages          []OpenAIMessage `json:"messages"`
	Stream            bool            `json:"stream,omitempty"`
	ToolChoice        any             `json:"tool_choice,omitempty"`         // API-001: "auto", "none", "required", or {"type":"function","function":{"name":"..."}}
	ParallelToolCalls *bool           `json:"parallel_tool_calls,omitempty"` // API-001: Enable/disable parallel tool execution
	ResponseFormat    any             `json:"response_format,omitempty"`     // API-002: {"type":"json_object"} or {"type":"json_schema","json_schema":{...}}
	MaxTokens         *int            `json:"max_tokens,omitempty"`
	Temperature       *float64        `json:"temperature,omitempty"`
	TopP              *float64        `json:"top_p,omitempty"`
}

// OpenAIChatResponse is the OpenAI-compatible response format.
type OpenAIChatResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int           `json:"index"`
		Message      OpenAIMessage `json:"message"`
		FinishReason string        `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// HandleOpenAIProxy is the handler for /v1/chat/completions in server mode.
//
// Governance behavior:
//   - If HELM_UPSTREAM_URL and HELM_UPSTREAM_API_KEY are set: proxies to the
//     upstream LLM with full governance (validates requests, enforces policy,
//     generates receipts). The upstream key is server-owned and is never
//     derived from the caller's runtime authorization header.
//   - If either setting is absent: returns a configuration error without
//     forwarding the request.
//
// For CLI-based governance with interactive upstream forwarding, use:
//
//	helm-ai-kernel proxy --upstream <url>
//
// maxOpenAIRequestSize is the maximum allowed request body size (10 MiB).
const (
	maxOpenAIRequestSize  = 10 << 20
	upstreamURLEnv        = "HELM_UPSTREAM_URL"
	upstreamAPIKeyEnv     = "HELM_UPSTREAM_API_KEY"
	runtimeAdminAPIKeyEnv = "HELM_ADMIN_API_KEY"
)

func HandleOpenAIProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteMethodNotAllowed(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxOpenAIRequestSize)
	var req OpenAIChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteBadRequest(w, "Invalid request body")
		return
	}

	if req.Model == "" {
		req.Model = "gpt-4"
	}

	upstreamURL := strings.TrimSpace(os.Getenv(upstreamURLEnv))
	if upstreamURL == "" {
		// No upstream configured — return error with instructions
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "HELM server mode requires HELM_UPSTREAM_URL to be set. " +
					"Set this to your LLM API endpoint (e.g., https://api.openai.com). " +
					"Alternatively, use: helm-ai-kernel proxy --upstream <url>",
				"type": "helm_configuration_error",
				"code": "upstream_not_configured",
			},
		})
		return
	}
	upstreamAPIKey := strings.TrimSpace(os.Getenv(upstreamAPIKeyEnv))
	if upstreamAPIKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "HELM server mode requires HELM_UPSTREAM_API_KEY to be set for its configured upstream. " +
					"This server-owned provider credential is distinct from HELM_ADMIN_API_KEY.",
				"type": "helm_configuration_error",
				"code": "upstream_credentials_not_configured",
			},
		})
		return
	}
	if credentialsEqual(upstreamAPIKey, strings.TrimSpace(os.Getenv(runtimeAdminAPIKeyEnv))) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "HELM_UPSTREAM_API_KEY must be distinct from HELM_ADMIN_API_KEY.",
				"type":    "helm_configuration_error",
				"code":    "upstream_credentials_not_distinct",
			},
		})
		return
	}

	// Forward to upstream with governance
	upstreamReq, err := json.Marshal(req)
	if err != nil {
		WriteBadRequest(w, fmt.Sprintf("Failed to marshal request: %v", err))
		return
	}

	// Create an upstream request using only server-owned provider credentials.
	// The caller's Authorization header is consumed by the runtime boundary and
	// must never be sent to a third-party model provider.
	proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		openAICompletionsURL(upstreamURL), bytes.NewReader(upstreamReq))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": fmt.Sprintf("Failed to create upstream request: %v", err),
				"type":    "helm_proxy_error",
			},
		})
		return
	}

	proxyReq.Header.Set("Authorization", "Bearer "+upstreamAPIKey)
	proxyReq.Header.Set("Content-Type", "application/json")

	// Execute upstream request
	client := &http.Client{Timeout: 120 * time.Second}
	upstreamResp, err := client.Do(proxyReq)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": fmt.Sprintf("Upstream request failed: %v", err),
				"type":    "helm_upstream_error",
			},
		})
		return
	}
	defer upstreamResp.Body.Close()

	// Read upstream response
	respBody, err := io.ReadAll(upstreamResp.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	// Add HELM governance headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-HELM-Governed", "true")
	w.Header().Set("X-HELM-Model", req.Model)

	// Forward upstream status code and body
	w.WriteHeader(upstreamResp.StatusCode)
	_, _ = w.Write(respBody)
}

// openAICompletionsURL accepts an upstream base URL with or without the OpenAI
// /v1 path. This keeps chart and local configuration unambiguous while
// ensuring the handler sends exactly one version segment upstream.
func openAICompletionsURL(upstreamURL string) string {
	base := strings.TrimRight(strings.TrimSpace(upstreamURL), "/")
	if strings.HasSuffix(base, "/v1") {
		return base + "/chat/completions"
	}
	return base + "/v1/chat/completions"
}

// credentialsEqual avoids turning a configuration error into a credential
// comparison side channel. Empty credentials are handled by the caller's
// required-value check and never compare as equal here.
func credentialsEqual(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	leftDigest := sha256.Sum256([]byte(left))
	rightDigest := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1
}
