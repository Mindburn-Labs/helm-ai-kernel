// Package api provides the OpenAI-compatible proxy endpoint for HELM.
// Enabled via HELM_ENABLE_OPENAI_PROXY=1, this intercepts tool calls
// through the PEP boundary, enforcing governance on every operation.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
//   - If HELM_UPSTREAM_URL is set: proxies to the upstream LLM with full governance
//     (validates requests, enforces policy, generates receipts)
//   - If HELM_UPSTREAM_URL is NOT set: returns an error directing users to configure it
//
// For CLI-based governance with interactive upstream forwarding, use:
//
//	helm-ai-kernel proxy --upstream <url>
//
// maxOpenAIRequestSize is the maximum allowed request body size (10 MiB).
const maxOpenAIRequestSize = 10 << 20

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

	upstreamURL := os.Getenv("HELM_UPSTREAM_URL")
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

	// Forward to upstream with governance
	upstreamReq, err := json.Marshal(req)
	if err != nil {
		WriteBadRequest(w, fmt.Sprintf("Failed to marshal request: %v", err))
		return
	}

	// Create upstream request
	proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		upstreamURL+"/v1/chat/completions", bytes.NewReader(upstreamReq))
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

	// Forward authorization header to upstream
	if auth := r.Header.Get("Authorization"); auth != "" {
		proxyReq.Header.Set("Authorization", auth)
	}
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
