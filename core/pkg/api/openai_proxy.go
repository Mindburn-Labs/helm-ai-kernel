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

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/privacy"
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

// OpenAIChatRequest is the typed view of an OpenAI-compatible request that the
// proxy validates. The proxy forwards the caller's whole request object, so
// fields this view does not model (max_completion_tokens, reasoning_effort,
// tools, ...) still reach the upstream provider unchanged.
// API-001/002: Includes tool_choice, parallel_tool_calls, and response_format.
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
// maxOpenAIRequestSize matches the canonical privacy payload ceiling.
const maxOpenAIRequestSize = privacy.MaxPayloadBytes

func HandleOpenAIProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteMethodNotAllowed(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxOpenAIRequestSize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteBadRequest(w, "Invalid request body")
		return
	}
	// req is validated; fields is what goes upstream, so request parameters
	// that OpenAIChatRequest does not model are not dropped.
	var req OpenAIChatRequest
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &req) != nil || json.Unmarshal(body, &fields) != nil || fields == nil {
		WriteBadRequest(w, "Invalid request body")
		return
	}

	if req.Model == "" {
		req.Model = "gpt-6-sol"
		fields["model"], _ = json.Marshal(req.Model)
	}
	if req.Stream {
		WriteForbidden(w, privacy.ErrDataEgressBlocked.Error())
		return
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
	upstreamReq, err := json.Marshal(fields)
	if err != nil {
		WriteBadRequest(w, fmt.Sprintf("Failed to marshal request: %v", err))
		return
	}
	protectedRequest, _, err := privacy.ProtectModelRequestJSON(r.Context(), json.RawMessage(upstreamReq))
	if err != nil {
		WriteForbidden(w, privacy.ErrDataEgressBlocked.Error())
		return
	}
	if err := json.Unmarshal(protectedRequest, &req); err != nil {
		WriteForbidden(w, privacy.ErrDataEgressBlocked.Error())
		return
	}

	// Create upstream request
	proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		upstreamURL+"/v1/chat/completions", bytes.NewReader(protectedRequest))
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
	respBody, err := io.ReadAll(io.LimitReader(upstreamResp.Body, privacy.MaxPayloadBytes+1))
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	protectedResponse, _, err := privacy.ProtectModelResponseJSON(r.Context(), json.RawMessage(respBody))
	if err != nil {
		WriteError(w, http.StatusBadGateway, "Upstream response blocked", privacy.ErrDataEgressBlocked.Error())
		return
	}

	// Add HELM governance headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-HELM-Governed", "true")
	w.Header().Set("X-HELM-Model", req.Model)

	// Forward upstream status code and body
	w.WriteHeader(upstreamResp.StatusCode)
	_, _ = w.Write(protectedResponse)
}
