package main

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/manifest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
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

// validateToolCallArgs parses JSON arguments and returns their canonical
// SHA-256 digest. The open-policy proxy passes a nil tool schema.
func validateToolCallArgs(argsStr string) (string, bool) {
	var parsed any
	if err := json.Unmarshal([]byte(argsStr), &parsed); err != nil {
		return "", false
	}

	result, err := manifest.ValidateAndCanonicalizeToolArgs(nil, parsed)
	if err != nil {
		return "", false
	}

	return result.ArgsHash, true
}
