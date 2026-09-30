package modelgw

import (
	"bytes"
	"encoding/json"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// reported is a usage report as a provider wrote it, kept as it came so the
// ledger records what was said, and the normalized counts that price it.
type reported struct {
	Usage
	Raw json.RawMessage
}

// anthropicUsage is Anthropic's usage object, in a message or in the
// message_start and message_delta events. Fields absent from an event are nil,
// so a later event overrides only what it reports.
type anthropicUsage struct {
	InputTokens              *int64 `json:"input_tokens,omitempty"`
	OutputTokens             *int64 `json:"output_tokens,omitempty"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens,omitempty"`
	CacheCreation            *struct {
		Ephemeral5m *int64 `json:"ephemeral_5m_input_tokens,omitempty"`
		Ephemeral1h *int64 `json:"ephemeral_1h_input_tokens,omitempty"`
	} `json:"cache_creation,omitempty"`
}

func (a *anthropicUsage) merge(b anthropicUsage) {
	if b.InputTokens != nil {
		a.InputTokens = b.InputTokens
	}
	if b.OutputTokens != nil {
		a.OutputTokens = b.OutputTokens
	}
	if b.CacheCreationInputTokens != nil {
		a.CacheCreationInputTokens = b.CacheCreationInputTokens
	}
	if b.CacheReadInputTokens != nil {
		a.CacheReadInputTokens = b.CacheReadInputTokens
	}
	if b.CacheCreation != nil {
		a.CacheCreation = b.CacheCreation
	}
}

// report returns the normalized usage, nil when nothing was reported. The cache
// write tokens are split by lifetime when the provider says how, and all
// counted at the shorter, cheaper lifetime when it does not: never above what
// the quote covers.
func (a anthropicUsage) report(raw json.RawMessage) *reported {
	if a.InputTokens == nil && a.OutputTokens == nil {
		return nil
	}
	u := Usage{InputTokens: val(a.InputTokens), OutputTokens: val(a.OutputTokens), CacheReadTokens: val(a.CacheReadInputTokens)}
	switch {
	case a.CacheCreation != nil:
		u.CacheWrite5mTokens, u.CacheWrite1hTokens = val(a.CacheCreation.Ephemeral5m), val(a.CacheCreation.Ephemeral1h)
		if rest := val(a.CacheCreationInputTokens) - u.CacheWrite5mTokens - u.CacheWrite1hTokens; rest > 0 {
			u.CacheWrite5mTokens += rest
		}
	default:
		u.CacheWrite5mTokens = val(a.CacheCreationInputTokens)
	}
	return &reported{Usage: u, Raw: raw}
}

// openAIUsage is OpenAI's usage object in either API: chat calls the counts
// prompt and completion, responses calls them input and output.
type openAIUsage struct {
	PromptTokens        *int64 `json:"prompt_tokens"`
	CompletionTokens    *int64 `json:"completion_tokens"`
	InputTokens         *int64 `json:"input_tokens"`
	OutputTokens        *int64 `json:"output_tokens"`
	PromptTokensDetails *struct {
		CachedTokens *int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	InputTokensDetails *struct {
		CachedTokens *int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

func (o openAIUsage) report(raw json.RawMessage) *reported {
	in, out := o.PromptTokens, o.CompletionTokens
	if in == nil {
		in = o.InputTokens
	}
	if out == nil {
		out = o.OutputTokens
	}
	if in == nil && out == nil {
		return nil
	}
	var cached int64
	switch {
	case o.PromptTokensDetails != nil:
		cached = val(o.PromptTokensDetails.CachedTokens)
	case o.InputTokensDetails != nil:
		cached = val(o.InputTokensDetails.CachedTokens)
	}
	regular := val(in)
	if cached > 0 && cached <= regular {
		regular -= cached
	} else {
		cached = 0
	}
	return &reported{Usage: Usage{InputTokens: regular, CacheReadTokens: cached, OutputTokens: val(out)}, Raw: raw}
}

func val(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// parseBodyUsage reads the usage of a complete, non-streamed response, nil
// when the body reports none.
func parseBodyUsage(api string, body []byte) *reported {
	var envelope struct {
		Usage json.RawMessage `json:"usage"`
	}
	if json.Unmarshal(body, &envelope) != nil || len(envelope.Usage) == 0 || bytes.Equal(envelope.Usage, []byte("null")) {
		return nil
	}
	return decodeUsage(api, envelope.Usage)
}

func decodeUsage(api string, raw json.RawMessage) *reported {
	if api == effectargs.APIAnthropicMessages {
		var a anthropicUsage
		if json.Unmarshal(raw, &a) != nil {
			return nil
		}
		return a.report(raw)
	}
	var o openAIUsage
	if json.Unmarshal(raw, &o) != nil {
		return nil
	}
	return o.report(raw)
}

// streamTracker follows a streamed response's events for the two facts the
// ledger needs: whether the provider finished the stream, and the usage it
// reported. It never changes an event.
type streamTracker struct {
	api string
	// done is set on the event that ends a well-formed stream.
	done bool
	// providerError is set when the stream carried an error event.
	providerError bool

	anthropic    anthropicUsage
	sawAnthropic bool
	final        *reported
}

func newStreamTracker(api string) *streamTracker { return &streamTracker{api: api} }

// usage is the usage the stream reported, nil when it reported none.
func (t *streamTracker) usage() *reported {
	if t.api == effectargs.APIAnthropicMessages {
		if !t.sawAnthropic {
			return nil
		}
		raw, _ := json.Marshal(t.anthropic)
		return t.anthropic.report(raw)
	}
	return t.final
}

// observe reads one event.
func (t *streamTracker) observe(ev sseEvent) {
	switch t.api {
	case effectargs.APIAnthropicMessages:
		t.observeAnthropic(ev)
	case effectargs.APIOpenAIChat:
		t.observeChat(ev)
	default:
		t.observeResponses(ev)
	}
}

func (t *streamTracker) observeAnthropic(ev sseEvent) {
	name := ev.Name
	if name == "" {
		var probe struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(ev.Data, &probe)
		name = probe.Type
	}
	switch name {
	case "message_start":
		var m struct {
			Message struct {
				Usage anthropicUsage `json:"usage"`
			} `json:"message"`
		}
		if json.Unmarshal(ev.Data, &m) == nil {
			t.anthropic.merge(m.Message.Usage)
			t.sawAnthropic = true
		}
	case "message_delta":
		var m struct {
			Usage anthropicUsage `json:"usage"`
		}
		if json.Unmarshal(ev.Data, &m) == nil {
			t.anthropic.merge(m.Usage)
			t.sawAnthropic = true
		}
	case "message_stop":
		t.done = true
	case "error":
		t.providerError = true
	}
}

func (t *streamTracker) observeChat(ev sseEvent) {
	if bytes.Equal(bytes.TrimSpace(ev.Data), []byte("[DONE]")) {
		t.done = true
		return
	}
	if bytes.Contains(ev.Data, []byte(`"error"`)) && chatError(ev.Data) {
		t.providerError = true
		return
	}
	if !bytes.Contains(ev.Data, []byte(`"usage"`)) {
		return
	}
	var chunk struct {
		Usage json.RawMessage `json:"usage"`
	}
	if json.Unmarshal(ev.Data, &chunk) == nil && len(chunk.Usage) > 0 && !bytes.Equal(chunk.Usage, []byte("null")) {
		if r := decodeUsage(t.api, chunk.Usage); r != nil {
			t.final = r
		}
	}
}

// chatError reports whether a chunk is an error object, which some
// OpenAI-compatible upstreams send mid-stream.
func chatError(data []byte) bool {
	var probe struct {
		Error json.RawMessage `json:"error"`
	}
	return json.Unmarshal(data, &probe) == nil && len(probe.Error) > 0 && !bytes.Equal(probe.Error, []byte("null"))
}

// isChatUsageOnly reports whether a chat chunk carries usage and no choices:
// the chunk stream_options.include_usage adds at the end of a stream.
func isChatUsageOnly(data []byte) bool {
	if !bytes.Contains(data, []byte(`"usage"`)) {
		return false
	}
	var chunk struct {
		Choices json.RawMessage `json:"choices"`
		Usage   json.RawMessage `json:"usage"`
	}
	if json.Unmarshal(data, &chunk) != nil || len(chunk.Usage) == 0 || bytes.Equal(chunk.Usage, []byte("null")) {
		return false
	}
	choices := bytes.TrimSpace(chunk.Choices)
	return len(choices) == 0 || bytes.Equal(choices, []byte("[]")) || bytes.Equal(choices, []byte("null"))
}

func (t *streamTracker) observeResponses(ev sseEvent) {
	name := ev.Name
	if name == "" {
		var probe struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(ev.Data, &probe)
		name = probe.Type
	}
	switch name {
	case "response.completed", "response.incomplete", "response.failed":
		t.done = true
		if name == "response.failed" {
			t.providerError = true
		}
		var m struct {
			Response struct {
				Usage json.RawMessage `json:"usage"`
			} `json:"response"`
		}
		if json.Unmarshal(ev.Data, &m) == nil && len(m.Response.Usage) > 0 && !bytes.Equal(m.Response.Usage, []byte("null")) {
			if r := decodeUsage(t.api, m.Response.Usage); r != nil {
				t.final = r
			}
		}
	case "error":
		t.providerError = true
	}
}
