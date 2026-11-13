package modelgw

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// refusedNaming checks that each body is refused with 400 and an error that
// names the member, before any attempt exists.
func refusedNaming(t *testing.T, cases map[string]struct{ api, body, member string }) {
	t.Helper()
	for name, test := range cases {
		c, err := inspectFor(t, test.api, test.body)
		if err == nil {
			t.Errorf("%s: accepted (%s)", name, c.Body)
			continue
		}
		if err.Status != http.StatusBadRequest || !strings.Contains(err.Message, test.member) {
			t.Errorf("%s: refused with %d %s (%s), want 400 naming %q", name, err.Status, err.Code, err.Message, test.member)
		}
	}
}

func acceptedAll(t *testing.T, cases map[string]struct{ api, body string }) {
	t.Helper()
	for name, test := range cases {
		if _, err := inspectFor(t, test.api, test.body); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

// TestStoredStateNamedByIDIsRefused (helm-tracker#313 r1, F3): a Responses
// input item that names a stored item by its id, without carrying what the
// provider bills for it, makes the provider bill stored state the quote never
// saw. A reasoning item must carry its encrypted content.
func TestStoredStateNamedByIDIsRefused(t *testing.T) {
	input := func(items string) string {
		return `{"model":"gpt-6-sol","max_output_tokens":10,"input":` + items + `}`
	}
	refusedNaming(t, map[string]struct{ api, body, member string }{
		"reasoning by id without encrypted content": {effectargs.APIOpenAIResponses,
			input(`[{"role":"user","content":"go"},{"type":"reasoning","id":"rs_stored","summary":[]},{"type":"function_call","call_id":"c1","name":"f","arguments":"{}"},{"type":"function_call_output","call_id":"c1","output":"ok"}]`), "encrypted_content"},
		"reasoning without an id or encrypted content": {effectargs.APIOpenAIResponses,
			input(`[{"type":"reasoning","summary":[{"type":"summary_text","text":"x"}]}]`), "encrypted_content"},
		"a function call by id alone": {effectargs.APIOpenAIResponses,
			input(`[{"type":"function_call","id":"fc_stored"}]`), "fc_stored"},
		"a message by id with no content": {effectargs.APIOpenAIResponses,
			input(`[{"type":"message","id":"msg_stored","role":"assistant","content":[]},{"role":"user","content":"go"}]`), "msg_stored"},
		"a message by id without content": {effectargs.APIOpenAIResponses,
			input(`[{"type":"message","id":"msg_stored","role":"assistant"}]`), "msg_stored"},
		"a tool output by id alone": {effectargs.APIOpenAIResponses,
			input(`[{"type":"function_call_output","id":"fco_stored"}]`), "fco_stored"},
	})
	acceptedAll(t, map[string]struct{ api, body string }{
		"reasoning that carries its encrypted content": {effectargs.APIOpenAIResponses,
			input(`[{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"gAAAAA"}]`)},
		"a function call that carries its call": {effectargs.APIOpenAIResponses,
			input(`[{"type":"function_call","id":"fc_1","call_id":"c1","name":"f","arguments":"{}"},{"type":"function_call_output","call_id":"c1","output":"ok"}]`)},
		"a message that carries its content": {effectargs.APIOpenAIResponses,
			input(`[{"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"hi"}]}]`)},
	})
}

// TestResponsesAreNotStored (F3): OpenAI stores a response unless told not to,
// and a stored response can be billed again by reference. The gateway sends
// store false when the request names none.
func TestResponsesAreNotStored(t *testing.T) {
	c, err := inspectFor(t, effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","max_output_tokens":10,"input":"hi"}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(forwarded(t, c)["store"]); got != "false" {
		t.Fatalf("forwarded store = %q, want false; body %s", got, c.Body)
	}
	c, err = inspectFor(t, effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","max_output_tokens":10,"input":"hi","store":false}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(forwarded(t, c)["store"]); got != "false" {
		t.Fatalf("forwarded store = %q, want false", got)
	}
}

// TestNestedMembersAreClosed (F5): the closed list reaches inside the members
// that configure the call. Anthropic's compaction edit runs an extra sampling
// pass billed on top of max_tokens; only edits that remove content pass.
func TestNestedMembersAreClosed(t *testing.T) {
	messages := func(extra string) string {
		return `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}]` + extra + `}`
	}
	responses := func(extra string) string {
		return `{"model":"gpt-6-sol","max_output_tokens":10,"input":"hi"` + extra + `}`
	}
	refusedNaming(t, map[string]struct{ api, body, member string }{
		"messages: a compaction edit": {effectargs.APIAnthropicMessages,
			messages(`,"context_management":{"edits":[{"type":"compact_20260112","trigger":{"type":"input_tokens","value":50000}}]}`), "compact_20260112"},
		"messages: an unknown context_management member": {effectargs.APIAnthropicMessages,
			messages(`,"context_management":{"edits":[],"future":1}`), "future"},
		"messages: an unknown member of a clearing edit": {effectargs.APIAnthropicMessages,
			messages(`,"context_management":{"edits":[{"type":"clear_tool_uses_20250919","summarize":true}]}`), "summarize"},
		"messages: an unknown output_config member": {effectargs.APIAnthropicMessages,
			messages(`,"output_config":{"effort":"max","future":{"x":1}}`), "future"},
		"messages: an unknown thinking member": {effectargs.APIAnthropicMessages,
			messages(`,"thinking":{"type":"enabled","budget_tokens":5,"future":1}`), "future"},
		"messages: an unknown thinking type": {effectargs.APIAnthropicMessages,
			messages(`,"thinking":{"type":"extended"}`), "extended"},
		"responses: a reasoning token budget": {effectargs.APIOpenAIResponses,
			responses(`,"reasoning":{"effort":"high","max_tokens":100000}`), "max_tokens"},
		"responses: an unknown text member": {effectargs.APIOpenAIResponses,
			responses(`,"text":{"verbosity":"low","future":1}`), "future"},
		"responses: an unknown text format": {effectargs.APIOpenAIResponses,
			responses(`,"text":{"format":{"type":"grammar","grammar":"x"}}`), "grammar"},
	})
	acceptedAll(t, map[string]struct{ api, body string }{
		"messages: edits that clear content": {effectargs.APIAnthropicMessages,
			messages(`,"context_management":{"edits":[{"type":"clear_tool_uses_20250919","trigger":{"type":"input_tokens","value":30000},"keep":{"type":"tool_uses","value":3},"clear_at_least":{"type":"input_tokens","value":5000},"exclude_tools":["Read"],"clear_tool_inputs":true},{"type":"clear_thinking_20251015","keep":"all"}]}`)},
		"messages: output_config effort and format": {effectargs.APIAnthropicMessages,
			messages(`,"output_config":{"effort":"high","format":{"type":"json_schema","schema":{"type":"object"}}}`)},
		"messages: adaptive thinking": {effectargs.APIAnthropicMessages, messages(`,"thinking":{"type":"adaptive"}`)},
		"messages: thinking off":      {effectargs.APIAnthropicMessages, messages(`,"thinking":{"type":"disabled"}`)},
		"responses: reasoning effort and summary": {effectargs.APIOpenAIResponses,
			responses(`,"reasoning":{"effort":"high","summary":"auto"}`)},
		"responses: a json schema text format": {effectargs.APIOpenAIResponses,
			responses(`,"text":{"format":{"type":"json_schema","name":"r","schema":{"type":"object"},"strict":true},"verbosity":"low"}`)},
	})
}

// TestAnthropicBetasAreAllowlisted (F5): an anthropic-beta changes what
// Anthropic runs and bills; only betas the quote is known to bound pass.
func TestAnthropicBetasAreAllowlisted(t *testing.T) {
	for _, beta := range []string{"compact-2026-01-12", "files-api-2025-04-14", "mcp-client-2025-04-04", "code-execution-2025-05-22", "a-future-beta-2027-01-01"} {
		h := http.Header{}
		h.Add("Anthropic-Beta", "claude-code-20250219")
		h.Add("Anthropic-Beta", "interleaved-thinking-2025-05-14, "+beta)
		if e := anthropicBetaRefusal(effectargs.APIAnthropicMessages, h); e == nil || e.Status != http.StatusBadRequest || !strings.Contains(e.Message, beta) {
			t.Errorf("anthropic-beta %s: refusal = %v, want 400 naming it", beta, e)
		}
	}
	h := http.Header{}
	h.Set("Anthropic-Beta", "claude-code-20250219,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14,context-management-2025-06-27,prompt-caching-2024-07-31,token-efficient-tools-2025-02-19")
	if e := anthropicBetaRefusal(effectargs.APIAnthropicMessages, h); e != nil {
		t.Fatalf("an allowed beta was refused: %v", e)
	}
}

// TestServiceTierIsTheStandardTier (F6): an absent or auto service tier bills
// at whatever tier the provider account defaults to, which can be priority.
// On the vendors' own APIs the gateway names the standard tier; on an
// OpenAI-compatible upstream it refuses auto, whose meaning it cannot know.
func TestServiceTierIsTheStandardTier(t *testing.T) {
	for name, test := range map[string]struct{ api, body, want string }{
		"chat on openai, absent":      {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`, `"default"`},
		"chat on openai, auto":        {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"service_tier":"auto"}`, `"default"`},
		"chat on openai, flex":        {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"service_tier":"flex"}`, `"flex"`},
		"responses on openai, absent": {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","max_output_tokens":10,"input":"hi"}`, `"default"`},
		"responses on openai, auto":   {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","max_output_tokens":10,"input":"hi","service_tier":"auto"}`, `"default"`},
		"messages, absent":            {effectargs.APIAnthropicMessages, `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`, `"standard_only"`},
		"messages, auto":              {effectargs.APIAnthropicMessages, `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"service_tier":"auto"}`, `"standard_only"`},
		"chat on openrouter, absent":  {effectargs.APIOpenAIChat, `{"model":"deepseek/deepseek-chat","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`, ``},
	} {
		c, err := inspectFor(t, test.api, test.body)
		if err != nil {
			t.Errorf("%s: refused: %v", name, err)
			continue
		}
		if got := string(forwarded(t, c)["service_tier"]); got != test.want {
			t.Errorf("%s: forwarded service_tier %s, want %s", name, got, test.want)
		}
	}
	refusedNaming(t, map[string]struct{ api, body, member string }{
		"chat on openrouter, auto": {effectargs.APIOpenAIChat, `{"model":"deepseek/deepseek-chat","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"service_tier":"auto"}`, "service_tier"},
	})
}

// TestCitedDocumentsAreRefused (F13): Anthropic splits a text document with
// citations into chunks and bills tokens for the chunking that its bytes do
// not bound, so the gateway refuses citations on a document.
func TestCitedDocumentsAreRefused(t *testing.T) {
	doc := func(citations string) string {
		return `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"text","media_type":"text/plain","data":"a.a.a.a.a.a.a.a.a.a.a.a."}` + citations + `}]}]}`
	}
	refusedNaming(t, map[string]struct{ api, body, member string }{
		"messages: a text document with citations": {effectargs.APIAnthropicMessages, doc(`,"citations":{"enabled":true}`), "citations"},
	})
	acceptedAll(t, map[string]struct{ api, body string }{
		"messages: citations off": {effectargs.APIAnthropicMessages, doc(`,"citations":{"enabled":false}`)},
		"messages: no citations":  {effectargs.APIAnthropicMessages, doc(``)},
	})
}

// TestChatMessageMembersAreClosed (mutant M12): a chat message member the
// quote does not know is refused, naming it.
func TestChatMessageMembersAreClosed(t *testing.T) {
	refusedNaming(t, map[string]struct{ api, body, member string }{
		"chat: an unknown message member": {effectargs.APIOpenAIChat,
			`{"model":"gpt-6-sol","max_tokens":10,"messages":[{"role":"user","content":"hi","future_member":{"x":1}}]}`, "future_member"},
	})
}

// TestInlineMediaMustBeAnImage: an inline data URL in an image part is held at
// the image floor, so it must be an image; a video or audio data URL bills by
// its duration, which neither its bytes nor the image floor bound.
func TestInlineMediaMustBeAnImage(t *testing.T) {
	refusedNaming(t, map[string]struct{ api, body, member string }{
		"chat: a video data URL": {effectargs.APIOpenAIChat,
			`{"model":"gpt-6-sol","max_tokens":10,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:video/mp4;base64,AAAA"}}]}]}`, "data:image/"},
		"responses: an audio data URL": {effectargs.APIOpenAIResponses,
			`{"model":"gpt-6-sol","max_output_tokens":10,"input":[{"role":"user","content":[{"type":"input_image","image_url":"data:audio/wav;base64,AAAA"}]}]}`, "data:image/"},
	})
}

// TestFittedDefaultOutputCountsTheFloors (mutant M16): a defaulted output
// maximum is lowered until the whole quote fits, and that quote includes the
// image and tool floors, not only the bytes.
func TestFittedDefaultOutputCountsTheFloors(t *testing.T) {
	body := `{"model":"gpt-6-sol","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` + tinyPNG + `"}}]}]}`
	c, err := inspectFor(t, effectargs.APIOpenAIChat, body)
	if err != nil || !c.DefaultedOutput || c.ExtraInputTokens == 0 {
		t.Fatalf("inspect: %+v, %v", c, err)
	}
	remaining, qerr := c.Route.Quote(c.inputBound(c.Body), 100, c.MayWriteCache)
	must(t, qerr)
	c.fitDefaultOutput(remaining)
	quote, qerr := c.Route.Quote(c.inputBound(c.Body), c.MaxOutputTokens, c.MayWriteCache)
	must(t, qerr)
	if quote > remaining {
		t.Fatalf("the fitted call quotes %d usd_micros with its floors, above the %d it was fitted to", quote, remaining)
	}
	var sent struct {
		Max int64 `json:"max_completion_tokens"`
	}
	if err := json.Unmarshal(c.Body, &sent); err != nil || sent.Max != c.MaxOutputTokens {
		t.Fatalf("forwarded max_completion_tokens %d, want %d (%v)", sent.Max, c.MaxOutputTokens, err)
	}
}
