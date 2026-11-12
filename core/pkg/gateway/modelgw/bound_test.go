package modelgw

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/modelbound"
)

// A one-pixel PNG, inline. Its bytes are far fewer than the tokens a provider
// bills for any image.
const tinyPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="

// TestRequestFormsWhoseCostTheQuoteCannotSeeAreRefused (helm-tracker#313,
// audit H6): the quote counts the request's bytes and its output cap, so a
// request that makes the provider bill anything else (a stored thread, a stored
// prompt, remote media, a member the gateway does not know, a routing member
// that changes the billed model) is refused before any attempt, naming the
// member.
func TestRequestFormsWhoseCostTheQuoteCannotSeeAreRefused(t *testing.T) {
	user := func(parts string) string { return `[{"role":"user","content":[` + parts + `]}]` }
	responses := func(extra string) string {
		return `{"model":"gpt-6-sol","max_output_tokens":10,"input":"hi"` + extra + `}`
	}
	responsesInput := func(input string) string { return `{"model":"gpt-6-sol","max_output_tokens":10,"input":` + input + `}` }
	chat := func(model, extra string) string {
		return `{"model":"` + model + `","max_tokens":10,"messages":[{"role":"user","content":"hi"}]` + extra + `}`
	}
	chatMessages := func(messages string) string {
		return `{"model":"gpt-6-sol","max_tokens":10,"messages":` + messages + `}`
	}
	messages := func(extra string) string {
		return `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}]` + extra + `}`
	}
	anthropic := func(msgs string) string {
		return `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":` + msgs + `}`
	}

	for name, test := range map[string]struct{ api, body, member string }{
		// Server-side state the request names but does not carry.
		"responses: previous_response_id": {effectargs.APIOpenAIResponses, responses(`,"previous_response_id":"resp_1"`), "previous_response_id"},
		"responses: conversation":         {effectargs.APIOpenAIResponses, responses(`,"conversation":"conv_1"`), "conversation"},
		"responses: conversation object":  {effectargs.APIOpenAIResponses, responses(`,"conversation":{"id":"conv_1"}`), "conversation"},
		"responses: a stored prompt":      {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","max_output_tokens":10,"prompt":{"id":"pmpt_1","version":"2"}}`, "prompt"},
		"responses: store true":           {effectargs.APIOpenAIResponses, responses(`,"store":true`), "store"},
		"responses: an item reference":    {effectargs.APIOpenAIResponses, responsesInput(`[{"type":"item_reference","id":"msg_1"}]`), "item_reference"},
		"chat: store true":                {effectargs.APIOpenAIChat, chat("gpt-6-sol", `,"store":true`), "store"},
		"chat: a stored audio reply":      {effectargs.APIOpenAIChat, chatMessages(`[{"role":"user","content":"hi"},{"role":"assistant","audio":{"id":"audio_1"}}]`), "audio"},

		// Remote and stored media, in every spelling the APIs take.
		"responses: an image URL":                 {effectargs.APIOpenAIResponses, responsesInput(user(`{"type":"input_image","image_url":"https://example.test/cat.png"}`)), "image_url"},
		"responses: an image file id":             {effectargs.APIOpenAIResponses, responsesInput(user(`{"type":"input_image","file_id":"file-1"}`)), "file_id"},
		"responses: a file by id":                 {effectargs.APIOpenAIResponses, responsesInput(user(`{"type":"input_file","file_id":"file-1"}`)), "input_file"},
		"responses: a file by URL":                {effectargs.APIOpenAIResponses, responsesInput(user(`{"type":"input_file","file_url":"https://example.test/a.pdf"}`)), "input_file"},
		"responses: an inline file":               {effectargs.APIOpenAIResponses, responsesInput(user(`{"type":"input_file","filename":"a.pdf","file_data":"data:application/pdf;base64,JVBERi0="}`)), "input_file"},
		"responses: an image in a tool output":    {effectargs.APIOpenAIResponses, responsesInput(`[{"type":"function_call_output","call_id":"c1","output":[{"type":"input_image","image_url":"https://example.test/cat.png"}]}]`), "image_url"},
		"chat: an image URL":                      {effectargs.APIOpenAIChat, chatMessages(user(`{"type":"image_url","image_url":{"url":"https://example.test/cat.png"}}`)), "url"},
		"chat: a file by id":                      {effectargs.APIOpenAIChat, chatMessages(user(`{"type":"file","file":{"file_id":"file-1"}}`)), "file"},
		"chat: an inline file":                    {effectargs.APIOpenAIChat, chatMessages(user(`{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,JVBERi0="}}`)), "file"},
		"chat: input audio":                       {effectargs.APIOpenAIChat, chatMessages(user(`{"type":"input_audio","input_audio":{"data":"UklGRg==","format":"wav"}}`)), "input_audio"},
		"messages: an image URL":                  {effectargs.APIAnthropicMessages, anthropic(user(`{"type":"image","source":{"type":"url","url":"https://example.test/cat.png"}}`)), "url"},
		"messages: an image file":                 {effectargs.APIAnthropicMessages, anthropic(user(`{"type":"image","source":{"type":"file","file_id":"file_1"}}`)), "file"},
		"messages: a document URL":                {effectargs.APIAnthropicMessages, anthropic(user(`{"type":"document","source":{"type":"url","url":"https://example.test/a.pdf"}}`)), "url"},
		"messages: a document file":               {effectargs.APIAnthropicMessages, anthropic(user(`{"type":"document","source":{"type":"file","file_id":"file_1"}}`)), "file"},
		"messages: an inline PDF":                 {effectargs.APIAnthropicMessages, anthropic(user(`{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBERi0="}}`)), "base64"},
		"messages: an image URL in a tool result": {effectargs.APIAnthropicMessages, anthropic(user(`{"type":"tool_result","tool_use_id":"t1","content":[{"type":"image","source":{"type":"url","url":"https://example.test/cat.png"}}]}`)), "url"},
		"messages: a container upload":            {effectargs.APIAnthropicMessages, anthropic(user(`{"type":"container_upload","file_id":"file_1"}`)), "container_upload"},
		"messages: a server tool block":           {effectargs.APIAnthropicMessages, anthropic(`[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"server_tool_use","id":"s1","name":"web_search","input":{}}]}]`), "server_tool_use"},

		// Members that change the billed model or price.
		"chat: models":               {effectargs.APIOpenAIChat, chat("deepseek/deepseek-chat", `,"models":["openai/gpt-6-sol"]`), "models"},
		"chat: provider":             {effectargs.APIOpenAIChat, chat("deepseek/deepseek-chat", `,"provider":{"order":["x"]}`), "provider"},
		"chat: plugins":              {effectargs.APIOpenAIChat, chat("deepseek/deepseek-chat", `,"plugins":[{"id":"web"}]`), "plugins"},
		"chat: route":                {effectargs.APIOpenAIChat, chat("deepseek/deepseek-chat", `,"route":"fallback"`), "route"},
		"chat: audio output":         {effectargs.APIOpenAIChat, chat("gpt-6-sol", `,"modalities":["text","audio"],"audio":{"voice":"alloy","format":"wav"}`), "modalities"},
		"chat: predicted output":     {effectargs.APIOpenAIChat, chat("gpt-6-sol", `,"prediction":{"type":"content","content":"x"}`), "prediction"},
		"chat: priority tier":        {effectargs.APIOpenAIChat, chat("gpt-6-sol", `,"service_tier":"priority"`), "service_tier"},
		"responses: priority tier":   {effectargs.APIOpenAIResponses, responses(`,"service_tier":"priority"`), "service_tier"},
		"responses: models":          {effectargs.APIOpenAIResponses, responses(`,"models":["a","b"]`), "models"},
		"messages: fast mode":        {effectargs.APIAnthropicMessages, messages(`,"speed":"fast"`), "speed"},
		"messages: inference region": {effectargs.APIAnthropicMessages, messages(`,"inference_geo":"us"`), "inference_geo"},

		// A member the quote does not know is refused, not passed through.
		"responses: an unknown member": {effectargs.APIOpenAIResponses, responses(`,"future_member":1`), "future_member"},
		"chat: an unknown member":      {effectargs.APIOpenAIChat, chat("gpt-6-sol", `,"future_member":1`), "future_member"},
		"messages: an unknown member":  {effectargs.APIAnthropicMessages, messages(`,"future_member":1`), "future_member"},
		"chat: an unknown part type":   {effectargs.APIOpenAIChat, chatMessages(user(`{"type":"future_part","x":1}`)), "future_part"},
		"messages: an unknown block":   {effectargs.APIAnthropicMessages, anthropic(user(`{"type":"future_block","x":1}`)), "future_block"},
	} {
		c, err := inspectFor(t, test.api, test.body)
		if err == nil {
			t.Errorf("%s: accepted (%s)", name, c.Body)
			continue
		}
		if err.Status != 400 || !strings.Contains(err.Message, test.member) {
			t.Errorf("%s: refused with %d %s (%s), want 400 naming %q", name, err.Status, err.Code, err.Message, test.member)
		}
	}
}

// TestRequestsTheQuoteUnderstandsStillPass guards the closed list from the
// other side: what an unmodified client sends is not refused.
func TestRequestsTheQuoteUnderstandsStillPass(t *testing.T) {
	image := `{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + tinyPNG + `"}}`
	for name, test := range map[string]struct{ api, body string }{
		"messages: Claude Code shape": {effectargs.APIAnthropicMessages, `{"model":"claude-sonnet-5-5","max_tokens":1024,"stream":true,
			"system":[{"type":"text","text":"You are Claude Code.","cache_control":{"type":"ephemeral"}}],
			"messages":[{"role":"user","content":[{"type":"text","text":"look"},` + image + `]},
			  {"role":"assistant","content":[{"type":"thinking","thinking":"hm","signature":"sig"},{"type":"tool_use","id":"t1","name":"Read","input":{"path":"a"}}]},
			  {"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"file"},` + image + `]}]}],
			"tools":[{"name":"Read","description":"read","input_schema":{"type":"object"}}],"tool_choice":{"type":"auto"},
			"metadata":{"user_id":"u"},"temperature":1,"thinking":{"type":"enabled","budget_tokens":512},"context_management":{"edits":[]}}`},
		"messages: an inline text document": {effectargs.APIAnthropicMessages, `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"text","media_type":"text/plain","data":"abc"}}]}]}`},
		"responses: Codex shape": {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","instructions":"x","store":false,"stream":true,"parallel_tool_calls":false,
			"include":["reasoning.encrypted_content"],"reasoning":{"effort":"high","summary":"auto"},"prompt_cache_key":"k","text":{"verbosity":"low"},
			"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"},{"type":"input_image","image_url":"data:image/png;base64,` + tinyPNG + `"}]},
			  {"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"gAAAAA"},{"type":"function_call","call_id":"c1","name":"shell","arguments":"{}"},
			  {"type":"function_call_output","call_id":"c1","output":"ok"}],
			"tools":[{"type":"function","name":"shell","parameters":{}}],"tool_choice":"auto"}`},
		"chat: SDK shape": {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","max_completion_tokens":100,"temperature":0.2,"top_p":1,"n":1,"stream":true,"stream_options":{"include_usage":true},
			"messages":[{"role":"system","content":"s"},{"role":"user","content":[{"type":"text","text":"x"},{"type":"image_url","image_url":{"url":"data:image/png;base64,` + tinyPNG + `","detail":"high"}}]},
			  {"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{}"}}]},{"role":"tool","tool_call_id":"c1","content":"r"}],
			"tools":[{"type":"function","function":{"name":"f","parameters":{}}}],"response_format":{"type":"json_object"},"seed":1,"user":"u","store":false,"service_tier":"default"}`},
	} {
		if _, err := inspectFor(t, test.api, test.body); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

// TestTheHoldCoversWhatAnAllowedRequestCanBill (audit H6): bytes bound the
// tokens of text a request carries, not what a provider bills for an image or
// for the system prompt it adds when a request declares tools. The hold must
// cover the providers' documented maximum for each.
func TestTheHoldCoversWhatAnAllowedRequestCanBill(t *testing.T) {
	ledger := &stubLedger{t: t, OnGrants: agentGrants()}
	var mu sync.Mutex
	var quotes []int64
	ledger.OnPropose = func(_ admission.Caller, in admission.ProposeInput) (admission.Attempt, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		for _, a := range in.Quote {
			if a.Unit == admission.UnitUSDMicros {
				quotes = append(quotes, a.Amount)
			}
		}
		return admission.Attempt{ID: attemptID, State: "DENIED", ReasonCode: string(contracts.ReasonBudgetExceeded)}, false, nil
	}
	url := stubbed(t, ledger, true)
	cfg := testConfig(t, "http://127.0.0.1:9", "http://127.0.0.1:9/v1", "http://127.0.0.1:9/v1")

	for name, test := range map[string]struct {
		path, route, body string
		// extra is the input tokens the provider documents beyond the
		// request's bytes for what the request carries.
		extra int64
	}{
		// Anthropic: an image of up to about 1.15 megapixels is about 1,600
		// tokens, whatever its encoded size.
		"messages: one inline image": {"/v1/messages", routeSonnet,
			`{"model":"claude-sonnet-5-5","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + tinyPNG + `"}}]}]}`, 1600},
		// OpenAI: a high-detail image on gpt-4o-mini is 2,833 + 8 x 5,667 tokens.
		"chat: one inline image": {"/v1/chat/completions", routeGPT,
			`{"model":"gpt-6-sol","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` + tinyPNG + `","detail":"high"}}]}]}`, 2833 + 8*5667},
		"responses: one inline image": {"/v1/responses", routeGPT,
			`{"model":"gpt-6-sol","max_output_tokens":1,"input":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,` + tinyPNG + `"}]}]}`, 2833 + 8*5667},
		// Anthropic: the tool-use system prompt (346 tokens) and the computer
		// use tool (735 tokens and a 499-token system prompt).
		"messages: the computer use tool": {"/v1/messages", routeSonnet,
			`{"model":"claude-sonnet-5-5","max_tokens":1,"messages":[{"role":"user","content":"x"}],"tools":[{"type":"computer_20250124","name":"computer","display_width_px":1024,"display_height_px":768}]}`, 346 + 735 + 499},
	} {
		mu.Lock()
		quotes = nil
		mu.Unlock()
		r := post(t, url, test.path, workerHeaders(tokenAgent), test.body)
		if r.Status != 403 {
			t.Fatalf("%s: %s, want the scripted denial", name, r)
		}
		var route *Route
		for _, candidate := range cfg.Routes() {
			if candidate.ID == test.route {
				route = candidate
			}
		}
		worst, err := route.Cost(Usage{InputTokens: int64(len(test.body)) + test.extra, OutputTokens: 1})
		must(t, err)
		mu.Lock()
		got := append([]int64(nil), quotes...)
		mu.Unlock()
		if len(got) != 1 || got[0] < worst {
			t.Errorf("%s: held %v usd_micros, but the provider can bill %d for it", name, got, worst)
		}
	}
}

// TestLongContextBetaIsRefused: an anthropic-beta that bills a long request at
// a premium is refused before any attempt; other betas pass.
func TestLongContextBetaIsRefused(t *testing.T) {
	h := http.Header{}
	h.Add("Anthropic-Beta", "claude-code-20250219, context-1m-2025-08-07")
	if e := anthropicBetaRefusal(effectargs.APIAnthropicMessages, h); e == nil || e.Status != 400 || !strings.Contains(e.Message, "context-1m") {
		t.Fatalf("refusal = %v, want 400 naming the beta", e)
	}
	h.Set("Anthropic-Beta", "claude-code-20250219,interleaved-thinking-2025-05-14")
	if e := anthropicBetaRefusal(effectargs.APIAnthropicMessages, h); e != nil {
		t.Fatalf("an ordinary beta was refused: %v", e)
	}
}

// TestHiddenToolDefinitionsAreInTheHold: tools whose definitions the provider
// supplies add their floor to the input bound; function tools carry theirs.
func TestHiddenToolDefinitionsAreInTheHold(t *testing.T) {
	for name, test := range map[string]struct {
		api, body string
		extra     int64
	}{
		"responses: local_shell and apply_patch": {effectargs.APIOpenAIResponses,
			`{"model":"gpt-6-sol","max_output_tokens":1,"input":"x","tools":[{"type":"local_shell"},{"type":"apply_patch"},{"type":"function","name":"f","parameters":{}}]}`, 2 * modelbound.HiddenToolTokens},
		"messages: a custom tool": {effectargs.APIAnthropicMessages,
			`{"model":"claude-sonnet-5-5","max_tokens":1,"messages":[{"role":"user","content":"x"}],"tools":[{"name":"f","input_schema":{}}]}`, modelbound.AnthropicToolSystemTokens},
		"messages: bash and an image in a tool result": {effectargs.APIAnthropicMessages,
			`{"model":"claude-sonnet-5-5","max_tokens":1,"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + tinyPNG + `"}}]}]}],"tools":[{"type":"bash_20250124","name":"bash"}]}`,
			modelbound.AnthropicToolSystemTokens + modelbound.HiddenToolTokens + modelbound.AnthropicImageTokens},
		"chat: two inline images": {effectargs.APIOpenAIChat,
			`{"model":"gpt-6-sol","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` + tinyPNG + `"}},{"type":"image_url","image_url":"data:image/png;base64,` + tinyPNG + `"}]}]}`, 2 * modelbound.OpenAIImageTokens},
	} {
		c, err := inspectFor(t, test.api, test.body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.ExtraInputTokens != test.extra || c.inputBound(c.Body) != int64(len(c.Body))+test.extra {
			t.Errorf("%s: extra input tokens %d, want %d", name, c.ExtraInputTokens, test.extra)
		}
	}
}
