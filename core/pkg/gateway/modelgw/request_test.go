package modelgw

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

func inspectFor(t *testing.T, api, body string) (*call, *apiError) {
	t.Helper()
	return inspect(testConfig(t, "https://a.test", "https://o.test/v1", "https://r.test/v1"), api, []byte(body))
}

// forwarded parses the body the gateway would send.
func forwarded(t *testing.T, c *call) map[string]json.RawMessage {
	t.Helper()
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(c.Body, &m); err != nil {
		t.Fatalf("the forwarded body is not JSON: %v\n%s", err, c.Body)
	}
	return m
}

func TestEscapedPromptCacheKeysReserveTheCacheWriteTariff(t *testing.T) {
	for _, key := range []string{`cache_control`, `\u0063ache_control`, `cache_\u0063ontrol`, `\u0063\u0061\u0063\u0068\u0065\u005f\u0063\u006f\u006e\u0074\u0072\u006f\u006c`} {
		t.Run(key, func(t *testing.T) {
			body := `{"model":"claude-sonnet-5-5","max_tokens":1,"messages":[{"role":"user","content":[{"type":"text","text":"cache this","` + key + `":{"type":"ephemeral","ttl":"1h"}}]}]}`
			c, refusal := inspectFor(t, effectargs.APIAnthropicMessages, body)
			if refusal != nil {
				t.Fatal(refusal)
			}
			if !bytes.Equal(c.Body, []byte(body)) {
				t.Fatal("cache detection changed the native request")
			}
			quote, err := c.Route.Quote(int64(len(c.Body)), c.MaxOutputTokens, c.MayWriteCache)
			must(t, err)
			// A legitimate cache write within the byte and output bounds
			// must fit its reservation regardless of JSON key spelling.
			cost, err := c.Route.Cost(Usage{CacheWrite1hTokens: int64(len(c.Body)), OutputTokens: 1})
			must(t, err)
			if quote < cost {
				t.Fatalf("cache write within the request bounds costs %d but only %d was reserved", cost, quote)
			}
		})
	}
}

func TestNestedDuplicateKeysCannotHidePromptCacheCharges(t *testing.T) {
	for _, content := range []string{
		`[{"type":"text","text":"x","cache_control":null,"\u0063ache_control":{"type":"ephemeral","ttl":"1h"}}]`,
		`[{"type":"text","text":"x","\u0063ache_control":{"type":"ephemeral","ttl":"1h"},"cache_control":null}]`,
		`[{"type":"text","text":"x","nested":{"value":{},"value":{"\u0063ache_control":{"type":"ephemeral","ttl":"1h"}}}}]`,
	} {
		body := `{"model":"claude-sonnet-5-5","max_tokens":1,"messages":[{"role":"user","content":` + content + `}]}`
		if _, refusal := inspectFor(t, effectargs.APIAnthropicMessages, body); refusal == nil || refusal.Status != 400 || refusal.Code != "invalid_json" {
			t.Fatalf("an ambiguous nested request was not refused before admission: %v", refusal)
		}
	}
}

func TestAnUntouchedRequestIsForwardedByteForByte(t *testing.T) {
	for api, body := range map[string]string{
		effectargs.APIAnthropicMessages: `{"model": "claude-sonnet-5-5",  "max_tokens": 1024, "stream": true, "messages": [{"role":"user","content":"hi"}],
		 "system":[{"type":"text","text":"x","cache_control":{"type":"ephemeral"}}], "tools":[{"name":"get","input_schema":{"type":"object"}},{"type":"bash_20250124","name":"bash"}],
		 "thinking":{"type":"enabled","budget_tokens":512}}`,
		effectargs.APIOpenAIResponses: `{"model":"gpt-6-sol","input":"hi","max_output_tokens":2048,"stream":true,"tools":[{"type":"function","name":"f","parameters":{}},{"type":"custom","name":"apply_patch"},{"type":"local_shell"}]}`,
		effectargs.APIOpenAIChat:      `{"model":"gpt-6-sol","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":2048,"stream":true,"stream_options":{"include_usage":true},"tools":[{"type":"function","function":{"name":"f"}}]}`,
	} {
		c, err := inspectFor(t, api, body)
		if err != nil {
			t.Fatalf("%s: %v", api, err)
		}
		if !bytes.Equal(c.Body, []byte(body)) {
			t.Errorf("%s: the body was changed though nothing needed clamping:\n%s\n%s", api, c.Body, body)
		}
		if !c.Stream {
			t.Errorf("%s: stream not read", api)
		}
	}
}

func TestMaximumOutputTokensAreClampedOrInjected(t *testing.T) {
	type want struct {
		field string
		value int64
	}
	for name, test := range map[string]struct {
		api, body string
		want      want
		max       int64
	}{
		"messages: absent takes the route default":           {effectargs.APIAnthropicMessages, `{"model":"claude-haiku-4-5-20251001","messages":[]}`, want{"max_tokens", 4096}, 4096},
		"messages: null takes the default":                   {effectargs.APIAnthropicMessages, `{"model":"claude-haiku-4-5-20251001","max_tokens":null,"messages":[]}`, want{"max_tokens", 4096}, 4096},
		"messages: above the clamp is clamped":               {effectargs.APIAnthropicMessages, `{"model":"claude-haiku-4-5-20251001","max_tokens":999999,"messages":[]}`, want{"max_tokens", 32000}, 32000},
		"messages: an enormous integer is clamped":           {effectargs.APIAnthropicMessages, `{"model":"claude-haiku-4-5-20251001","max_tokens":123456789012345678901234567890,"messages":[]}`, want{"max_tokens", 32000}, 32000},
		"messages: within the clamp is the client's":         {effectargs.APIAnthropicMessages, `{"model":"claude-haiku-4-5-20251001","max_tokens":100,"messages":[]}`, want{}, 100},
		"responses: absent":                                  {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","input":"x"}`, want{"max_output_tokens", 8192}, 8192},
		"responses: above the clamp":                         {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","input":"x","max_output_tokens":100000}`, want{"max_output_tokens", 32000}, 32000},
		"chat: absent on openai takes max_completion_tokens": {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","messages":[]}`, want{"max_completion_tokens", 8192}, 8192},
		"chat: absent on openai-compatible takes max_tokens": {effectargs.APIOpenAIChat, `{"model":"deepseek/deepseek-chat","messages":[]}`, want{"max_tokens", 4096}, 4096},
		"chat: max_tokens above the clamp":                   {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","messages":[],"max_tokens":99999}`, want{"max_tokens", 32000}, 32000},
		"chat: max_completion_tokens above the clamp":        {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","messages":[],"max_completion_tokens":99999}`, want{"max_completion_tokens", 32000}, 32000},
		"chat: null is absent":                               {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","messages":[],"max_tokens":null}`, want{"max_completion_tokens", 8192}, 8192},
	} {
		c, err := inspectFor(t, test.api, test.body)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if c.MaxOutputTokens != test.max {
			t.Errorf("%s: effective maximum = %d, want %d", name, c.MaxOutputTokens, test.max)
		}
		if test.want.field == "" {
			if !bytes.Equal(c.Body, []byte(test.body)) {
				t.Errorf("%s: changed a request that was within bounds: %s", name, c.Body)
			}
			continue
		}
		got := forwarded(t, c)
		if string(got[test.want.field]) != json.Number(itoa(test.want.value)).String() {
			t.Errorf("%s: %s = %s, want %d (%s)", name, test.want.field, got[test.want.field], test.want.value, c.Body)
		}
		// Every other member survives, with its value untouched.
		var original map[string]json.RawMessage
		_ = json.Unmarshal([]byte(test.body), &original)
		for k, v := range original {
			if k != test.want.field && !bytes.Equal(got[k], v) {
				t.Errorf("%s: member %s changed from %s to %s", name, k, v, got[k])
			}
		}
	}
}

func itoa(v int64) string { b, _ := json.Marshal(v); return string(b) }

func TestRefusedRequests(t *testing.T) {
	msg := func(model, extra string) string {
		return `{"model":"` + model + `","max_tokens":100,"messages":[]` + extra + `}`
	}
	for name, test := range map[string]struct {
		api, body string
		status    int
		code      string
	}{
		"not an object":                  {effectargs.APIOpenAIChat, `[]`, 400, "invalid_json"},
		"not json":                       {effectargs.APIOpenAIChat, `{"model":`, 400, "invalid_json"},
		"trailing data":                  {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol"} {}`, 400, "invalid_json"},
		"a repeated key":                 {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","messages":[],"model":"gpt-6-sol"}`, 400, "invalid_json"},
		"no model":                       {effectargs.APIOpenAIChat, `{"messages":[]}`, 400, "missing_model"},
		"a model that is not a string":   {effectargs.APIOpenAIChat, `{"model":7}`, 400, "missing_model"},
		"an unknown model":               {effectargs.APIOpenAIChat, `{"model":"gpt-9"}`, 404, "model_not_found"},
		"a model of another api":         {effectargs.APIAnthropicMessages, msg("gpt-6-sol", ""), 404, "model_not_found"},
		"a zero maximum":                 {effectargs.APIAnthropicMessages, `{"model":"claude-sonnet-5-5","max_tokens":0,"messages":[]}`, 400, "invalid_max_tokens"},
		"a negative maximum":             {effectargs.APIAnthropicMessages, `{"model":"claude-sonnet-5-5","max_tokens":-5,"messages":[]}`, 400, "invalid_max_tokens"},
		"a fractional maximum":           {effectargs.APIAnthropicMessages, `{"model":"claude-sonnet-5-5","max_tokens":10.5,"messages":[]}`, 400, "invalid_max_tokens"},
		"a stream that is not a boolean": {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","stream":"yes"}`, 400, "invalid_stream"},

		// Provider-executed tools.
		"responses: web search":                              {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"type":"web_search_preview"}]}`, 400, "unsupported_tool"},
		"responses: web search dated":                        {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"type":"web_search_preview_2025_03_11"}]}`, 400, "unsupported_tool"},
		"responses: web search plain":                        {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"type":"web_search"}]}`, 400, "unsupported_tool"},
		"responses: file search":                             {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"type":"file_search","vector_store_ids":["v"]}]}`, 400, "unsupported_tool"},
		"responses: code interpreter":                        {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"type":"code_interpreter","container":{"type":"auto"}}]}`, 400, "unsupported_tool"},
		"responses: image generation":                        {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"type":"image_generation"}]}`, 400, "unsupported_tool"},
		"responses: remote mcp":                              {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"type":"mcp","server_label":"x","server_url":"https://x"}]}`, 400, "unsupported_tool"},
		"responses: an unknown tool type":                    {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"type":"future_hosted_thing"}]}`, 400, "unsupported_tool"},
		"responses: a hosted tool after a function":          {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"type":"function","name":"f"},{"type":"mcp"}]}`, 400, "unsupported_tool"},
		"responses: a tool with no type":                     {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"name":"f"}]}`, 400, "unsupported_tool"},
		"responses: a tool that is not an object":            {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":["web_search"]}`, 400, "invalid_tools"},
		"responses: tools that are not a list":               {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":{}}`, 400, "invalid_tools"},
		"responses: background":                              {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","background":true}`, 400, "unsupported_background"},
		"responses: a hosted tool_choice":                    {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tool_choice":{"type":"web_search_preview"}}`, 400, "unsupported_tool"},
		"responses: a hosted tool in allowed_tools":          {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"mcp"}]}}`, 400, "unsupported_tool"},
		"responses: a case-folded smuggle":                   {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"type":"mcp","TYPE":"function"}]}`, 400, "unsupported_tool"},
		"responses: a repeated tool key":                     {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"type":"function","type":"mcp"}]}`, 400, "invalid_json"},
		"chat: web_search_options":                           {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","web_search_options":{}}`, 400, "unsupported_tool"},
		"chat: a custom tool":                                {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","tools":[{"type":"custom","custom":{"name":"x"}}]}`, 400, "unsupported_tool"},
		"chat: n above one":                                  {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","n":2}`, 400, "unsupported_n"},
		"chat: n that is not an integer":                     {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","n":1.5}`, 400, "unsupported_n"},
		"chat: stream_options not an object":                 {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","stream":true,"stream_options":5}`, 400, "invalid_stream_options"},
		"chat: include_usage not a boolean":                  {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","stream":true,"stream_options":{"include_usage":"x"}}`, 400, "invalid_stream_options"},
		"messages: web search":                               {effectargs.APIAnthropicMessages, msg("claude-sonnet-5-5", `,"tools":[{"type":"web_search_20250305","name":"web_search"}]`), 400, "unsupported_tool"},
		"messages: web fetch":                                {effectargs.APIAnthropicMessages, msg("claude-sonnet-5-5", `,"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]`), 400, "unsupported_tool"},
		"messages: code execution":                           {effectargs.APIAnthropicMessages, msg("claude-sonnet-5-5", `,"tools":[{"type":"code_execution_20250825","name":"code_execution"}]`), 400, "unsupported_tool"},
		"messages: the mcp toolset":                          {effectargs.APIAnthropicMessages, msg("claude-sonnet-5-5", `,"tools":[{"type":"mcp_toolset","mcp_server_name":"x"}]`), 400, "unsupported_tool"},
		"messages: tool search":                              {effectargs.APIAnthropicMessages, msg("claude-sonnet-5-5", `,"tools":[{"type":"tool_search_tool_regex_20251119","name":"tool_search"}]`), 400, "unsupported_tool"},
		"messages: mcp_servers":                              {effectargs.APIAnthropicMessages, msg("claude-sonnet-5-5", `,"mcp_servers":[{"type":"url","url":"https://x","name":"x"}]`), 400, "unsupported_tool"},
		"messages: a code execution container":               {effectargs.APIAnthropicMessages, msg("claude-sonnet-5-5", `,"container":"container_1"`), 400, "unsupported_tool"},
		"messages: thinking budget at the maximum":           {effectargs.APIAnthropicMessages, `{"model":"claude-sonnet-5-5","max_tokens":1000,"messages":[],"thinking":{"type":"enabled","budget_tokens":1000}}`, 400, "thinking_budget_too_large"},
		"messages: thinking budget above the clamp":          {effectargs.APIAnthropicMessages, `{"model":"claude-haiku-4-5-20251001","max_tokens":999999,"messages":[],"thinking":{"type":"enabled","budget_tokens":32000}}`, 400, "thinking_budget_too_large"},
		"messages: thinking budget with the default maximum": {effectargs.APIAnthropicMessages, `{"model":"claude-haiku-4-5-20251001","messages":[],"thinking":{"type":"enabled","budget_tokens":5000}}`, 400, "thinking_budget_too_large"},
		"messages: a repeated thinking key":                  {effectargs.APIAnthropicMessages, `{"model":"claude-sonnet-5-5","max_tokens":9,"messages":[],"thinking":{"type":"disabled","type":"enabled"}}`, 400, "invalid_json"},
	} {
		c, err := inspectFor(t, test.api, test.body)
		if err == nil {
			t.Errorf("%s: accepted (%s)", name, c.Body)
			continue
		}
		if err.Status != test.status || err.Code != test.code {
			t.Errorf("%s: refused with %d %s (%s), want %d %s", name, err.Status, err.Code, err.Message, test.status, test.code)
		}
	}
}

func TestClientExecutedToolsPass(t *testing.T) {
	for name, test := range map[string]struct{ api, body string }{
		"messages: custom, typeless and client tools": {effectargs.APIAnthropicMessages, `{"model":"claude-sonnet-5-5","max_tokens":100,"messages":[],"tools":[
			{"name":"a","input_schema":{}},{"type":"custom","name":"b","input_schema":{}},{"type":"bash_20250124","name":"bash"},
			{"type":"text_editor_20250728","name":"str_replace_based_edit_tool"},{"type":"computer_20250124","name":"computer"},{"type":"memory_20250818","name":"memory"}],
			"mcp_servers":[],"container":null,"thinking":{"type":"enabled","budget_tokens":50}}`},
		"responses: function, custom, local_shell, apply_patch": {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tools":[{"type":"function","name":"f"},{"type":"custom","name":"c"},{"type":"local_shell"},{"type":"apply_patch"}],"tool_choice":{"type":"function","name":"f"},"background":false}`},
		"responses: tool_choice strings":                        {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tool_choice":"required"}`},
		"responses: allowed_tools of functions":                 {effectargs.APIOpenAIResponses, `{"model":"gpt-6-sol","tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"function","name":"f"}]}}`},
		"chat: function tools and n=1":                          {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","n":1,"tools":[{"type":"function","function":{"name":"f"}}],"tool_choice":{"type":"function","function":{"name":"f"}}}`},
		"chat: null tools":                                      {effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","tools":null,"web_search_options":null}`},
	} {
		if _, err := inspectFor(t, test.api, test.body); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

func TestChatStreamAsksForUsageAndStripsWhatTheClientDidNotAskFor(t *testing.T) {
	// A client that did not ask: the gateway asks, and will strip the chunk.
	c, err := inspectFor(t, effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","messages":[],"stream":true,"max_tokens":50}`)
	if err != nil {
		t.Fatal(err)
	}
	got := forwarded(t, c)
	if string(got["stream_options"]) != `{"include_usage":true}` || !c.DropChatUsage {
		t.Fatalf("stream_options = %s, drop = %v", got["stream_options"], c.DropChatUsage)
	}
	// Other stream options are kept.
	c, err = inspectFor(t, effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","messages":[],"stream":true,"max_tokens":50,"stream_options":{"include_obfuscation":false}}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := forwarded(t, c); string(got["stream_options"]) != `{"include_obfuscation":false,"include_usage":true}` || !c.DropChatUsage {
		t.Fatalf("stream_options = %s", got["stream_options"])
	}
	// include_usage false is asked for too, and stripped.
	c, err = inspectFor(t, effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","messages":[],"stream":true,"max_tokens":50,"stream_options":{"include_usage":false}}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := forwarded(t, c); string(got["stream_options"]) != `{"include_usage":true}` || !c.DropChatUsage {
		t.Fatalf("include_usage false: %s", got["stream_options"])
	}
	// A client that asked gets the chunk, and the request is untouched.
	c, err = inspectFor(t, effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","messages":[],"stream":true,"max_tokens":50,"stream_options":{"include_usage":true}}`)
	if err != nil || c.DropChatUsage || !strings.Contains(string(c.Body), `"include_usage":true`) {
		t.Fatalf("a client that asked: drop %v body %s err %v", c.DropChatUsage, c.Body, err)
	}
	// A request that does not stream needs nothing.
	c, err = inspectFor(t, effectargs.APIOpenAIChat, `{"model":"gpt-6-sol","messages":[],"max_tokens":50}`)
	if err != nil || c.DropChatUsage || strings.Contains(string(c.Body), "stream_options") {
		t.Fatalf("no stream: %s", c.Body)
	}
}

func TestACacheMarkerMakesTheQuoteCoverCacheWrites(t *testing.T) {
	c, err := inspectFor(t, effectargs.APIAnthropicMessages, `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"x","cache_control":{"type":"ephemeral"}}]}]}`)
	if err != nil || !c.MayWriteCache {
		t.Fatalf("cache marker: %v %v", c, err)
	}
	c, err = inspectFor(t, effectargs.APIAnthropicMessages, `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[]}`)
	if err != nil || c.MayWriteCache {
		t.Fatalf("no cache marker: %v %v", c, err)
	}
}

func TestRebuildKeepsOrderAndValuesAndEscapesKeys(t *testing.T) {
	fields, err := parseObject([]byte(`{"a": 1, "b":  {"x": [1, 2]}, "c\"d": "e"}`))
	if err != nil {
		t.Fatal(err)
	}
	out := rebuild(fields, map[string]json.RawMessage{"a": json.RawMessage("9"), "z": json.RawMessage("true")}, []string{"z"})
	if string(out) != `{"a":9,"b":{"x": [1, 2]},"c\"d":"e","z":true}` {
		t.Fatalf("rebuilt = %s", out)
	}
}
