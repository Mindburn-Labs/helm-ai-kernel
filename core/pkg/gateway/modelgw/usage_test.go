package modelgw

import (
	"strings"
	"testing"
)

func TestBodyUsagePerAPI(t *testing.T) {
	for name, test := range map[string]struct {
		api, body string
		want      *Usage
	}{
		"anthropic with a cache breakdown": {"anthropic-messages",
			`{"id":"msg_1","usage":{"input_tokens":25,"cache_creation_input_tokens":10,"cache_read_input_tokens":200,"cache_creation":{"ephemeral_5m_input_tokens":4,"ephemeral_1h_input_tokens":6},"output_tokens":15}}`,
			&Usage{InputTokens: 25, CacheReadTokens: 200, CacheWrite5mTokens: 4, CacheWrite1hTokens: 6, OutputTokens: 15}},
		"anthropic without a breakdown counts writes at the short lifetime": {"anthropic-messages",
			`{"usage":{"input_tokens":25,"cache_creation_input_tokens":10,"output_tokens":15}}`,
			&Usage{InputTokens: 25, CacheWrite5mTokens: 10, OutputTokens: 15}},
		"anthropic with a breakdown short of the total": {"anthropic-messages",
			`{"usage":{"input_tokens":1,"cache_creation_input_tokens":10,"cache_creation":{"ephemeral_5m_input_tokens":4,"ephemeral_1h_input_tokens":3},"output_tokens":1}}`,
			&Usage{InputTokens: 1, CacheWrite5mTokens: 7, CacheWrite1hTokens: 3, OutputTokens: 1}},
		"openai chat with cached tokens": {"openai-chat",
			`{"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_tokens_details":{"cached_tokens":40}}}`,
			&Usage{InputTokens: 60, CacheReadTokens: 40, OutputTokens: 20}},
		"openai chat without details": {"openai-chat",
			`{"usage":{"prompt_tokens":100,"completion_tokens":20}}`, &Usage{InputTokens: 100, OutputTokens: 20}},
		"a cached count above the prompt is not believed": {"openai-chat",
			`{"usage":{"prompt_tokens":10,"completion_tokens":2,"prompt_tokens_details":{"cached_tokens":99}}}`, &Usage{InputTokens: 10, OutputTokens: 2}},
		"openai responses": {"openai-responses",
			`{"id":"resp_1","usage":{"input_tokens":50,"output_tokens":30,"total_tokens":80,"input_tokens_details":{"cached_tokens":10},"output_tokens_details":{"reasoning_tokens":12}}}`,
			&Usage{InputTokens: 40, CacheReadTokens: 10, OutputTokens: 30}},
		"no usage":       {"openai-chat", `{"choices":[]}`, nil},
		"null usage":     {"openai-chat", `{"usage":null}`, nil},
		"an empty usage": {"anthropic-messages", `{"usage":{}}`, nil},
		"not json":       {"openai-chat", `nope`, nil},
	} {
		got := parseBodyUsage(test.api, []byte(test.body))
		switch {
		case test.want == nil && got != nil:
			t.Errorf("%s: usage = %+v, want none", name, got.Usage)
		case test.want != nil && (got == nil || got.Usage != *test.want):
			t.Errorf("%s: usage = %+v, want %+v", name, got, *test.want)
		case test.want != nil && !strings.HasPrefix(string(got.Raw), "{"):
			t.Errorf("%s: the usage is kept as reported: %q", name, got.Raw)
		}
	}
}

// track feeds a raw stream through the splitter and the tracker.
func track(t *testing.T, api, stream string) *streamTracker {
	t.Helper()
	r := newSSEReader(strings.NewReader(stream), 1<<20)
	tr := newStreamTracker(api)
	for {
		ev, err := r.Next()
		if err != nil {
			return tr
		}
		tr.observe(ev)
	}
}

func TestStreamTrackerAnthropic(t *testing.T) {
	stream := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"usage\":{\"input_tokens\":25,\"cache_read_input_tokens\":100,\"output_tokens\":1}}}\n\n" +
		"event: ping\ndata: {\"type\": \"ping\"}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":15}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	tr := track(t, "anthropic-messages", stream)
	u := tr.usage()
	if !tr.done || tr.providerError || u == nil || u.Usage != (Usage{InputTokens: 25, CacheReadTokens: 100, OutputTokens: 15}) {
		t.Fatalf("done %v error %v usage %+v", tr.done, tr.providerError, u)
	}
	// Cut before message_stop: not done, but what was reported is kept.
	cut := track(t, "anthropic-messages", stream[:strings.Index(stream, "event: message_stop")])
	if cut.done || cut.usage() == nil || cut.usage().OutputTokens != 15 {
		t.Fatalf("a cut stream: done %v usage %+v", cut.done, cut.usage())
	}
	// An error event in the stream.
	failed := track(t, "anthropic-messages", "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n")
	if !failed.providerError || failed.done || failed.usage() != nil {
		t.Fatalf("an error event: %+v", failed)
	}
	// A stream with no usage events reports none.
	if bare := track(t, "anthropic-messages", "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"); bare.usage() != nil || !bare.done {
		t.Fatalf("a bare stop: %+v", bare)
	}
}

func TestStreamTrackerOpenAIChat(t *testing.T) {
	stream := "data: {\"id\":\"c\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n" +
		"data: {\"id\":\"c\",\"choices\":[],\"usage\":{\"prompt_tokens\":30,\"completion_tokens\":5,\"prompt_tokens_details\":{\"cached_tokens\":10}}}\n\n" +
		"data: [DONE]\n\n"
	tr := track(t, "openai-chat", stream)
	if u := tr.usage(); !tr.done || u == nil || u.Usage != (Usage{InputTokens: 20, CacheReadTokens: 10, OutputTokens: 5}) {
		t.Fatalf("done %v usage %+v", tr.done, u)
	}
	// Without include_usage there is no usage, and the stream is still complete.
	if bare := track(t, "openai-chat", "data: {\"choices\":[{\"delta\":{}}]}\n\ndata: [DONE]\n\n"); !bare.done || bare.usage() != nil {
		t.Fatalf("no usage: %+v", bare)
	}
	if e := track(t, "openai-chat", "data: {\"error\":{\"message\":\"boom\"}}\n\n"); !e.providerError {
		t.Fatal("an error chunk was not noticed")
	}
}

func TestChatUsageOnlyChunk(t *testing.T) {
	for chunk, want := range map[string]bool{
		`{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`:                          true,
		`{"usage":{"prompt_tokens":1,"completion_tokens":1}}`:                                       true,
		`{"choices":null,"usage":{"prompt_tokens":1,"completion_tokens":1}}`:                        true,
		`{"choices":[{"delta":{"content":"x"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`: false,
		`{"choices":[],"usage":null}`:                                                               false,
		`{"choices":[{"delta":{"content":"x"}}]}`:                                                   false,
		`not json`: false,
		`[DONE]`:   false,
	} {
		if got := isChatUsageOnly([]byte(chunk)); got != want {
			t.Errorf("isChatUsageOnly(%s) = %v, want %v", chunk, got, want)
		}
	}
}

func TestStreamTrackerOpenAIResponses(t *testing.T) {
	completed := "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"r\"}}\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n" +
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"usage\":{\"input_tokens\":50,\"output_tokens\":30,\"input_tokens_details\":{\"cached_tokens\":10}}}}\n\n"
	tr := track(t, "openai-responses", completed)
	if u := tr.usage(); !tr.done || tr.providerError || u == nil || u.Usage != (Usage{InputTokens: 40, CacheReadTokens: 10, OutputTokens: 30}) {
		t.Fatalf("done %v usage %+v", tr.done, u)
	}
	// The events carry their type in the data too, for a stream with no event: lines.
	unnamed := "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\n\n"
	if tr := track(t, "openai-responses", unnamed); !tr.done || tr.usage() == nil {
		t.Fatalf("an unnamed completed event: %+v", tr)
	}
	failed := "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"usage\":null,\"error\":{\"message\":\"x\"}}}\n\n"
	if tr := track(t, "openai-responses", failed); !tr.done || !tr.providerError || tr.usage() != nil {
		t.Fatalf("a failed response: %+v", tr)
	}
	if cut := track(t, "openai-responses", completed[:strings.Index(completed, "event: response.completed")]); cut.done {
		t.Fatal("a stream cut before completion is done")
	}
}
