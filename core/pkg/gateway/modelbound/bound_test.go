package modelbound

import (
	"strings"
	"testing"
)

const tinyPNG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="

func check(t *testing.T, api, body string) (*Bound, *Refusal) {
	t.Helper()
	_, bound, refusal := CheckBody(api, []byte(body), Options{})
	return bound, refusal
}

// TestFloorsArePinned (helm-tracker#313 r2, mutant N40): each floor is the
// value the docs state, and Check adds it once per item it counts.
func TestFloorsArePinned(t *testing.T) {
	for name, test := range map[string]struct {
		got, want int64
	}{
		"OpenAIImageTokens":         {OpenAIImageTokens, 48_169},
		"AnthropicImageTokens":      {AnthropicImageTokens, 8_000},
		"AnthropicToolSystemTokens": {AnthropicToolSystemTokens, 600},
		"HiddenToolTokens":          {HiddenToolTokens, 2_000},
	} {
		if test.got != test.want {
			t.Errorf("%s = %d, want %d", name, test.got, test.want)
		}
	}
	for name, test := range map[string]struct {
		api, body string
		extra     int64
	}{
		"messages: a custom tool": {APIAnthropicMessages,
			`{"model":"m","max_tokens":1,"tools":[{"name":"f","input_schema":{"type":"object"}}],"messages":[{"role":"user","content":"x"}]}`, 600},
		"messages: a custom and a bash tool": {APIAnthropicMessages,
			`{"model":"m","max_tokens":1,"tools":[{"name":"f","input_schema":{}},{"type":"bash_20250124","name":"bash"}],"messages":[{"role":"user","content":"x"}]}`, 600 + 2_000},
		"messages: two images": {APIAnthropicMessages,
			`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="}},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="}}]}]}`, 2 * 8_000},
		"chat: an image": {APIOpenAIChat,
			`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"` + tinyPNG + `"}}]}]}`, 48_169},
		"responses: local_shell": {APIOpenAIResponses,
			`{"model":"m","max_output_tokens":1,"input":"ls","tools":[{"type":"local_shell"}]}`, 2_000},
		"chat: text only": {APIOpenAIChat, `{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"x"}]}`, 0},
	} {
		bound, refusal := check(t, test.api, test.body)
		if refusal != nil {
			t.Errorf("%s: refused: %s", name, refusal.Message)
			continue
		}
		if bound.ExtraInputTokens != test.extra {
			t.Errorf("%s: extra input tokens %d, want %d", name, bound.ExtraInputTokens, test.extra)
		}
	}
}

// TestPartItemAndBlockMembersAreClosed (finding 8): a member of a content
// part, an input item, a message block, a block source or an image URL object
// that the list does not name is refused, naming it, and Responses
// instructions is a string.
func TestPartItemAndBlockMembersAreClosed(t *testing.T) {
	for name, test := range map[string]struct{ api, body, member string }{
		"responses: input_text with file_id": {APIOpenAIResponses,
			`{"model":"m","max_output_tokens":1,"input":[{"role":"user","content":[{"type":"input_text","text":"x","file_id":"file-1"}]}]}`, "file_id"},
		"responses: input_image with a file": {APIOpenAIResponses,
			`{"model":"m","max_output_tokens":1,"input":[{"role":"user","content":[{"type":"input_image","image_url":"` + tinyPNG + `","file":"f"}]}]}`, `"file"`},
		"responses: a message with an unknown member": {APIOpenAIResponses,
			`{"model":"m","max_output_tokens":1,"input":[{"role":"user","content":"x","attachments":["file-1"]}]}`, "attachments"},
		"responses: a function call output with an unknown member": {APIOpenAIResponses,
			`{"model":"m","max_output_tokens":1,"input":[{"type":"function_call_output","call_id":"c","output":"ok","file_ids":["f"]}]}`, "file_ids"},
		"responses: a reasoning item with an unknown member": {APIOpenAIResponses,
			`{"model":"m","max_output_tokens":1,"input":[{"type":"reasoning","encrypted_content":"e","summary":[],"stored_ref":"r"}]}`, "stored_ref"},
		"responses: instructions as a list": {APIOpenAIResponses,
			`{"model":"m","max_output_tokens":1,"instructions":[{"role":"developer","content":[{"type":"input_image","image_url":"https://x.test/a.png"}]}],"input":"x"}`, "instructions"},
		"chat: a text part with a file": {APIOpenAIChat,
			`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"text","text":"x","file":{"file_id":"file-1"}}]}]}`, `"file"`},
		"chat: an image_url object with an unknown member": {APIOpenAIChat,
			`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"` + tinyPNG + `","file_id":"f"}}]}]}`, "file_id"},
		"messages: a message with an unknown member": {APIAnthropicMessages,
			`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"x","container_upload":"f"}]}`, "container_upload"},
		"messages: a text block with an unknown member": {APIAnthropicMessages,
			`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"text","text":"x","file_id":"f"}]}]}`, "file_id"},
		"messages: a tool_result with an unknown member": {APIAnthropicMessages,
			`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":"ok","source":{"type":"url","url":"https://x.test"}}]}]}`, "source"},
		"messages: a base64 source with an unknown member": {APIAnthropicMessages,
			`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA==","url":"https://x.test/a.png"}}]}]}`, "url"},
		"messages: a system block with an unknown member": {APIAnthropicMessages,
			`{"model":"m","max_tokens":1,"system":[{"type":"text","text":"x","document_id":"d"}],"messages":[]}`, "document_id"},
	} {
		_, refusal := check(t, test.api, test.body)
		if refusal == nil || !strings.Contains(refusal.Message, test.member) {
			t.Errorf("%s: refusal %v, want one naming %s", name, refusal, test.member)
		}
	}
}

// TestStreamMustBeABoolean: a stream the gateway reads as false but the
// provider reads otherwise is refused, as the model gateway refuses it.
func TestStreamMustBeABoolean(t *testing.T) {
	if _, refusal := check(t, APIOpenAIChat, `{"model":"m","max_tokens":1,"stream":"true","messages":[{"role":"user","content":"x"}]}`); refusal == nil || refusal.Code != "invalid_stream" {
		t.Fatalf("a string stream: %v", refusal)
	}
	if _, refusal := check(t, APIOpenAIChat, `{"model":"m","max_tokens":1,"stream":false,"messages":[{"role":"user","content":"x"}]}`); refusal != nil {
		t.Fatalf("stream false: %v", refusal)
	}
}
