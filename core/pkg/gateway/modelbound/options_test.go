package modelbound

import (
	"strings"
	"testing"
)

// TestCacheWritesNeedTheOption (helm-tracker#313 r2, finding 6): a gateway
// whose price book carries no cache-write price (the spend proxy's) refuses a
// request that asks the provider to write a prompt cache, in any spelling of
// the key at any depth; a gateway that prices writes sets Options.CacheWrites.
func TestCacheWritesNeedTheOption(t *testing.T) {
	for name, test := range map[string]struct{ api, body string }{
		"chat: a text part":        {APIOpenAIChat, `{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]}`},
		"chat: an escaped key":     {APIOpenAIChat, `{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"text","text":"x","\u0063ache_control":{"type":"ephemeral"}}]}]}`},
		"messages: a tool":         {APIAnthropicMessages, `{"model":"m","max_tokens":1,"tools":[{"name":"f","input_schema":{},"cache_control":{"type":"ephemeral"}}],"messages":[]}`},
		"messages: a system block": {APIAnthropicMessages, `{"model":"m","max_tokens":1,"system":[{"type":"text","text":"s","cache_control":{"type":"ephemeral"}}],"messages":[]}`},
	} {
		if _, _, refusal := CheckBody(test.api, []byte(test.body), Options{}); refusal == nil || !strings.Contains(refusal.Message, "cache_control") {
			t.Errorf("%s without cache prices: %v, want a refusal naming cache_control", name, refusal)
		}
		if _, _, refusal := CheckBody(test.api, []byte(test.body), Options{CacheWrites: true}); refusal != nil {
			t.Errorf("%s with cache prices: refused: %s", name, refusal.Message)
		}
	}
}

// TestKnownMembersPass (finding 8): what the providers document for each
// part, item and block still passes.
func TestKnownMembersPass(t *testing.T) {
	for name, test := range map[string]struct{ api, body string }{
		"responses: a Codex-shaped history": {APIOpenAIResponses, `{"model":"m","max_output_tokens":1,"instructions":"be brief","input":[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"},{"type":"input_image","image_url":"` + tinyPNG + `","detail":"low"}]},
			{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"s"}],"content":[{"type":"reasoning_text","text":"r"}],"encrypted_content":"e","status":"completed"},
			{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":"ok","annotations":[],"logprobs":[]},{"type":"refusal","refusal":"no"}]},
			{"type":"function_call","id":"fc_1","call_id":"c1","name":"f","arguments":"{}","status":"completed"},
			{"type":"function_call_output","id":"fco_1","call_id":"c1","output":"done","status":"completed"},
			{"type":"custom_tool_call","id":"ct_1","call_id":"c2","name":"g","input":"x","status":"completed"},
			{"type":"custom_tool_call_output","call_id":"c2","output":"y"},
			{"type":"local_shell_call","id":"ls_1","call_id":"c3","action":{"type":"exec","command":["ls"]},"status":"completed"},
			{"type":"local_shell_call_output","id":"ls_1","output":"a","status":"completed"},
			{"type":"apply_patch_call","id":"ap_1","call_id":"c4","operation":{"type":"update_file","path":"a","diff":"d"},"status":"completed"},
			{"type":"apply_patch_call_output","id":"apo_1","call_id":"c4","status":"completed","output":"ok"}
		]}`},
		"chat: parts and members": {APIOpenAIChat, `{"model":"m","max_tokens":1,"messages":[
			{"role":"system","content":"s","name":"n"},
			{"role":"user","content":[{"type":"text","text":"x"},{"type":"image_url","image_url":{"url":"` + tinyPNG + `","detail":"high"}}]},
			{"role":"assistant","content":[{"type":"refusal","refusal":"no"}],"tool_calls":[{"id":"t","type":"function","function":{"name":"f","arguments":"{}"}}]},
			{"role":"tool","tool_call_id":"t","content":"ok"}
		]}`},
		"messages: blocks and sources": {APIAnthropicMessages, `{"model":"m","max_tokens":1,"system":[{"type":"text","text":"s","cache_control":{"type":"ephemeral"}}],"messages":[
			{"role":"user","content":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","ttl":"1h"}},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="},"cache_control":{"type":"ephemeral"}},
				{"type":"document","source":{"type":"text","media_type":"text/plain","data":"d"},"title":"t","context":"c","citations":{"enabled":false},"cache_control":{"type":"ephemeral"}}]},
			{"role":"assistant","content":[{"type":"thinking","thinking":"t","signature":"sig"},{"type":"redacted_thinking","data":"r"},{"type":"text","text":"x","citations":[]},{"type":"tool_use","id":"tu","name":"f","input":{},"cache_control":{"type":"ephemeral"}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu","content":[{"type":"text","text":"ok"}],"is_error":false,"cache_control":{"type":"ephemeral"}}]}
		]}`},
	} {
		if _, _, refusal := CheckBody(test.api, []byte(test.body), Options{CacheWrites: true}); refusal != nil {
			t.Errorf("%s: refused: %s", name, refusal.Message)
		}
	}
}
