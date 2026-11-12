package modelgw

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// The quote is a bound only for what it can see (helm-tracker#313, audit H6).
// It counts each byte of the request as an input token, which bounds the
// tokens of text the request carries (a byte-level tokenizer never emits more
// tokens than bytes), and the clamped output maximum. A request is therefore
// read against a closed list of what the quote understands, per API: a member,
// an input item, a content part or a media source outside it is refused before
// any attempt exists, naming it. What the list keeps but bytes do not bound is
// added to the input side of the quote as a token floor:
//
//   - an inline image bills by its pixels, not its bytes;
//   - Anthropic adds a tool-use system prompt to a request that declares
//     tools, and a hidden definition for each schema-less client tool;
//   - OpenAI adds a hidden definition for the local_shell and apply_patch
//     tools.
//
// The route's price must be the provider's price for the largest request the
// gateway's limits allow (a provider that charges more above a context length
// needs that price), and the provider must honour the output maximum.

// Token floors. Each is at or above the most the provider documents for the
// item; a smaller real cost is settled from the reported usage.
const (
	// openAIImageTokens: OpenAI's most expensive documented image cost, a
	// high-detail image on gpt-4o-mini: 2,833 base tokens plus 5,667 for each
	// of at most 8 tiles of 512 px (an image is fitted into 2048 px and its
	// short side scaled to 768 px). The patch-based models bill less.
	openAIImageTokens = 2_833 + 8*5_667
	// anthropicImageTokens: Anthropic scales an image down until it is at most
	// about 1,600 tokens (about 1.15 megapixels at width x height / 750). The
	// floor is five times that, so a model that accepts larger images stays
	// under it as well.
	anthropicImageTokens = 8_000
	// anthropicToolSystemTokens: the tool-use system prompt Anthropic adds
	// when a request declares tools. The documented maximum is 530 tokens.
	anthropicToolSystemTokens = 600
	// hiddenToolTokens: a client tool whose definition the provider supplies
	// (Anthropic's bash_, text_editor_, computer_ and memory_ tools; OpenAI's
	// local_shell and apply_patch). The documented maximum is the computer
	// use tool, 735 tokens and a 499-token system prompt.
	hiddenToolTokens = 2_000
)

// The members each API's quote understands. Any other non-null member is
// refused. Members with a refusal of their own are in refusedMembers.
var quotedMembers = map[string][]string{
	effectargs.APIOpenAIResponses: {
		"model", "input", "instructions", "max_output_tokens", "stream", "stream_options", "temperature", "top_p",
		"top_logprobs", "tools", "tool_choice", "parallel_tool_calls", "max_tool_calls", "reasoning", "text",
		"include", "metadata", "user", "safety_identifier", "prompt_cache_key", "prompt_cache_retention",
		"service_tier", "truncation", "store", "background",
	},
	effectargs.APIOpenAIChat: {
		"model", "messages", "max_tokens", "max_completion_tokens", "stream", "stream_options", "temperature",
		"top_p", "n", "stop", "presence_penalty", "frequency_penalty", "logit_bias", "logprobs", "top_logprobs",
		"seed", "user", "safety_identifier", "prompt_cache_key", "prompt_cache_retention", "response_format",
		"tools", "tool_choice", "parallel_tool_calls", "functions", "function_call", "reasoning_effort",
		"verbosity", "metadata", "store", "service_tier", "modalities", "web_search_options",
	},
	effectargs.APIAnthropicMessages: {
		"model", "messages", "max_tokens", "system", "stream", "temperature", "top_p", "top_k", "stop_sequences",
		"metadata", "tools", "tool_choice", "thinking", "context_management", "service_tier", "output_config",
		"output_format", "mcp_servers", "container",
	},
}

// refusedMembers are members the quote cannot price, with the reason.
var refusedMembers = map[string]string{
	"previous_response_id": "makes the provider bill a stored conversation the request does not carry, which the quote cannot count",
	"conversation":         "makes the provider bill a stored conversation the request does not carry, which the quote cannot count",
	"prompt":               "names a stored prompt the provider expands on its side, which the quote cannot count",
	"models":               "lets the upstream fall back to another model than the quoted route",
	"provider":             "lets the upstream choose the provider that bills the call",
	"plugins":              "adds upstream features billed outside the quoted route",
	"route":                "lets the upstream route the call to another model than the quoted route",
	"prediction":           "bills rejected prediction tokens the output maximum does not bound",
	"audio":                "requests audio, billed at audio prices the route does not carry",
	"speed":                "selects a faster mode billed at a premium the route's price does not carry",
	"inference_geo":        "selects regional inference billed at a premium the route's price does not carry",
}

// serviceTiers are the service_tier values billed at the route's standard
// price (flex is cheaper). Priority and scale are billed above it.
var serviceTiers = map[string][]string{
	effectargs.APIOpenAIResponses:   {"auto", "default", "flex"},
	effectargs.APIOpenAIChat:        {"auto", "default", "flex"},
	effectargs.APIAnthropicMessages: {"auto", "standard_only"},
}

func unquoted(code, format string, args ...any) *apiError {
	return refuse(http.StatusBadRequest, kindInvalidRequest, code, fmt.Sprintf(format, args...)+"; the gateway refuses a request whose provider bill its hold might not cover")
}

func memberRefusal(name, why string) *apiError {
	return unquoted("unsupported_member", "the request member %q %s", name, why)
}

// bounder walks a request's content against the closed lists and counts what
// the quote adds as token floors.
type bounder struct {
	api         string
	images      int64
	hiddenTools int64
	toolPrompt  bool
}

// boundRequest refuses what the quote of c cannot see and sets
// c.ExtraInputTokens to the floors of what it keeps.
func boundRequest(c *call, fields []field) *apiError {
	b := &bounder{api: c.API}
	allowed := map[string]bool{}
	for _, name := range quotedMembers[c.API] {
		allowed[name] = true
	}
	for _, f := range fields {
		if isNull(f.Raw) {
			continue // every API reads a null member as absent
		}
		if why, refused := refusedMembers[f.Key]; refused {
			return memberRefusal(f.Key, why)
		}
		if !allowed[f.Key] {
			return memberRefusal(f.Key, "is not one the gateway's quote understands")
		}
		if e := b.member(f.Key, f.Raw); e != nil {
			return e
		}
	}
	extra := b.images * openAIImageTokens
	if c.API == effectargs.APIAnthropicMessages {
		extra = b.images * anthropicImageTokens
	}
	extra += b.hiddenTools * hiddenToolTokens
	if b.toolPrompt {
		extra += anthropicToolSystemTokens
	}
	c.ExtraInputTokens = extra
	return nil
}

// member checks one top-level member's value.
func (b *bounder) member(name string, raw json.RawMessage) *apiError {
	switch name {
	case "store":
		var store bool
		if json.Unmarshal(raw, &store) != nil || store {
			return memberRefusal("store", "must be false: a stored response can be billed again by reference, which the gateway does not serve")
		}
	case "service_tier":
		tier, _ := stringOf(raw)
		for _, ok := range serviceTiers[b.api] {
			if tier == ok {
				return nil
			}
		}
		return memberRefusal("service_tier", fmt.Sprintf("is %s, which bills at a tier the route's price does not carry (allowed: %s)",
			strings.TrimSpace(string(raw)), strings.Join(serviceTiers[b.api], ", ")))
	case "modalities":
		var modalities []string
		if json.Unmarshal(raw, &modalities) != nil {
			return memberRefusal("modalities", "must be a list of strings")
		}
		for _, m := range modalities {
			if m != "text" {
				return memberRefusal("modalities", fmt.Sprintf("names %q; only text output is billed at the route's price", m))
			}
		}
	case "input":
		return b.responsesInput(raw)
	case "messages":
		if b.api == effectargs.APIOpenAIChat {
			return b.chatMessages(raw)
		}
		return b.anthropicMessages(raw)
	case "system":
		return b.anthropicContent(raw, "system")
	case "tools":
		b.countTools(raw)
	}
	return nil
}

// countTools records the hidden tool definitions a provider adds. The tool
// types themselves were checked by clientTools.
func (b *bounder) countTools(raw json.RawMessage) {
	var tools []json.RawMessage
	if json.Unmarshal(raw, &tools) != nil || len(tools) == 0 {
		return
	}
	if b.api == effectargs.APIAnthropicMessages {
		b.toolPrompt = true
	}
	for _, t := range tools {
		tool, _ := object(t)
		kind, _ := stringOf(tool["type"])
		switch {
		case b.api == effectargs.APIAnthropicMessages && kind != "" && kind != "custom":
			b.hiddenTools++ // bash_, text_editor_, computer_, memory_
		case b.api == effectargs.APIOpenAIResponses && (kind == "local_shell" || kind == "apply_patch"):
			b.hiddenTools++
		}
	}
}

func list(raw json.RawMessage, where string) ([]json.RawMessage, *apiError) {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil, unquoted("invalid_content", "%s must be a list", where)
	}
	return items, nil
}

// OpenAI Responses ----------------------------------------------------------

// responsesItems are the input item types the quote understands: messages and
// the calls and outputs of client-executed tools, which the request carries in
// full, and reasoning items, whose encrypted content it carries.
var responsesItems = map[string]bool{
	"message": true, "function_call": true, "function_call_output": true, "custom_tool_call": true,
	"custom_tool_call_output": true, "local_shell_call": true, "local_shell_call_output": true,
	"apply_patch_call": true, "apply_patch_call_output": true, "reasoning": true,
}

func (b *bounder) responsesInput(raw json.RawMessage) *apiError {
	if _, isString := stringOf(raw); isString {
		return nil
	}
	items, e := list(raw, "input")
	if e != nil {
		return e
	}
	for i, item := range items {
		where := fmt.Sprintf("input[%d]", i)
		obj, ok := object(item)
		if !ok {
			return unquoted("invalid_content", "%s must be an object", where)
		}
		kind, _ := stringOf(obj["type"])
		if kind == "" {
			kind = "message"
		}
		switch {
		case kind == "item_reference":
			return unquoted("unsupported_content", "%s is an item_reference: it names a stored item the provider expands, which the quote cannot count", where)
		case !responsesItems[kind]:
			return unquoted("unsupported_content", "%s has the item type %q, which the gateway's quote does not understand", where, kind)
		case kind == "message":
			if e := b.responsesContent(obj["content"], where+".content"); e != nil {
				return e
			}
		case kind == "function_call_output" || kind == "custom_tool_call_output":
			if e := b.responsesContent(obj["output"], where+".output"); e != nil {
				return e
			}
		}
	}
	return nil
}

// responsesContent checks a message's content or a tool output: a string, or
// a list of text and inline image parts.
func (b *bounder) responsesContent(raw json.RawMessage, where string) *apiError {
	if len(raw) == 0 || isNull(raw) {
		return nil
	}
	if _, isString := stringOf(raw); isString {
		return nil
	}
	parts, e := list(raw, where)
	if e != nil {
		return e
	}
	for i, p := range parts {
		at := fmt.Sprintf("%s[%d]", where, i)
		part, ok := object(p)
		if !ok {
			return unquoted("invalid_content", "%s must be an object", at)
		}
		kind, _ := stringOf(part["type"])
		switch kind {
		case "input_text", "output_text", "refusal", "summary_text", "reasoning_text":
		case "input_image":
			if raw, has := part["file_id"]; has && !isNull(raw) {
				return unquoted("unsupported_content", "%s names an uploaded image by file_id, which the quote cannot size", at)
			}
			url, _ := stringOf(part["image_url"])
			if !strings.HasPrefix(url, "data:") {
				return unquoted("unsupported_content", "%s.image_url must be an inline data: URL; a remote image is fetched and billed by the provider at a size the quote cannot see", at)
			}
			b.images++
		case "input_file":
			return unquoted("unsupported_content", "%s is an input_file: a file is billed by its pages and their images, which its bytes do not bound", at)
		default:
			return unquoted("unsupported_content", "%s has the content type %q, which the gateway's quote does not understand", at, kind)
		}
	}
	return nil
}

// OpenAI Chat Completions ---------------------------------------------------

// chatMessageMembers are the message members the quote understands.
var chatMessageMembers = map[string]bool{
	"role": true, "content": true, "name": true, "tool_calls": true, "tool_call_id": true,
	"function_call": true, "refusal": true,
}

func (b *bounder) chatMessages(raw json.RawMessage) *apiError {
	messages, e := list(raw, "messages")
	if e != nil {
		return e
	}
	for i, m := range messages {
		where := fmt.Sprintf("messages[%d]", i)
		msg, ok := object(m)
		members, err := parseObject(m)
		if !ok || err != nil {
			return unquoted("invalid_content", "%s must be an object", where)
		}
		for _, member := range members {
			key := member.Key
			if isNull(member.Raw) {
				continue
			}
			if key == "audio" {
				return unquoted("unsupported_content", "%s.audio names a stored audio reply the provider expands, which the quote cannot count", where)
			}
			if !chatMessageMembers[key] {
				return unquoted("unsupported_content", "%s has the member %q, which the gateway's quote does not understand", where, key)
			}
		}
		if e := b.chatContent(msg["content"], where+".content"); e != nil {
			return e
		}
	}
	return nil
}

func (b *bounder) chatContent(raw json.RawMessage, where string) *apiError {
	if len(raw) == 0 || isNull(raw) {
		return nil
	}
	if _, isString := stringOf(raw); isString {
		return nil
	}
	parts, e := list(raw, where)
	if e != nil {
		return e
	}
	for i, p := range parts {
		at := fmt.Sprintf("%s[%d]", where, i)
		part, ok := object(p)
		if !ok {
			return unquoted("invalid_content", "%s must be an object", at)
		}
		kind, _ := stringOf(part["type"])
		switch kind {
		case "text", "refusal":
		case "image_url":
			url, isString := stringOf(part["image_url"])
			if !isString {
				image, _ := object(part["image_url"])
				url, _ = stringOf(image["url"])
			}
			if !strings.HasPrefix(url, "data:") {
				return unquoted("unsupported_content", "%s.image_url.url must be an inline data: URL; a remote image is fetched and billed by the provider at a size the quote cannot see", at)
			}
			b.images++
		case "input_audio":
			return unquoted("unsupported_content", "%s is input_audio, billed at audio prices the route does not carry", at)
		case "file":
			return unquoted("unsupported_content", "%s is a file: a file is billed by its pages and their images, which its bytes do not bound", at)
		default:
			return unquoted("unsupported_content", "%s has the content type %q, which the gateway's quote does not understand", at, kind)
		}
	}
	return nil
}

// Anthropic Messages --------------------------------------------------------

func (b *bounder) anthropicMessages(raw json.RawMessage) *apiError {
	messages, e := list(raw, "messages")
	if e != nil {
		return e
	}
	for i, m := range messages {
		where := fmt.Sprintf("messages[%d]", i)
		msg, ok := object(m)
		if !ok {
			return unquoted("invalid_content", "%s must be an object", where)
		}
		if e := b.anthropicContent(msg["content"], where+".content"); e != nil {
			return e
		}
	}
	return nil
}

// anthropicContent checks a string or a list of content blocks: text, inline
// images, text documents, client tool calls and results, and thinking. Server
// tool blocks, uploads and anything else are refused.
func (b *bounder) anthropicContent(raw json.RawMessage, where string) *apiError {
	if len(raw) == 0 || isNull(raw) {
		return nil
	}
	if _, isString := stringOf(raw); isString {
		return nil
	}
	blocks, e := list(raw, where)
	if e != nil {
		return e
	}
	for i, bl := range blocks {
		at := fmt.Sprintf("%s[%d]", where, i)
		block, ok := object(bl)
		if !ok {
			return unquoted("invalid_content", "%s must be an object", at)
		}
		kind, _ := stringOf(block["type"])
		switch kind {
		case "text", "tool_use", "thinking", "redacted_thinking":
		case "tool_result":
			if e := b.anthropicContent(block["content"], at+".content"); e != nil {
				return e
			}
		case "image":
			if e := b.anthropicSource(block["source"], at, "image"); e != nil {
				return e
			}
		case "document":
			if e := b.anthropicSource(block["source"], at, "document"); e != nil {
				return e
			}
		default:
			return unquoted("unsupported_content", "%s has the content block type %q, which the gateway's quote does not understand", at, kind)
		}
	}
	return nil
}

// anthropicSource checks an image or document source: an inline image is
// counted at its floor; a text document, or a content document of blocks, is
// carried in the request; a PDF (base64), a URL and an uploaded file are
// refused.
func (b *bounder) anthropicSource(raw json.RawMessage, at, kind string) *apiError {
	source, ok := object(raw)
	if !ok {
		return unquoted("invalid_content", "%s.source must be an object", at)
	}
	sourceType, _ := stringOf(source["type"])
	switch {
	case kind == "image" && sourceType == "base64":
		b.images++
		return nil
	case kind == "document" && sourceType == "text":
		return nil
	case kind == "document" && sourceType == "content":
		return b.anthropicContent(source["content"], at+".source.content")
	case sourceType == "url":
		return unquoted("unsupported_content", "%s is a %s with the source type \"url\": the provider fetches and bills it at a size the quote cannot see", at, kind)
	case sourceType == "file":
		return unquoted("unsupported_content", "%s is a %s with the source type \"file\": it names an uploaded file the quote cannot size", at, kind)
	case kind == "document" && sourceType == "base64":
		return unquoted("unsupported_content", "%s is a document with the source type \"base64\": a PDF is billed by its pages and their images, which its bytes do not bound", at)
	default:
		return unquoted("unsupported_content", "%s is a %s with the source type %q, which the gateway's quote does not understand", at, kind, sourceType)
	}
}

// anthropicBetaRefusal refuses a beta that bills the call above the route's
// price: context-1m bills a long request at a premium.
func anthropicBetaRefusal(api string, h http.Header) *apiError {
	if api != effectargs.APIAnthropicMessages {
		return nil
	}
	for _, value := range h.Values("Anthropic-Beta") {
		for _, beta := range strings.Split(value, ",") {
			if beta = strings.TrimSpace(beta); strings.HasPrefix(beta, "context-1m") {
				return unquoted("unsupported_beta", "the anthropic-beta %q bills a long request at a premium the route's price does not carry", beta)
			}
		}
	}
	return nil
}
