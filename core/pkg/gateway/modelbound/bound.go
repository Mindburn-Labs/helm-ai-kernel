// Package modelbound reads a model request against the closed list of what a
// gateway's quote prices (helm-tracker#313). The quote counts each byte of the
// request as an input token, which bounds the tokens of text the request
// carries (a byte-level tokenizer never emits more tokens than bytes), and the
// output maximum the gateway forwards. What the list keeps but bytes do not
// bound is added to the input side of the quote as a token floor:
//
//   - an inline image bills by its pixels, not its bytes;
//   - Anthropic adds a tool-use system prompt to a request that declares
//     tools, and a hidden definition for each schema-less client tool;
//   - OpenAI adds a hidden definition for the local_shell and apply_patch
//     tools.
//
// Anything else is refused before any hold or dispatch, naming it: a member of
// the request, of a message, of an input item, of a content part, of a block
// or of a media source outside the list,
// stored state the provider would bill (a stored conversation, a stored
// prompt, an item named by its id alone), remote or uploaded media, tools the
// provider runs on its own account, members that change the billed model or
// the price tier, nested configuration outside the closed lists of reasoning,
// text, thinking, output_config and context_management, and, where the
// gateway prices no cache write (Options.CacheWrites), a prompt-cache write.
// Values the quote counts by their bytes are not read further: tool
// definitions, tool calls, JSON schemas, metadata and the like. Both model
// gateways read requests through this package: helm-gateway's model gateway
// (core/pkg/gateway/modelgw) and the governed OpenAI-compatible gateway the
// spend proxy serves (core/pkg/api.GovernedGateway).
//
// The quote is then an upper bound of what the provider can bill, at the
// route's price, under the assumptions docs/architecture/model-gateway.md
// lists: the provider honours the output maximum, its tokenizer emits at most
// one token per byte, its image and tool costs are at or under the floors, and
// the route's price is its highest for a request of the gateway's maximum size.
package modelbound

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// The APIs a request is read for. The first three are model.inference's; the
// governed gateway also serves OpenAI's embeddings.
const (
	APIOpenAIResponses   = effectargs.APIOpenAIResponses
	APIOpenAIChat        = effectargs.APIOpenAIChat
	APIAnthropicMessages = effectargs.APIAnthropicMessages
	APIOpenAIEmbeddings  = "openai-embeddings"
)

// Token floors. Each is at or above the most the provider documents for the
// item; a smaller real cost is settled from the reported usage.
const (
	// OpenAIImageTokens: OpenAI's most expensive documented image cost, a
	// high-detail image on gpt-4o-mini: 2,833 base tokens plus 5,667 for each
	// of at most 8 tiles of 512 px (an image is fitted into 2048 px and its
	// short side scaled to 768 px). The patch-based models bill less.
	OpenAIImageTokens = 2_833 + 8*5_667
	// AnthropicImageTokens: Anthropic scales an image down until it is at
	// most about 1,600 tokens (about 1.15 megapixels at width x height / 750).
	// The floor is five times that, so a model that accepts larger images
	// stays under it as well.
	AnthropicImageTokens = 8_000
	// AnthropicToolSystemTokens: the tool-use system prompt Anthropic adds
	// when a request declares tools. The documented maximum is 530 tokens.
	AnthropicToolSystemTokens = 600
	// HiddenToolTokens: a client tool whose definition the provider supplies
	// (Anthropic's bash_, text_editor_, computer_ and memory_ tools; OpenAI's
	// local_shell and apply_patch). The documented maximum is the computer
	// use tool, 735 tokens and a 499-token system prompt.
	HiddenToolTokens = 2_000
)

// Refusal is a request the quote cannot bound. Code is stable; Message names
// the member, item, part or block and says why.
type Refusal struct {
	Code    string
	Message string
}

// Options say what the upstream's own API defines.
type Options struct {
	// StandardTier: the upstream is the vendor's own API, whose standard
	// service tier is OpenAI's "default" or Anthropic's "standard_only". A
	// request that names no tier, or auto, is sent with it, because an absent
	// or auto tier bills at whatever tier the account defaults to, which can
	// be priority. On another upstream the tier's meaning is the upstream's,
	// so auto is refused and an absent tier is left absent.
	StandardTier bool
	// CacheWrites: the gateway prices a prompt-cache write and reads the
	// provider's cache-write usage (the model gateway's routes carry
	// cache-write prices). Without it a request that names cache_control at
	// any depth is refused: a cache write bills above the input price.
	CacheWrites bool
}

// Bound is what Check found in a request the quote can price.
type Bound struct {
	// ExtraInputTokens is what the provider can bill as input beyond one
	// token per request byte: the floors of inline images and of the tool
	// definitions the provider adds.
	ExtraInputTokens int64
	// Set holds the members to set in the forwarded request, in order: store
	// false for a Responses request that names no store, and the standard
	// service tier.
	Set []Field
}

// The members each API's quote understands. Any other non-null member is
// refused. Members with a refusal of their own are in refusedMembers.
var quotedMembers = map[string][]string{
	APIOpenAIResponses: {
		"model", "input", "instructions", "max_output_tokens", "stream", "stream_options", "temperature", "top_p",
		"top_logprobs", "tools", "tool_choice", "parallel_tool_calls", "max_tool_calls", "reasoning", "text",
		"include", "metadata", "user", "safety_identifier", "prompt_cache_key", "prompt_cache_retention",
		"service_tier", "truncation", "store", "background",
	},
	APIOpenAIChat: {
		"model", "messages", "max_tokens", "max_completion_tokens", "stream", "stream_options", "temperature",
		"top_p", "n", "stop", "presence_penalty", "frequency_penalty", "logit_bias", "logprobs", "top_logprobs",
		"seed", "user", "safety_identifier", "prompt_cache_key", "prompt_cache_retention", "response_format",
		"tools", "tool_choice", "parallel_tool_calls", "functions", "function_call", "reasoning_effort",
		"verbosity", "metadata", "store", "service_tier", "modalities", "web_search_options",
	},
	APIAnthropicMessages: {
		"model", "messages", "max_tokens", "system", "stream", "temperature", "top_p", "top_k", "stop_sequences",
		"metadata", "tools", "tool_choice", "thinking", "context_management", "service_tier", "output_config",
		"output_format", "mcp_servers", "container",
	},
	APIOpenAIEmbeddings: {"model", "input", "encoding_format", "dimensions", "user"},
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

// standardTiers are each API's tiers billed at the route's standard price
// (flex is cheaper), and the tier StandardTier names. Priority and scale are
// billed above it.
var standardTiers = map[string]struct {
	allowed []string
	name    string
}{
	APIOpenAIResponses:   {[]string{"default", "flex"}, "default"},
	APIOpenAIChat:        {[]string{"default", "flex"}, "default"},
	APIAnthropicMessages: {[]string{"standard_only"}, "standard_only"},
}

func unquoted(code, format string, args ...any) *Refusal {
	return &Refusal{Code: code, Message: fmt.Sprintf(format, args...) + "; the gateway refuses a request whose provider bill its hold might not cover"}
}

func memberRefusal(name, why string) *Refusal {
	return unquoted("unsupported_member", "the request member %q %s", name, why)
}

func hostedRefusal(what string) *Refusal {
	return &Refusal{Code: "unsupported_tool", Message: what + " runs on the provider's account, outside this gateway's authority: use a function tool the agent runs itself, through the gateway's tools"}
}

// bounder walks a request's content against the closed lists and counts what
// the quote adds as token floors.
type bounder struct {
	api          string
	standardTier bool
	images       int64
	hiddenTools  int64
	toolPrompt   bool
}

// CheckBody parses body as one JSON object, refuses a key repeated at any
// depth, and checks it with Check. The Bound is never nil.
func CheckBody(api string, body []byte, opts Options) ([]Field, *Bound, *Refusal) {
	fields, err := ParseObject(body)
	if err != nil {
		return nil, &Bound{}, &Refusal{Code: "invalid_json", Message: err.Error()}
	}
	if err := CheckNoDuplicateKeys(body); err != nil {
		return fields, &Bound{}, &Refusal{Code: "invalid_json", Message: "the request body " + err.Error()}
	}
	bound, refusal := Check(api, fields, opts)
	return fields, bound, refusal
}

// Check refuses what the quote of a request with these top-level members
// cannot see, and returns the floors of what it keeps and the members to set
// in the forwarded request. The caller has refused keys repeated at any depth.
// The Bound is never nil; with a refusal it is empty.
func Check(api string, fields []Field, opts Options) (*Bound, *Refusal) {
	names, known := quotedMembers[api]
	if !known {
		return &Bound{}, &Refusal{Code: "unsupported_api", Message: fmt.Sprintf("the gateway reads no %q requests", api)}
	}
	if !opts.CacheWrites {
		if e := cacheWrite(fields); e != nil {
			return &Bound{}, e
		}
	}
	if e := hostedTools(api, fields); e != nil {
		return &Bound{}, e
	}
	b := &bounder{api: api, standardTier: opts.StandardTier}
	for _, f := range fields {
		if IsNull(f.Raw) {
			continue // every API reads a null member as absent
		}
		if why, refused := refusedMembers[f.Key]; refused {
			return &Bound{}, memberRefusal(f.Key, why)
		}
		if !slices.Contains(names, f.Key) {
			return &Bound{}, memberRefusal(f.Key, "is not one the gateway's quote understands")
		}
		if e := b.member(f.Key, f.Raw); e != nil {
			return &Bound{}, e
		}
	}
	bound := &Bound{}
	switch {
	case api == APIAnthropicMessages:
		bound.ExtraInputTokens = b.images * AnthropicImageTokens
	default:
		bound.ExtraInputTokens = b.images * OpenAIImageTokens
	}
	bound.ExtraInputTokens += b.hiddenTools * HiddenToolTokens
	if b.toolPrompt {
		bound.ExtraInputTokens += AnthropicToolSystemTokens
	}
	if api == APIOpenAIResponses {
		if raw, ok := Lookup(fields, "store"); !ok || IsNull(raw) {
			bound.Set = append(bound.Set, Field{Key: "store", Raw: json.RawMessage("false")})
		}
	}
	if tier, has := standardTiers[api]; has && opts.StandardTier {
		raw, ok := Lookup(fields, "service_tier")
		name, _ := String(raw)
		if !ok || IsNull(raw) || name == "auto" {
			bound.Set = append(bound.Set, Field{Key: "service_tier", Raw: json.RawMessage(`"` + tier.name + `"`)})
		}
	}
	return bound, nil
}

// cacheWrite refuses a request that names cache_control at any depth, in any
// spelling of the key (the decoder unescapes it): the provider would bill a
// cache write above the input price the hold is quoted at, and the gateway
// reads no cache-write usage to settle it.
func cacheWrite(fields []Field) *Refusal {
	for _, f := range fields {
		found := f.Key == "cache_control"
		_ = WalkKeys(json.NewDecoder(bytes.NewReader(f.Raw)), func(key string) {
			found = found || key == "cache_control"
		})
		if found {
			return unquoted("unsupported_member", "the request member %q carries cache_control: a prompt-cache write is billed above the input price, and this gateway's price book has no cache-write price", f.Key)
		}
	}
	return nil
}

// closedMembers refuses a member of obj that is not in allowed; a null member
// is absent.
func closedMembers(obj map[string]json.RawMessage, where string, allowed ...string) *Refusal {
	for _, key := range sortedKeys(obj) {
		if !IsNull(obj[key]) && !slices.Contains(allowed, key) {
			return unquoted("unsupported_content", "%s has the member %q, which the gateway's quote does not understand", where, key)
		}
	}
	return nil
}

// member checks one top-level member's value.
func (b *bounder) member(name string, raw json.RawMessage) *Refusal {
	switch name {
	case "stream":
		var stream bool
		if json.Unmarshal(raw, &stream) != nil {
			return &Refusal{Code: "invalid_stream", Message: "stream must be a boolean"}
		}
	case "instructions":
		if _, isString := String(raw); !isString {
			return memberRefusal("instructions", "must be a string: a list of instructions carries items and media the gateway does not read there")
		}
	case "store":
		var store bool
		if json.Unmarshal(raw, &store) != nil || store {
			return memberRefusal("store", "must be false: a stored response can be billed again by reference, which the gateway does not serve")
		}
	case "service_tier":
		return b.serviceTier(raw)
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
		if b.api == APIOpenAIEmbeddings {
			return embeddingsInput(raw)
		}
		return b.responsesInput(raw)
	case "messages":
		if b.api == APIOpenAIChat {
			return b.chatMessages(raw)
		}
		return b.anthropicMessages(raw)
	case "system":
		return b.anthropicContent(raw, "system")
	case "tools":
		b.countTools(raw)
	case "reasoning":
		return closedObject("reasoning", raw, map[string]func(json.RawMessage, string) *Refusal{
			"effort": isString, "summary": isString, "generate_summary": isString,
		})
	case "text":
		return closedObject("text", raw, map[string]func(json.RawMessage, string) *Refusal{
			"verbosity": isString, "format": outputFormat("text", "json_object", "json_schema"),
		})
	case "thinking":
		return closedObject("thinking", raw, map[string]func(json.RawMessage, string) *Refusal{
			"type": oneOf("enabled", "disabled", "adaptive"), "budget_tokens": isInteger, "display": isString,
		})
	case "output_config":
		return closedObject("output_config", raw, map[string]func(json.RawMessage, string) *Refusal{
			"effort": isString, "format": outputFormat("json_schema"),
		})
	case "output_format":
		return outputFormat("json_schema")(raw, "output_format")
	case "context_management":
		return contextManagement(raw)
	}
	return nil
}

// serviceTier admits the tiers billed at the route's standard price, and
// auto where it is sent as the standard tier (Options.StandardTier).
func (b *bounder) serviceTier(raw json.RawMessage) *Refusal {
	tier, _ := String(raw)
	standard := standardTiers[b.api]
	if slices.Contains(standard.allowed, tier) || (tier == "auto" && b.standardTier) {
		return nil
	}
	return memberRefusal("service_tier", fmt.Sprintf("is %s, which can bill at a tier the route's price does not carry (allowed: %s)",
		strings.TrimSpace(string(raw)), strings.Join(standard.allowed, ", ")))
}

// closedObject checks that raw is an object whose members are all in members,
// each passing its check.
func closedObject(where string, raw json.RawMessage, members map[string]func(json.RawMessage, string) *Refusal) *Refusal {
	obj, ok := Object(raw)
	if !ok {
		return unquoted("invalid_content", "%s must be an object", where)
	}
	for _, key := range sortedKeys(obj) {
		value := obj[key]
		if IsNull(value) {
			continue
		}
		check, known := members[key]
		if !known {
			return unquoted("unsupported_member", "%s has the member %q, which the gateway's quote does not understand", where, key)
		}
		if e := check(value, where+"."+key); e != nil {
			return e
		}
	}
	return nil
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func anything(json.RawMessage, string) *Refusal { return nil }

func isString(raw json.RawMessage, where string) *Refusal {
	if _, ok := String(raw); !ok {
		return unquoted("invalid_content", "%s must be a string", where)
	}
	return nil
}

func isInteger(raw json.RawMessage, where string) *Refusal {
	if _, ok := IntOf(raw); !ok {
		return unquoted("invalid_content", "%s must be an integer", where)
	}
	return nil
}

func oneOf(values ...string) func(json.RawMessage, string) *Refusal {
	return func(raw json.RawMessage, where string) *Refusal {
		value, _ := String(raw)
		if !slices.Contains(values, value) {
			return unquoted("unsupported_content", "%s is %s, which the gateway's quote does not understand (allowed: %s)",
				where, strings.TrimSpace(string(raw)), strings.Join(values, ", "))
		}
		return nil
	}
}

// outputFormat checks a structured-output format: a type from types and the
// members that describe its schema.
func outputFormat(types ...string) func(json.RawMessage, string) *Refusal {
	return func(raw json.RawMessage, where string) *Refusal {
		return closedObject(where, raw, map[string]func(json.RawMessage, string) *Refusal{
			"type": oneOf(types...), "name": isString, "description": isString, "schema": anything, "strict": anything,
		})
	}
}

// contextManagement admits only the edits that remove content from the
// context: clearing tool uses and clearing thinking. Compaction runs an extra
// sampling pass the output maximum does not bound and is refused, as is any
// edit type the gateway does not know.
func contextManagement(raw json.RawMessage) *Refusal {
	return closedObject("context_management", raw, map[string]func(json.RawMessage, string) *Refusal{
		"edits": func(raw json.RawMessage, where string) *Refusal {
			edits, e := list(raw, where)
			if e != nil {
				return e
			}
			for i, edit := range edits {
				at := fmt.Sprintf("%s[%d]", where, i)
				obj, ok := Object(edit)
				if !ok {
					return unquoted("invalid_content", "%s must be an object", at)
				}
				kind, _ := String(obj["type"])
				if !strings.HasPrefix(kind, "clear_tool_uses_") && !strings.HasPrefix(kind, "clear_thinking_") {
					return unquoted("unsupported_content", "%s has the edit type %q: only edits that clear content (clear_tool_uses_*, clear_thinking_*) are billed within the hold", at, kind)
				}
				if e := closedObject(at, edit, map[string]func(json.RawMessage, string) *Refusal{
					"type": isString, "trigger": anything, "keep": anything, "clear_at_least": anything,
					"exclude_tools": anything, "clear_tool_inputs": anything,
				}); e != nil {
					return e
				}
			}
			return nil
		},
	})
}

// countTools records the hidden tool definitions a provider adds. The tool
// types themselves were checked by hostedTools.
func (b *bounder) countTools(raw json.RawMessage) {
	var tools []json.RawMessage
	if json.Unmarshal(raw, &tools) != nil || len(tools) == 0 {
		return
	}
	if b.api == APIAnthropicMessages {
		b.toolPrompt = true
	}
	for _, t := range tools {
		tool, _ := Object(t)
		kind, _ := String(tool["type"])
		switch {
		case b.api == APIAnthropicMessages && kind != "" && kind != "custom":
			b.hiddenTools++ // bash_, text_editor_, computer_, memory_
		case b.api == APIOpenAIResponses && (kind == "local_shell" || kind == "apply_patch"):
			b.hiddenTools++
		}
	}
}

func list(raw json.RawMessage, where string) ([]json.RawMessage, *Refusal) {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil, unquoted("invalid_content", "%s must be a list", where)
	}
	return items, nil
}

// inlineImage reports whether url is an inline image: a data: URL of an image
// media type. A remote URL is fetched and billed by the provider at a size the
// quote cannot see, and another media type (video, audio) bills by duration.
func inlineImage(url string) bool { return strings.HasPrefix(url, "data:image/") }

// Hosted tools ---------------------------------------------------------------

// hostedTools refuses what the provider would execute on its own account:
// hosted tools, a tool_choice that names one, Chat's web_search_options and
// n other than 1, Anthropic's MCP servers and code execution container, and
// a Responses background run.
func hostedTools(api string, fields []Field) *Refusal {
	switch api {
	case APIOpenAIResponses:
		if raw, ok := Lookup(fields, "background"); ok && !IsNull(raw) {
			var background bool
			if json.Unmarshal(raw, &background) != nil {
				return &Refusal{Code: "invalid_background", Message: "background must be a boolean"}
			}
			if background {
				return &Refusal{Code: "unsupported_background", Message: "background responses run on the provider after the connection closes, so the gateway could not settle them"}
			}
		}
		if e := clientTools(fields, responsesToolAllowed, false); e != nil {
			return e
		}
		return choiceRefusal(fields, responsesToolAllowed)
	case APIOpenAIChat:
		if raw, ok := Lookup(fields, "n"); ok && !IsNull(raw) {
			if n, isInt := IntOf(raw); !isInt || n != 1 {
				return &Refusal{Code: "unsupported_n", Message: `the request member "n" must be 1: the gateway settles one completion per call`}
			}
		}
		if raw, ok := Lookup(fields, "web_search_options"); ok && !IsNull(raw) {
			return hostedRefusal("web_search_options")
		}
		chatTool := func(t string) bool { return t == "function" }
		if e := clientTools(fields, chatTool, false); e != nil {
			return e
		}
		return choiceRefusal(fields, chatTool)
	case APIAnthropicMessages:
		if raw, ok := Lookup(fields, "mcp_servers"); ok && !IsNull(raw) {
			var servers []json.RawMessage
			if json.Unmarshal(raw, &servers) != nil || len(servers) > 0 {
				return hostedRefusal("mcp_servers")
			}
		}
		if raw, ok := Lookup(fields, "container"); ok && !IsNull(raw) {
			return hostedRefusal("a code execution container")
		}
		return clientTools(fields, messagesToolAllowed, true)
	}
	return nil
}

// responsesToolAllowed: the tool types the Responses API runs on the client's
// side, a call the agent executes and reports back. Every other type
// (web_search*, file_search, code_interpreter, image_generation, mcp, computer
// and the rest) is provider-executed and refused.
func responsesToolAllowed(t string) bool {
	return slices.Contains([]string{"function", "custom", "local_shell", "apply_patch"}, t)
}

// messagesToolAllowed: a client tool is a custom tool (no type, or "custom")
// or one of Anthropic's schema-less client tools, which the agent runs itself.
// Server tools (web_search_*, web_fetch_*, code_execution_*, the MCP toolset
// and tool search) run on Anthropic's account and are refused.
func messagesToolAllowed(t string) bool {
	if t == "custom" {
		return true
	}
	for _, prefix := range []string{"bash_", "text_editor_", "computer_", "memory_"} {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}

// clientTools reads the tools member and refuses any tool whose type is not
// allowed. A tool with no type is a custom tool where allowMissing is set, and
// a refusal elsewhere.
func clientTools(fields []Field, allowed func(toolType string) bool, allowMissing bool) *Refusal {
	raw, ok := Lookup(fields, "tools")
	if !ok || IsNull(raw) {
		return nil
	}
	var tools []json.RawMessage
	if json.Unmarshal(raw, &tools) != nil {
		return &Refusal{Code: "invalid_tools", Message: "tools must be a list"}
	}
	for i, t := range tools {
		tool, ok := Object(t)
		if !ok {
			return &Refusal{Code: "invalid_tools", Message: fmt.Sprintf("tools[%d] must be an object", i)}
		}
		rawType, has := tool["type"]
		toolType, isString := String(rawType)
		switch {
		case !has || IsNull(rawType):
			if !allowMissing {
				return hostedRefusal(fmt.Sprintf("tools[%d] (no type)", i))
			}
		case !isString || !allowed(toolType):
			return hostedRefusal(fmt.Sprintf("the tool type %s", strings.TrimSpace(string(rawType))))
		}
	}
	return nil
}

// choiceRefusal refuses a tool_choice that selects a tool the gateway would
// have refused in tools, so a choice cannot name what tools may not.
func choiceRefusal(fields []Field, allowed func(toolType string) bool) *Refusal {
	raw, ok := Lookup(fields, "tool_choice")
	if !ok || IsNull(raw) {
		return nil
	}
	choice, ok := Object(raw)
	if !ok {
		return nil // a string such as "auto" or "required"
	}
	rawType, has := choice["type"]
	if !has {
		return nil
	}
	toolType, isString := String(rawType)
	if !isString {
		return hostedRefusal("this tool_choice")
	}
	if toolType == "allowed_tools" {
		return clientTools([]Field{{Key: "tools", Raw: choice["tools"]}}, allowed, false)
	}
	if !allowed(toolType) {
		return hostedRefusal("the tool_choice " + toolType)
	}
	return nil
}

// OpenAI Responses ----------------------------------------------------------

// responsesItemMembers are the members each input item type may have.
var responsesItemMembers = map[string][]string{
	"message":                 {"type", "id", "role", "content", "status"},
	"function_call":           {"type", "id", "call_id", "name", "arguments", "status"},
	"function_call_output":    {"type", "id", "call_id", "output", "status"},
	"custom_tool_call":        {"type", "id", "call_id", "name", "input", "status"},
	"custom_tool_call_output": {"type", "id", "call_id", "output"},
	"local_shell_call":        {"type", "id", "call_id", "action", "status"},
	"local_shell_call_output": {"type", "id", "output", "status"},
	"apply_patch_call":        {"type", "id", "call_id", "operation", "status"},
	"apply_patch_call_output": {"type", "id", "call_id", "output", "status"},
	"reasoning":               {"type", "id", "summary", "content", "encrypted_content", "status"},
}

// responsesItems are the input item types the quote understands: messages and
// the calls and outputs of client-executed tools, which the request carries in
// full, and reasoning items, whose encrypted content it carries. carried names
// the members an item must carry when it also names an id: without them the
// provider fills the item in from storage and bills what the quote never saw.
var responsesItems = map[string][]string{
	"message":                 {"content"},
	"function_call":           {"call_id", "name", "arguments"},
	"function_call_output":    {"call_id", "output"},
	"custom_tool_call":        {"call_id", "name", "input"},
	"custom_tool_call_output": {"call_id", "output"},
	"local_shell_call":        {"call_id", "action"},
	"local_shell_call_output": {"output"},
	"apply_patch_call":        {"call_id", "operation"},
	"apply_patch_call_output": {"call_id"},
	"reasoning":               {"encrypted_content"},
}

func (b *bounder) responsesInput(raw json.RawMessage) *Refusal {
	if _, isString := String(raw); isString {
		return nil
	}
	items, e := list(raw, "input")
	if e != nil {
		return e
	}
	for i, item := range items {
		where := fmt.Sprintf("input[%d]", i)
		obj, ok := Object(item)
		if !ok {
			return unquoted("invalid_content", "%s must be an object", where)
		}
		kind, _ := String(obj["type"])
		if kind == "" {
			kind = "message"
		}
		carried, known := responsesItems[kind]
		switch {
		case kind == "item_reference":
			return unquoted("unsupported_content", "%s is an item_reference: it names a stored item the provider expands, which the quote cannot count", where)
		case !known:
			return unquoted("unsupported_content", "%s has the item type %q, which the gateway's quote does not understand", where, kind)
		}
		if e := storedByID(obj, where, kind, carried); e != nil {
			return e
		}
		if e := closedMembers(obj, where, responsesItemMembers[kind]...); e != nil {
			return e
		}
		switch kind {
		case "message":
			if e := b.responsesContent(obj["content"], where+".content"); e != nil {
				return e
			}
		case "function_call_output", "custom_tool_call_output":
			if e := b.responsesContent(obj["output"], where+".output"); e != nil {
				return e
			}
		}
	}
	return nil
}

// storedByID refuses an input item that leaves to the provider what it bills
// for: a reasoning item without its encrypted content, and an item that names
// an id without carrying its content (an empty message is no content).
func storedByID(obj map[string]json.RawMessage, where, kind string, carried []string) *Refusal {
	if kind == "reasoning" {
		if content, _ := String(obj["encrypted_content"]); content == "" {
			return unquoted("unsupported_content", "%s is a reasoning item without encrypted_content: the provider would bill the stored reasoning it names, which the quote cannot see; send it with include reasoning.encrypted_content and store false", where)
		}
		return nil
	}
	id := obj["id"]
	if absent(id) {
		return nil
	}
	name, _ := String(id)
	for _, member := range carried {
		value := obj[member]
		if absent(value) || emptyContent(value) {
			return unquoted("unsupported_content", "%s names the stored item %q by its id without carrying its %s: the provider would bill the stored item, which the quote cannot see", where, name, member)
		}
	}
	return nil
}

// emptyContent reports an empty string or an empty list.
func emptyContent(raw json.RawMessage) bool {
	if s, ok := String(raw); ok {
		return s == ""
	}
	var items []json.RawMessage
	return json.Unmarshal(raw, &items) == nil && len(items) == 0
}

// responsesContent checks a message's content or a tool output: a string, or
// a list of text and inline image parts.
func (b *bounder) responsesContent(raw json.RawMessage, where string) *Refusal {
	if absent(raw) {
		return nil
	}
	if _, isString := String(raw); isString {
		return nil
	}
	parts, e := list(raw, where)
	if e != nil {
		return e
	}
	for i, p := range parts {
		at := fmt.Sprintf("%s[%d]", where, i)
		part, ok := Object(p)
		if !ok {
			return unquoted("invalid_content", "%s must be an object", at)
		}
		kind, _ := String(part["type"])
		switch kind {
		case "input_text", "summary_text", "reasoning_text":
			if e := closedMembers(part, at, "type", "text"); e != nil {
				return e
			}
		case "output_text":
			if e := closedMembers(part, at, "type", "text", "annotations", "logprobs"); e != nil {
				return e
			}
		case "refusal":
			if e := closedMembers(part, at, "type", "refusal"); e != nil {
				return e
			}
		case "input_image":
			if raw, has := part["file_id"]; has && !IsNull(raw) {
				return unquoted("unsupported_content", "%s names an uploaded image by file_id, which the quote cannot size", at)
			}
			if e := closedMembers(part, at, "type", "image_url", "detail"); e != nil {
				return e
			}
			url, _ := String(part["image_url"])
			if !inlineImage(url) {
				return unquoted("unsupported_content", "%s.image_url must be an inline data:image/ URL; a remote image is fetched and billed by the provider at a size the quote cannot see, and other media bill by their duration", at)
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

func (b *bounder) chatMessages(raw json.RawMessage) *Refusal {
	messages, e := list(raw, "messages")
	if e != nil {
		return e
	}
	for i, m := range messages {
		where := fmt.Sprintf("messages[%d]", i)
		msg, ok := Object(m)
		members, err := ParseObject(m)
		if !ok || err != nil {
			return unquoted("invalid_content", "%s must be an object", where)
		}
		for _, member := range members {
			key := member.Key
			if IsNull(member.Raw) {
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

func (b *bounder) chatContent(raw json.RawMessage, where string) *Refusal {
	if absent(raw) {
		return nil
	}
	if _, isString := String(raw); isString {
		return nil
	}
	parts, e := list(raw, where)
	if e != nil {
		return e
	}
	for i, p := range parts {
		at := fmt.Sprintf("%s[%d]", where, i)
		part, ok := Object(p)
		if !ok {
			return unquoted("invalid_content", "%s must be an object", at)
		}
		kind, _ := String(part["type"])
		switch kind {
		case "text":
			if e := closedMembers(part, at, "type", "text", "cache_control"); e != nil {
				return e
			}
		case "refusal":
			if e := closedMembers(part, at, "type", "refusal"); e != nil {
				return e
			}
		case "image_url":
			if e := closedMembers(part, at, "type", "image_url", "cache_control"); e != nil {
				return e
			}
			url, isString := String(part["image_url"])
			if !isString {
				image, _ := Object(part["image_url"])
				if e := closedMembers(image, at+".image_url", "url", "detail"); e != nil {
					return e
				}
				url, _ = String(image["url"])
			}
			if !inlineImage(url) {
				return unquoted("unsupported_content", "%s.image_url.url must be an inline data:image/ URL; a remote image is fetched and billed by the provider at a size the quote cannot see, and other media bill by their duration", at)
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

// OpenAI embeddings ---------------------------------------------------------

// embeddingsInput admits a string, a list of strings, a list of token ids or a
// list of token-id lists: each is billed by the tokens it carries, which its
// bytes bound. Anything else (an image, an object) is refused.
func embeddingsInput(raw json.RawMessage) *Refusal {
	if _, ok := String(raw); ok {
		return nil
	}
	var strs []string
	if json.Unmarshal(raw, &strs) == nil {
		return nil
	}
	var ids []int64
	if json.Unmarshal(raw, &ids) == nil {
		return nil
	}
	var idLists [][]int64
	if json.Unmarshal(raw, &idLists) == nil {
		return nil
	}
	return unquoted("unsupported_content", "input must be a string, a list of strings or a list of token ids for an embedding the quote can count")
}

// Anthropic Messages --------------------------------------------------------

func (b *bounder) anthropicMessages(raw json.RawMessage) *Refusal {
	messages, e := list(raw, "messages")
	if e != nil {
		return e
	}
	for i, m := range messages {
		where := fmt.Sprintf("messages[%d]", i)
		msg, ok := Object(m)
		if !ok {
			return unquoted("invalid_content", "%s must be an object", where)
		}
		if e := closedMembers(msg, where, "role", "content"); e != nil {
			return e
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
func (b *bounder) anthropicContent(raw json.RawMessage, where string) *Refusal {
	if absent(raw) {
		return nil
	}
	if _, isString := String(raw); isString {
		return nil
	}
	blocks, e := list(raw, where)
	if e != nil {
		return e
	}
	for i, bl := range blocks {
		at := fmt.Sprintf("%s[%d]", where, i)
		block, ok := Object(bl)
		if !ok {
			return unquoted("invalid_content", "%s must be an object", at)
		}
		kind, _ := String(block["type"])
		if members, known := anthropicBlockMembers[kind]; known {
			if e := closedMembers(block, at, members...); e != nil {
				return e
			}
		}
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
			if e := citations(block["citations"], at); e != nil {
				return e
			}
			if e := b.anthropicSource(block["source"], at, "document"); e != nil {
				return e
			}
		default:
			return unquoted("unsupported_content", "%s has the content block type %q, which the gateway's quote does not understand", at, kind)
		}
	}
	return nil
}

// anthropicBlockMembers are the members each content block type may have.
var anthropicBlockMembers = map[string][]string{
	"text":              {"type", "text", "cache_control", "citations"},
	"tool_use":          {"type", "id", "name", "input", "cache_control"},
	"tool_result":       {"type", "tool_use_id", "content", "is_error", "cache_control"},
	"thinking":          {"type", "thinking", "signature"},
	"redacted_thinking": {"type", "data"},
	"image":             {"type", "source", "cache_control"},
	"document":          {"type", "source", "title", "context", "citations", "cache_control"},
}

// citations refuses a document with citations enabled: Anthropic splits it
// into chunks and bills tokens for the chunking that the document's bytes do
// not bound.
func citations(raw json.RawMessage, at string) *Refusal {
	if absent(raw) {
		return nil
	}
	var c struct {
		Enabled *bool `json:"enabled"`
	}
	if json.Unmarshal(raw, &c) != nil || (c.Enabled != nil && *c.Enabled) {
		return unquoted("unsupported_content", "%s.citations is enabled: Anthropic bills tokens for chunking a cited document that its bytes do not bound", at)
	}
	return nil
}

// anthropicSource checks an image or document source: an inline image is
// counted at its floor; a text document, or a content document of blocks, is
// carried in the request; a PDF (base64), a URL and an uploaded file are
// refused.
func (b *bounder) anthropicSource(raw json.RawMessage, at, kind string) *Refusal {
	source, ok := Object(raw)
	if !ok {
		return unquoted("invalid_content", "%s.source must be an object", at)
	}
	sourceType, _ := String(source["type"])
	switch {
	case kind == "image" && sourceType == "base64":
		if e := closedMembers(source, at+".source", "type", "media_type", "data"); e != nil {
			return e
		}
		b.images++
		return nil
	case kind == "document" && sourceType == "text":
		return closedMembers(source, at+".source", "type", "media_type", "data")
	case kind == "document" && sourceType == "content":
		if e := closedMembers(source, at+".source", "type", "content"); e != nil {
			return e
		}
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

// anthropicBetas are the anthropic-beta values the quote is known to bound:
// they change how a request is streamed, cached or which client tools it may
// declare, not what Anthropic bills beyond the request's bytes, the floors and
// the output maximum. Any other beta is refused, naming it.
var anthropicBetas = map[string]bool{
	"claude-code-20250219":                     true,
	"oauth-2025-04-20":                         true,
	"interleaved-thinking-2025-05-14":          true,
	"fine-grained-tool-streaming-2025-05-14":   true,
	"token-efficient-tools-2025-02-19":         true,
	"context-management-2025-06-27":            true,
	"prompt-caching-2024-07-31":                true,
	"extended-cache-ttl-2025-04-11":            true,
	"output-128k-2025-02-19":                   true,
	"computer-use-2024-10-22":                  true,
	"computer-use-2025-01-24":                  true,
	"computer-use-2025-11-24":                  true,
	"structured-outputs-2025-11-13":            true,
	"effort-2025-11-24":                        true,
	"model-context-window-exceeded-2025-08-26": true,
}

// AnthropicBetas lists the anthropic-beta values BetaRefusal admits, sorted.
func AnthropicBetas() []string {
	out := make([]string, 0, len(anthropicBetas))
	for beta := range anthropicBetas {
		out = append(out, beta)
	}
	slices.Sort(out)
	return out
}

// BetaRefusal refuses an anthropic-beta outside the allowlist, in any of the
// request's anthropic-beta header lines. Among the betas it refuses are
// context-1m (a long request billed at a premium), compaction (an extra
// sampling pass), the Files API, MCP servers and code execution.
func BetaRefusal(api string, h http.Header) *Refusal {
	if api != APIAnthropicMessages {
		return nil
	}
	for _, value := range h.Values("Anthropic-Beta") {
		for _, beta := range strings.Split(value, ",") {
			if beta = strings.TrimSpace(beta); beta != "" && !anthropicBetas[beta] {
				return unquoted("unsupported_beta", "the anthropic-beta %q is not one the gateway's quote is known to bound (allowed: %s)", beta, strings.Join(AnthropicBetas(), ", "))
			}
		}
	}
	return nil
}
