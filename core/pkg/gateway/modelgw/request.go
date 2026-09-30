package modelgw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// call is a model request the gateway accepted: what it will send, what it
// will quote and how it will read the answer. Body is the request as the
// provider will get it, which is the client's request byte for byte except
// the maximum output tokens the gateway clamped or injected (and, for a
// streamed chat request that did not ask for usage, the include_usage option
// the gateway adds so that it can settle, whose extra final chunk it strips
// from the stream).
type call struct {
	API             string
	Route           *Route
	Stream          bool
	Body            []byte
	MaxOutputTokens int64
	// MayWriteCache: the request carries a cache_control marker, so the
	// provider may bill cache writes.
	MayWriteCache bool
	// DropChatUsage: strip the usage-only chunk the gateway asked for.
	DropChatUsage bool
}

// field is one member of a JSON object, in order, with its value untouched.
type field struct {
	Key string
	Raw json.RawMessage
}

// parseObject reads body as exactly one JSON object and returns its members
// in order. A repeated key is refused, and so is anything after the object:
// encoding/json would resolve a duplicate silently while a provider's parser
// may resolve it the other way, and what the gateway inspects must be what the
// provider executes.
func parseObject(body []byte) ([]field, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("the request body is not one JSON object")
	}
	var fields []field
	seen := map[string]struct{}{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errors.New("the request body is not valid JSON")
		}
		key, _ := tok.(string)
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("the request repeats the key %q", key)
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, errors.New("the request body is not valid JSON")
		}
		fields = append(fields, field{Key: key, Raw: raw})
	}
	if _, err := dec.Token(); err != nil {
		return nil, errors.New("the request body is not valid JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the request body has data after its JSON object")
	}
	return fields, nil
}

func lookup(fields []field, key string) (json.RawMessage, bool) {
	for _, f := range fields {
		if f.Key == key {
			return f.Raw, true
		}
	}
	return nil, false
}

// isNull reports a JSON null, which every API treats as an absent field.
func isNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// rebuild writes fields as one JSON object with edit applied: a member named
// in edit takes the new value, and the members of edit not in fields are
// appended in the order of add. Every other member is copied as it came.
func rebuild(fields []field, edit map[string]json.RawMessage, add []string) []byte {
	var out bytes.Buffer
	out.WriteByte('{')
	first := true
	write := func(key string, raw json.RawMessage) {
		if !first {
			out.WriteByte(',')
		}
		first = false
		k, _ := json.Marshal(key)
		out.Write(k)
		out.WriteByte(':')
		out.Write(raw)
	}
	for _, f := range fields {
		if replacement, ok := edit[f.Key]; ok {
			write(f.Key, replacement)
		} else {
			write(f.Key, f.Raw)
		}
	}
	for _, key := range add {
		if _, exists := lookup(fields, key); !exists {
			write(key, edit[key])
		}
	}
	out.WriteByte('}')
	return out.Bytes()
}

// checkNoDuplicateKeys refuses a repeated key at any depth of raw.
func checkNoDuplicateKeys(raw json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := walkKeys(dec, nil); err != nil {
		return err
	}
	return nil
}

// walkKeys visits decoded object keys without collapsing duplicates. A
// provider may resolve an ambiguous object differently, so every depth is
// checked before the request can authorize a call or determine its quote.
func walkKeys(dec *json.Decoder, visit func(string)) error {
	tok, err := dec.Token()
	if err != nil {
		return errors.New("not valid JSON")
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]struct{}{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return errors.New("not valid JSON")
			}
			key, _ := keyTok.(string)
			if _, dup := keys[key]; dup {
				return fmt.Errorf("repeats the key %q", key)
			}
			keys[key] = struct{}{}
			if visit != nil {
				visit(key)
			}
			if err := walkKeys(dec, visit); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkKeys(dec, visit); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return errors.New("not valid JSON")
	}
	return nil
}

// object reads raw as a JSON object with exact keys, as a provider does: a
// struct decode would fold case and let {"TYPE": "function", "type": "mcp"}
// read as the harmless one while the provider reads the other.
func object(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, false
	}
	return m, true
}

func stringOf(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// intOf reads a JSON integer, and refuses 1.5, 1e3 and the like. A value
// beyond int64 is reported as math.MaxInt64: it exceeds any clamp anyway.
func intOf(raw json.RawMessage) (int64, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var n json.Number
	if dec.Decode(&n) != nil {
		return 0, false
	}
	text := n.String()
	if strings.ContainsAny(text, ".eE") {
		return 0, false
	}
	if v, err := n.Int64(); err == nil {
		return v, true
	}
	if strings.HasPrefix(text, "-") {
		return 0, false
	}
	return math.MaxInt64, true
}

// inspect turns a request body into a call, or refuses it. It resolves the
// route, refuses what the provider would execute on its own account (hosted
// tools and server-side background runs), and clamps or injects the maximum
// output tokens: the bound every quote rests on.
func inspect(cfg *Config, api string, body []byte) (*call, *apiError) {
	fields, err := parseObject(body)
	if err != nil {
		return nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_json", err.Error())
	}
	rawModel, ok := lookup(fields, "model")
	model, isString := stringOf(rawModel)
	if !ok || !isString || model == "" {
		return nil, refuse(http.StatusBadRequest, kindInvalidRequest, "missing_model", "the request names no model")
	}
	route, ok := cfg.Resolve(api, model)
	if !ok {
		return nil, refuse(http.StatusNotFound, kindNotFound, "model_not_found",
			fmt.Sprintf("the model %q is not a route of this gateway on the %s API", model, api))
	}
	c := &call{API: api, Route: route, Body: body}
	// Cache tariffs depend on the provider's decoded key, including escaped
	// spellings such as "\u0063ache_control". Inspect every object key and
	// refuse duplicates rather than guessing which value the provider uses.
	if err := walkKeys(json.NewDecoder(bytes.NewReader(body)), func(key string) {
		if key == "cache_control" {
			c.MayWriteCache = true
		}
	}); err != nil {
		return nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_json", "the request body "+err.Error())
	}
	if raw, ok := lookup(fields, "stream"); ok && !isNull(raw) {
		var stream bool
		if json.Unmarshal(raw, &stream) != nil {
			return nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_stream", "stream must be a boolean")
		}
		c.Stream = stream
	}
	var edit map[string]json.RawMessage
	var add []string
	switch api {
	case effectargs.APIOpenAIResponses:
		edit, add, err = inspectResponses(c, route, fields)
	case effectargs.APIOpenAIChat:
		edit, add, err = inspectChat(c, route, fields)
	default:
		edit, add, err = inspectMessages(c, route, fields)
	}
	if err != nil {
		var refusal *apiError
		if errors.As(err, &refusal) {
			return nil, refusal
		}
		return nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_request", err.Error())
	}
	if len(edit) > 0 {
		c.Body = rebuild(fields, edit, add)
	}
	return c, nil
}

// hosted tools and refusals ------------------------------------------------

func hostedRefusal(what string) *apiError {
	return refuse(http.StatusBadRequest, kindInvalidRequest, "unsupported_tool",
		what+" runs on the provider's account, outside this gateway's authority: use a function tool the agent runs itself, through the gateway's tools")
}

// clientTools reads the tools member and refuses any tool whose type is not in
// allowed. A missing type is the tool type named by emptyType, or a refusal
// when emptyType is not allowed.
func clientTools(fields []field, allowed func(toolType string) bool, allowMissing bool) *apiError {
	raw, ok := lookup(fields, "tools")
	if !ok || isNull(raw) {
		return nil
	}
	if err := checkNoDuplicateKeys(raw); err != nil {
		return refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_json", "tools "+err.Error())
	}
	var tools []json.RawMessage
	if json.Unmarshal(raw, &tools) != nil {
		return refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_tools", "tools must be a list")
	}
	for i, t := range tools {
		tool, ok := object(t)
		if !ok {
			return refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_tools", fmt.Sprintf("tools[%d] must be an object", i))
		}
		rawType, has := tool["type"]
		toolType, isString := stringOf(rawType)
		switch {
		case !has || isNull(rawType):
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
func choiceRefusal(fields []field, allowed func(toolType string) bool) *apiError {
	raw, ok := lookup(fields, "tool_choice")
	if !ok || isNull(raw) {
		return nil
	}
	if err := checkNoDuplicateKeys(raw); err != nil {
		return refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_json", "tool_choice "+err.Error())
	}
	choice, ok := object(raw)
	if !ok {
		return nil // a string such as "auto" or "required"
	}
	rawType, has := choice["type"]
	if !has {
		return nil
	}
	toolType, isString := stringOf(rawType)
	if !isString {
		return hostedRefusal("this tool_choice")
	}
	if toolType == "allowed_tools" {
		return clientTools([]field{{Key: "tools", Raw: choice["tools"]}}, allowed, false)
	}
	if !allowed(toolType) {
		return hostedRefusal("the tool_choice " + toolType)
	}
	return nil
}

// max output tokens --------------------------------------------------------

// clampMax returns the maximum output tokens a request gets under route, and
// whether the request's own value must be replaced. A value at or under the
// clamp is the client's; absent or null takes the route's default; above the
// clamp takes the clamp. Zero and negative values are refused, as the
// providers refuse them.
func clampMax(raw json.RawMessage, present bool, route *Route, name string) (value int64, edit bool, err *apiError) {
	if !present || isNull(raw) {
		return route.DefaultMaxOutputTokens, true, nil
	}
	v, ok := intOf(raw)
	if !ok || v < 1 {
		return 0, false, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_max_tokens", name+" must be a positive integer")
	}
	if v > route.MaxOutputTokens {
		return route.MaxOutputTokens, true, nil
	}
	return v, false, nil
}

func number(v int64) json.RawMessage { return json.RawMessage(fmt.Sprint(v)) }

// OpenAI Responses ---------------------------------------------------------

// responsesTools are the tool types the Responses API runs on the client's
// side: a call the agent executes and reports back. Every other type
// (web_search*, file_search, code_interpreter, image_generation, mcp, computer
// and the rest) is provider-executed and refused.
func responsesToolAllowed(t string) bool {
	return slices.Contains([]string{"function", "custom", "local_shell", "apply_patch"}, t)
}

func inspectResponses(c *call, route *Route, fields []field) (map[string]json.RawMessage, []string, error) {
	if raw, ok := lookup(fields, "background"); ok && !isNull(raw) {
		var background bool
		if json.Unmarshal(raw, &background) != nil {
			return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_background", "background must be a boolean")
		}
		if background {
			return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "unsupported_background",
				"background responses run on the provider after the connection closes, so the gateway could not settle them")
		}
	}
	if e := clientTools(fields, responsesToolAllowed, false); e != nil {
		return nil, nil, e
	}
	if e := choiceRefusal(fields, responsesToolAllowed); e != nil {
		return nil, nil, e
	}
	raw, present := lookup(fields, "max_output_tokens")
	limit, edit, e := clampMax(raw, present, route, "max_output_tokens")
	if e != nil {
		return nil, nil, e
	}
	c.MaxOutputTokens = limit
	if !edit {
		return nil, nil, nil
	}
	return map[string]json.RawMessage{"max_output_tokens": number(limit)}, []string{"max_output_tokens"}, nil
}

// OpenAI Chat Completions ---------------------------------------------------

func inspectChat(c *call, route *Route, fields []field) (map[string]json.RawMessage, []string, error) {
	if raw, ok := lookup(fields, "n"); ok && !isNull(raw) {
		if n, isInt := intOf(raw); !isInt || n != 1 {
			return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "unsupported_n", "n must be 1: the gateway settles one completion per call")
		}
	}
	if raw, ok := lookup(fields, "web_search_options"); ok && !isNull(raw) {
		return nil, nil, hostedRefusal("web_search_options")
	}
	chatTool := func(t string) bool { return t == "function" }
	if e := clientTools(fields, chatTool, false); e != nil {
		return nil, nil, e
	}
	if e := choiceRefusal(fields, chatTool); e != nil {
		return nil, nil, e
	}
	edit := map[string]json.RawMessage{}
	var add []string

	// The maximum: both spellings, whichever the client used.
	rawCompletion, hasCompletion := lookup(fields, "max_completion_tokens")
	rawTokens, hasTokens := lookup(fields, "max_tokens")
	hasCompletion = hasCompletion && !isNull(rawCompletion)
	hasTokens = hasTokens && !isNull(rawTokens)
	var effective int64
	if !hasCompletion && !hasTokens {
		effective = route.DefaultMaxOutputTokens
		edit[route.ChatMaxTokensField] = number(effective)
		add = append(add, route.ChatMaxTokensField)
	}
	for _, m := range []struct {
		name    string
		raw     json.RawMessage
		present bool
	}{{"max_completion_tokens", rawCompletion, hasCompletion}, {"max_tokens", rawTokens, hasTokens}} {
		if !m.present {
			continue
		}
		v, replace, e := clampMax(m.raw, true, route, m.name)
		if e != nil {
			return nil, nil, e
		}
		effective = max(effective, v)
		if replace {
			edit[m.name] = number(v)
		}
	}
	c.MaxOutputTokens = effective

	// A stream reports its usage in a final chunk only when asked. Ask, so the
	// call can be settled from what the provider reports, and strip the chunk
	// again if the client did not ask.
	if c.Stream {
		options := map[string]json.RawMessage{}
		var optionFields []field
		if raw, ok := lookup(fields, "stream_options"); ok && !isNull(raw) {
			if err := checkNoDuplicateKeys(raw); err != nil {
				return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_json", "stream_options "+err.Error())
			}
			var ok bool
			if options, ok = object(raw); !ok {
				return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_stream_options", "stream_options must be an object")
			}
			optionFields, _ = parseObject(raw)
		}
		var include bool
		if raw, ok := options["include_usage"]; ok && !isNull(raw) {
			if json.Unmarshal(raw, &include) != nil {
				return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_stream_options", "stream_options.include_usage must be a boolean")
			}
		}
		if !include {
			edit["stream_options"] = rebuild(optionFields, map[string]json.RawMessage{"include_usage": json.RawMessage("true")}, []string{"include_usage"})
			if _, exists := lookup(fields, "stream_options"); !exists {
				add = append(add, "stream_options")
			}
			c.DropChatUsage = true
		}
	}
	if len(edit) == 0 {
		return nil, nil, nil
	}
	return edit, add, nil
}

// Anthropic Messages --------------------------------------------------------

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

func inspectMessages(c *call, route *Route, fields []field) (map[string]json.RawMessage, []string, error) {
	if raw, ok := lookup(fields, "mcp_servers"); ok && !isNull(raw) {
		var servers []json.RawMessage
		if json.Unmarshal(raw, &servers) != nil || len(servers) > 0 {
			return nil, nil, hostedRefusal("mcp_servers")
		}
	}
	if raw, ok := lookup(fields, "container"); ok && !isNull(raw) {
		return nil, nil, hostedRefusal("a code execution container")
	}
	if e := clientTools(fields, messagesToolAllowed, true); e != nil {
		return nil, nil, e
	}
	raw, present := lookup(fields, "max_tokens")
	limit, edit, e := clampMax(raw, present, route, "max_tokens")
	if e != nil {
		return nil, nil, e
	}
	c.MaxOutputTokens = limit
	if rawThinking, ok := lookup(fields, "thinking"); ok && !isNull(rawThinking) {
		if err := checkNoDuplicateKeys(rawThinking); err != nil {
			return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_json", "thinking "+err.Error())
		}
		if thinking, ok := object(rawThinking); ok {
			kind, _ := stringOf(thinking["type"])
			if budget, isInt := intOf(thinking["budget_tokens"]); kind == "enabled" && isInt && budget >= limit {
				return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "thinking_budget_too_large",
					fmt.Sprintf("thinking.budget_tokens (%d) must be less than max_tokens, which this route limits to %d", budget, limit))
			}
		}
	}
	if !edit {
		return nil, nil, nil
	}
	return map[string]json.RawMessage{"max_tokens": number(limit)}, []string{"max_tokens"}, nil
}
