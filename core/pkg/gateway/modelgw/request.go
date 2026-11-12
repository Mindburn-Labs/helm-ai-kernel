package modelgw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/modelbound"
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
	// MinOutputTokens is the lowest provider-valid cap for this body. An
	// Anthropic thinking budget requires max_tokens above budget_tokens.
	MinOutputTokens int64
	// DefaultedOutput says the client supplied no positive output maximum.
	// Only that default may be reduced to fit the current budget; an explicit
	// maximum is quoted as requested and denied if it cannot be held.
	DefaultedOutput bool
	// MayWriteCache: the request carries a cache_control marker, so the
	// provider may bill cache writes.
	MayWriteCache bool
	// DropChatUsage: strip the usage-only chunk the gateway asked for.
	DropChatUsage bool
	// ExtraInputTokens is what the provider can bill as input beyond one
	// token per request byte: the floors of inline images and of the tool
	// definitions the provider adds (bound.go).
	ExtraInputTokens int64
}

// inputBound is the input-token bound the quote prices for body: one token per
// byte plus the floors of what bytes do not bound.
func (c *call) inputBound(body []byte) int64 { return int64(len(body)) + c.ExtraInputTokens }

// field is one member of a JSON object, in order, with its value untouched.
type field = modelbound.Field

// inspect turns a request body into a call, or refuses it. It resolves the
// route, refuses what the provider would execute on its own account (hosted
// tools and server-side background runs) and anything else the quote cannot
// see (bound.go), and clamps or injects the maximum output tokens: the bound
// every quote rests on.
func inspect(cfg *Config, api string, body []byte) (*call, *apiError) {
	fields, err := modelbound.ParseObject(body)
	if err != nil {
		return nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_json", err.Error())
	}
	rawModel, ok := modelbound.Lookup(fields, "model")
	model, isString := modelbound.String(rawModel)
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
	if err := modelbound.WalkKeys(json.NewDecoder(bytes.NewReader(body)), func(key string) {
		if key == "cache_control" {
			c.MayWriteCache = true
		}
	}); err != nil {
		return nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_json", "the request body "+err.Error())
	}
	if raw, ok := modelbound.Lookup(fields, "stream"); ok && !modelbound.IsNull(raw) {
		var stream bool
		if json.Unmarshal(raw, &stream) != nil {
			return nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_stream", "stream must be a boolean")
		}
		c.Stream = stream
	}
	// What the quote cannot see is refused, what bytes do not bound gets its
	// floor, and store and the service tier are pinned (helm-tracker#313).
	set, refusal := boundRequest(cfg, c, fields)
	if refusal != nil {
		return nil, refusal
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
	for _, f := range set {
		if edit == nil {
			edit = map[string]json.RawMessage{}
		}
		edit[f.Key] = f.Raw
		add = append(add, f.Key)
	}
	if len(edit) > 0 {
		c.Body = modelbound.Rebuild(fields, edit, add)
	}
	return c, nil
}

// max output tokens --------------------------------------------------------

// clampMax returns the maximum output tokens a request gets under route, and
// whether the request's own value must be replaced. A value at or under the
// clamp is the client's; absent or null takes the route's default; above the
// clamp takes the clamp. Zero and negative values are refused, as the
// providers refuse them.
func clampMax(raw json.RawMessage, present bool, route *Route, name string) (value int64, edit bool, err *apiError) {
	if !present || modelbound.IsNull(raw) {
		return route.DefaultMaxOutputTokens, true, nil
	}
	v, ok := modelbound.IntOf(raw)
	if !ok || v < 1 {
		return 0, false, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_max_tokens", name+" must be a positive integer")
	}
	if v > route.MaxOutputTokens {
		return route.MaxOutputTokens, true, nil
	}
	return v, false, nil
}

func number(v int64) json.RawMessage { return json.RawMessage(fmt.Sprint(v)) }

// fitDefaultOutput lowers an injected route default to the largest positive
// maximum whose full quote fits remaining. The quote includes the bytes of
// the amended request, so the input and output terms use the same body that
// will reach the provider. If even one token cannot fit, admission receives
// the original quote and records its BUDGET_EXCEEDED denial.
func (c *call) fitDefaultOutput(remaining int64) {
	if !c.DefaultedOutput || remaining < 0 {
		return
	}
	fields, err := modelbound.ParseObject(c.Body)
	if err != nil {
		return // inspect already validated this body
	}
	name := "max_output_tokens"
	switch c.API {
	case effectargs.APIOpenAIChat:
		name = c.Route.ChatMaxTokensField
	case effectargs.APIAnthropicMessages:
		name = "max_tokens"
	}
	candidate := func(tokens int64) ([]byte, bool) {
		body := modelbound.Rebuild(fields, map[string]json.RawMessage{name: number(tokens)}, nil)
		quote, err := c.Route.Quote(c.inputBound(body), tokens, c.MayWriteCache)
		return body, err == nil && quote <= remaining
	}
	if _, fits := candidate(c.MaxOutputTokens); fits {
		return
	}
	low, high := max(int64(1), c.MinOutputTokens), c.MaxOutputTokens
	best := int64(0)
	for low <= high {
		mid := low + (high-low)/2
		if _, fits := candidate(mid); fits {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	if best > 0 {
		c.Body, _ = candidate(best)
		c.MaxOutputTokens = best
	}
}

// OpenAI Responses ---------------------------------------------------------

func inspectResponses(c *call, route *Route, fields []field) (map[string]json.RawMessage, []string, error) {
	raw, present := modelbound.Lookup(fields, "max_output_tokens")
	c.DefaultedOutput = !present || modelbound.IsNull(raw)
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
	edit := map[string]json.RawMessage{}
	var add []string

	// The maximum: both spellings, whichever the client used.
	rawCompletion, hasCompletion := modelbound.Lookup(fields, "max_completion_tokens")
	rawTokens, hasTokens := modelbound.Lookup(fields, "max_tokens")
	hasCompletion = hasCompletion && !modelbound.IsNull(rawCompletion)
	hasTokens = hasTokens && !modelbound.IsNull(rawTokens)
	c.DefaultedOutput = !hasCompletion && !hasTokens
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
		if raw, ok := modelbound.Lookup(fields, "stream_options"); ok && !modelbound.IsNull(raw) {
			if err := modelbound.CheckNoDuplicateKeys(raw); err != nil {
				return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_json", "stream_options "+err.Error())
			}
			var ok bool
			if options, ok = modelbound.Object(raw); !ok {
				return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_stream_options", "stream_options must be an object")
			}
			optionFields, _ = modelbound.ParseObject(raw)
		}
		var include bool
		if raw, ok := options["include_usage"]; ok && !modelbound.IsNull(raw) {
			if json.Unmarshal(raw, &include) != nil {
				return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_stream_options", "stream_options.include_usage must be a boolean")
			}
		}
		if !include {
			edit["stream_options"] = modelbound.Rebuild(optionFields, map[string]json.RawMessage{"include_usage": json.RawMessage("true")}, []string{"include_usage"})
			if _, exists := modelbound.Lookup(fields, "stream_options"); !exists {
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

func inspectMessages(c *call, route *Route, fields []field) (map[string]json.RawMessage, []string, error) {
	raw, present := modelbound.Lookup(fields, "max_tokens")
	c.DefaultedOutput = !present || modelbound.IsNull(raw)
	limit, edit, e := clampMax(raw, present, route, "max_tokens")
	if e != nil {
		return nil, nil, e
	}
	c.MaxOutputTokens = limit
	if rawThinking, ok := modelbound.Lookup(fields, "thinking"); ok && !modelbound.IsNull(rawThinking) {
		if err := modelbound.CheckNoDuplicateKeys(rawThinking); err != nil {
			return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_json", "thinking "+err.Error())
		}
		if thinking, ok := modelbound.Object(rawThinking); ok {
			kind, _ := modelbound.String(thinking["type"])
			if budget, isInt := modelbound.IntOf(thinking["budget_tokens"]); kind == "enabled" && isInt {
				if budget >= limit {
					return nil, nil, refuse(http.StatusBadRequest, kindInvalidRequest, "thinking_budget_too_large",
						fmt.Sprintf("thinking.budget_tokens (%d) must be less than max_tokens, which this route limits to %d", budget, limit))
				}
				c.MinOutputTokens = budget + 1
			}
		}
	}
	if !edit {
		return nil, nil, nil
	}
	return map[string]json.RawMessage{"max_tokens": number(limit)}, []string{"max_tokens"}, nil
}
