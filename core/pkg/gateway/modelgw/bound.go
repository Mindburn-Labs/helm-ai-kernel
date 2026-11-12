package modelgw

import (
	"net/http"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/modelbound"
)

// The quote is a bound only for what it can see (helm-tracker#313, audit H6).
// It counts each byte of the request as an input token and the clamped output
// maximum, so a request is read against the closed list of what the quote
// understands, per API (core/pkg/gateway/modelbound, which the governed
// gateway shares): anything outside it is refused before any attempt exists,
// naming it, and what the list keeps but bytes do not bound is added to the
// input side of the quote as a token floor (call.ExtraInputTokens).

func boundRefusal(r *modelbound.Refusal) *apiError {
	return refuse(http.StatusBadRequest, kindInvalidRequest, r.Code, r.Message)
}

// boundRequest refuses what the quote of c cannot see, sets c.ExtraInputTokens
// to the floors of what it keeps, and returns the members to set in the
// forwarded request: store false on Responses, and the standard service tier
// when the route's provider is the vendor's own API.
func boundRequest(cfg *Config, c *call, fields []field) ([]field, *apiError) {
	standard := false
	if p := cfg.Provider(c.Route.Provider); p != nil {
		standard = p.Kind == KindOpenAI || p.Kind == KindAnthropic
	}
	// The routes carry cache-write prices (defaulted where a provider bills a
	// write premium, Price), and usage.go reads the provider's cache writes.
	bound, refusal := modelbound.Check(c.API, fields, modelbound.Options{StandardTier: standard, CacheWrites: true})
	if refusal != nil {
		return nil, boundRefusal(refusal)
	}
	c.ExtraInputTokens = bound.ExtraInputTokens
	return bound.Set, nil
}

// anthropicBetaRefusal refuses an anthropic-beta outside the allowlist of
// betas the quote is known to bound.
func anthropicBetaRefusal(api string, h http.Header) *apiError {
	if r := modelbound.BetaRefusal(api, h); r != nil {
		return boundRefusal(r)
	}
	return nil
}
