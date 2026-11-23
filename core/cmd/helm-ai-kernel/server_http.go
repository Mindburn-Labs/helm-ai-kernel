package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	helmapi "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
)

// buildAPIHandler assembles the daemon's request pipeline.
//
// Layer order is load-bearing and pinned by api_handler_chain_test.go:
//
//	SecurityHeaders -> CORS -> RequestID -> tracing -> rateLimiter -> mux
//
// The tracing wrapper (HELM-333/HELM-495) sits INSIDE RequestIDMiddleware and
// OUTSIDE the rate limiter. Both halves matter:
//
//   - Inside RequestID because that middleware calls next.ServeHTTP with
//     r.WithContext(ctx). http.ServeMux stamps the matched pattern onto the
//     *http.Request it is handed, in place — so whichever request object
//     otelhttp passes downstream is the one that comes back carrying Pattern.
//     From outside RequestID, otelhttp holds the pre-clone request and never
//     sees the pattern, which makes per-route naming structurally impossible.
//   - Outside the rate limiter so a rejected request is still a span: a 429 is
//     exactly the case worth seeing in a trace.
//
// The accepted cost of moving in is the CORS preflight, which CORSMiddleware
// answers before the span starts and which therefore is no longer traced.
//
// Nothing here stamps http.route, and nothing here could. The three
// route-bearing surfaces are coordinated inside tracing.WrapEdgeHandler, but
// by different mechanisms — the split pins them to that function rather than
// to this chain:
//
//   - The span NAME needs an otelhttp OPTION (WithSpanNameFormatter). otelhttp
//     re-runs its formatter after the inner handler returns (handler.go:180-181)
//     and overwrites whatever SetName a middleware performed, so no middleware,
//     here or anywhere, can win that race.
//   - The span ATTRIBUTE needs a MIDDLEWARE (tracing's own withRouteAttribute).
//     There is no option for it: otelhttp freezes the request attributes at span
//     start, before routing, and never revisits them. The middleware has to sit
//     INSIDE otelhttp.NewHandler, because from outside the span has already
//     ended and the write is dropped — which is precisely why it lives in the
//     wrapper and cannot be a layer of this chain.
//   - The metric ATTRIBUTE comes from otelhttp's post-routing read of Pattern.
//     The wrapper clears a non-discriminating catch-all Pattern after the inner
//     handler returns, so that metric and the span agree on its absence. Real
//     routes retain their Pattern. See tracing.WrapEdgeHandler for the rule.
//
// The one requirement this chain owes that machinery is that every layer below
// the wrapper pass the request through unchanged; the rate limiter does.
//
// Everything downstream runs with a span in r.Context(), which is what lets
// *Context slog call sites stamp trace_id/span_id (see tracing.NewSlogHandler).
//
// This is the daemon's only traced entry point: api.NewServer wraps its own
// edge, but the daemon does not use that constructor (it registers its routes
// on its own mux). The tracer is resolved per request from the global
// TracerProvider, so wrapping before observability.New has configured OTel is
// harmless as long as configuration lands before traffic does.
//
// The health (:HELM_HEALTH_PORT) and metrics (:HELM_METRICS_PORT) servers are
// deliberately NOT wrapped: they serve liveness probes and Prometheus scrapes
// on separate ports at a fixed cadence (~1200 probes per idle hour), which
// would bury real request traces in root spans that carry no inbound
// traceparent and no governance decision.
func buildAPIHandler(mux http.Handler, rateLimiter *helmapi.GlobalRateLimiter) http.Handler {
	return helmauth.SecurityHeaders(
		helmauth.CORSMiddleware(nil)(
			helmauth.RequestIDMiddleware(
				tracing.WrapEdgeHandler(
					rateLimiter.Middleware(mux),
					"helm.api",
				),
			),
		),
	)
}

func buildRuntimeRateLimiter() (*helmapi.GlobalRateLimiter, error) {
	rateLimiter := helmapi.NewGlobalRateLimiter(
		envInt("HELM_LIMIT_GLOBAL_RPS", envInt("HELM_LIMIT_RPS", 60)),
		envInt("HELM_LIMIT_GLOBAL_BURST", envInt("HELM_LIMIT_BURST", 120)),
	)
	rateLimiter = rateLimiter.WithEndpointLimits(runtimeRateClassForRequest, map[string]helmapi.RateLimitProfile{
		string(RouteRatePublic):   endpointRateProfile(RouteRatePublic, 120, 240),
		string(RouteRateKernel):   endpointRateProfile(RouteRateKernel, 60, 120),
		string(RouteRateEvidence): endpointRateProfile(RouteRateEvidence, 40, 80),
		string(RouteRateAdmin):    endpointRateProfile(RouteRateAdmin, 20, 40),
		string(RouteRateStream):   endpointRateProfile(RouteRateStream, 20, 40),
	})
	rateLimiter = rateLimiter.WithActorLimit(helmapi.RateLimitProfile{
		RPS:   envInt("HELM_LIMIT_ACTOR_RPS", 60),
		Burst: envInt("HELM_LIMIT_ACTOR_BURST", 120),
	})
	rateLimiter = rateLimiter.WithConcurrencyLimit(envInt("HELM_CONCURRENCY_MAX", 0))
	if envBool("HELM_LOAD_SHED_ENABLED") {
		rateLimiter = rateLimiter.WithLowPriorityLoadShed(envInt("HELM_LOAD_SHED_LOW_PRIORITY_MAX", 0))
	}
	trustedProxies, err := helmapi.ParseTrustedProxyCIDRs(os.Getenv("HELM_TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return nil, fmt.Errorf("HELM_TRUSTED_PROXY_CIDRS: %w", err)
	}
	if envBool("HELM_TRUST_PROXY_HEADERS") && len(trustedProxies) == 0 {
		slog.Warn("HELM_TRUST_PROXY_HEADERS is ignored: forwarded client addresses are honoured only from peers in HELM_TRUSTED_PROXY_CIDRS")
	}
	return rateLimiter.WithTrustedProxies(trustedProxies), nil
}

func endpointRateProfile(class RouteRateLimit, defaultRPS, defaultBurst int) helmapi.RateLimitProfile {
	name := strings.ToUpper(string(class))
	return helmapi.RateLimitProfile{
		RPS:   envInt("HELM_LIMIT_"+name+"_RPS", envInt("HELM_LIMIT_ENDPOINT_RPS", defaultRPS)),
		Burst: envInt("HELM_LIMIT_"+name+"_BURST", envInt("HELM_LIMIT_ENDPOINT_BURST", defaultBurst)),
	}
}

func runtimeRateClassForRequest(r *http.Request) string {
	path := r.URL.EscapedPath()
	bestClass := string(RouteRatePublic)
	bestLen := -1
	for _, spec := range RuntimeRouteSpecs() {
		if spec.Method != "" && spec.Method != r.Method {
			continue
		}
		if !runtimeRouteMatches(spec.MuxPattern, path) {
			continue
		}
		if len(spec.MuxPattern) > bestLen {
			bestLen = len(spec.MuxPattern)
			bestClass = string(spec.RateLimit)
		}
	}
	return bestClass
}

func runtimeRouteMatches(pattern string, path string) bool {
	if pattern == "" {
		return false
	}
	if pattern == path {
		return true
	}
	return strings.HasSuffix(pattern, "/") && strings.HasPrefix(path, pattern)
}
