package tracing

import (
	"net/http"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// WrapEdgeHandler wraps an external HTTP edge in an otelhttp server-span
// handler (HELM-333). The daemon's shared listener is a public trust boundary:
// an inbound W3C traceparent is linked to a new kernel trace, never adopted as
// its parent. That keeps a caller from choosing the kernel trace ID or clearing
// the sampled flag to suppress the server span. The explicit TraceContext-only
// propagator also prevents untrusted baggage from entering request context.
//
// The tracer is resolved PER REQUEST, not at wrap time: no WithTracerProvider
// option is passed, so otelhttp reads otel.GetTracerProvider() inside
// serveHTTP (otelhttp v0.65.0), and otel's global tracer is a forwarding
// delegate that back-fills once SetTracerProvider runs (otel v1.44.0). Wrapping
// before OTel is configured is therefore fine — only wrapping after traffic has
// started would lose spans. An earlier comment here claimed construction-time
// resolution and sent an investigation down the wrong path; do not restore it.
// When no SDK provider is installed, however, OTel's noop tracer ignores
// WithNewRoot and carries the extracted remote SpanContext forward unchanged.
// dropRemoteSpanContext closes that provider-independent trust-boundary gap
// before application handlers or context-aware logs can observe it.
//
// # Per-route identity (HELM-495)
//
// Out of the box otelhttp gives an edge no route identity at all, and both
// halves have to be supplied here rather than at the call site:
//
//   - The span NAME. defaultHandlerFormatter (handler.go:38) ignores the
//     request and returns the operation, so every route on a mux collapses onto
//     one constant name. The fix cannot live downstream: handler.go:181 re-runs
//     the formatter after next.ServeHTTP returns, overwriting any SetName a
//     middleware performed. That second call is also what makes the fix
//     possible — by then http.ServeMux has stamped r.Pattern.
//   - The http.route ATTRIBUTE. otelhttp builds the request attributes once, at
//     span start (internal/semconv/server.go:164), where r.Pattern is still
//     empty because routing has not happened, and never revisits them. So
//     withRouteAttribute below stamps it after the inner handler returns.
//     Without it a span's only path discriminator is url.path, which embeds
//     path parameters and therefore cannot be aggregated.
//   - The http.route METRIC attribute. handler.go:198 builds
//     semconv.MetricAttributes without ever populating its Route field, so
//     http.server.request.duration carries no route either. Its
//     AdditionalAttributes are `append(labeler.Get(), h.metricAttributesFromRequest(r)...)`,
//     so there are TWO post-routing hooks, not one: otelhttp.Labeler, which a
//     handler reaches through LabelerFromContext, and WithMetricAttributesFn,
//     the option used here. Either would work — the Labeler was tried and the
//     assertions pass with it.
//     The option is chosen because it is a property of the WRAPPER rather than
//     of a handler: it applies to every edge this function covers, including
//     handlers we do not own, and no handler can forget to call it. The Labeler
//     remains the right hook for an attribute only a specific handler knows,
//     such as a tenant or an upstream identity.
//     Because the library leaves MetricAttributes.Route empty, contributing the
//     attribute here adds it exactly once.
//
// All three go through edgeRoute, so the span attribute, the metric attribute
// and the route half of the span name are the same string by construction.
//
// A request stays unrouted from this wrapper's point of view in three different
// ways, and only the first is obvious:
//
//  1. Nothing routes it — the inner handler is not a mux, or the mux misses
//     (a 404). Pattern is never set.
//  2. Something routes it, but hands the mux a COPY of the request.
//     net/http.ServeMux stamps Pattern onto the request it is given, so the
//     copy takes the stamp and the original — the one otelhttp holds — never
//     sees it.
//  3. A mux routes it, to the bare "/" catch-all. Pattern IS set, and says
//     nothing: "/" matches every path. edgeRoute drops it so the edge keeps its
//     operation name — see that function for why the constant is the better
//     label of the two.
//
// Case 2 is api.NewServer's edge: serveEdge ends in
// `s.mux.ServeHTTP(w, r.WithContext(ctx))`, and WithContext returns a shallow
// copy. So that edge does route through a mux, and still keeps the operation
// name with no route attribute — for the copy, not for want of a mux. Do not
// read it as "that handler has no routes". It also means a future cleanup that
// stops copying there would silently start producing per-route names and
// http.route on that edge: an improvement, but a behaviour change rather than a
// no-op refactor.
//
// The same mechanism is why the daemon's chain in cmd/helm-ai-kernel keeps this
// wrapper BELOW RequestIDMiddleware, which copies the request the same way.
func WrapEdgeHandler(h http.Handler, operation string) http.Handler {
	return otelhttp.NewHandler(withRouteAttribute(dropRemoteSpanContext(h)), operation,
		otelhttp.WithPropagators(propagation.TraceContext{}),
		otelhttp.WithPublicEndpointFn(func(*http.Request) bool { return true }),
		otelhttp.WithSpanNameFormatter(edgeSpanName),
		otelhttp.WithMetricAttributesFn(edgeMetricAttributes),
	)
}

// dropRemoteSpanContext removes the extracted caller context only when the
// tracer failed to replace it with a local server span. That is the observable
// noop-provider failure mode: a real SDK span is local and remains untouched,
// preserving both recording and the link created by WithPublicEndpointFn.
//
// Update the request in place so the outer otelhttp wrapper still observes the
// route pattern stamped by http.ServeMux after the handler returns.
func dropRemoteSpanContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if oteltrace.SpanContextFromContext(r.Context()).IsRemote() {
			ctx := oteltrace.ContextWithSpanContext(r.Context(), oteltrace.SpanContext{})
			*r = *r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// edgeSpanName renders the server span name.
//
// The OTel HTTP convention — and otelhttp's own documented example
// (handler_test.go TestWithSpanNameFormatter, "with a custom span name
// formatter using the pattern") — is "{method} {route}". The method belongs in
// the NAME but not in the route, which is why r.Pattern is normalised rather
// than used verbatim: a method-scoped registration such as "GET /probe/{id}"
// would otherwise render "GET GET /probe/{id}".
//
// The name is a low-cardinality aggregation key, so the method is folded onto
// the known set exactly as otelhttp folds it for metric attributes
// (internal/semconv/util.go standardizeHTTPMethod). Without that, a caller can
// mint an unbounded stream of distinct span names with arbitrary request-line
// tokens against any bare-path route — which matches every method.
//
// This runs twice per request (span start, then again at handler.go:181). At
// the first call routing has not happened, r.Pattern is empty and the operation
// stands in; the second call is the one that lands.
//
// The operation also stands in permanently when edgeRoute finds no usable route
// — a 404, a cloning middleware, or the bare "/" catch-all. Falling back to a
// constant is not a degraded outcome there: the operation names the EDGE
// ("helm.api", "helm.proxy"), which for a request that matched nothing
// discriminating is the only true thing left to say about it.
func edgeSpanName(operation string, r *http.Request) string {
	route := edgeRoute(r.Pattern)
	if route == "" {
		return operation
	}
	return standardMethod(r.Method) + " " + route
}

// edgeMetricAttributes contributes http.route to the otelhttp server metrics
// (http.server.request.duration and the body-size histograms). It runs after
// the inner handler has returned, so r.Pattern is set for a routed request.
//
// An unrouted request contributes nothing: an empty http.route is worse than an
// absent one, because it mints a bogus aggregation bucket that looks like a
// real route. A catch-all route ("/", see edgeRoute) is the same failure with a
// non-empty string — one bucket holding every path — and is dropped with it.
func edgeMetricAttributes(r *http.Request) []attribute.KeyValue {
	route := edgeRoute(r.Pattern)
	if route == "" {
		return nil
	}
	return []attribute.KeyValue{semconv.HTTPRoute(route)}
}

// withRouteAttribute stamps http.route onto the server span once the mux has
// resolved the request to a registered pattern that discriminates on path (see
// edgeRoute — the "/" catch-all does not, and is skipped like a miss).
//
// It must sit INSIDE otelhttp.NewHandler (it wraps the next handler, not the
// otelhttp handler): from outside, the span is already ended by the time the
// attribute would be set and the write is dropped.
//
// Reading Pattern after next.ServeHTTP returns is safe because ServeMux mutates
// the request it is handed rather than a copy (net/http server.go:2826,
// "h, r.Pattern, r.pat, r.matches = mux.findHandler(r)"). The corollary is that
// any middleware between this one and the mux must pass the request through
// unchanged — a middleware that clones with r.WithContext breaks the span name
// and this attribute together, which is the intended failure mode: they cannot
// silently diverge.
func withRouteAttribute(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		route := edgeRoute(r.Pattern)
		if route == "" {
			return
		}
		if span := oteltrace.SpanFromContext(r.Context()); span.IsRecording() {
			span.SetAttributes(semconv.HTTPRoute(route))
		}
	})
}

// edgeRoute is the http.route value this wrapper will publish for a request,
// given its http.ServeMux pattern: the library-mirroring normalisation, minus
// the one pattern that normalises to something true and useless.
//
// A bare "/" is not a route. In net/http's pattern language a trailing slash
// makes the pattern a SUBTREE match, so "/" matches every path and r.Pattern
// comes back as "/" whether the request was for "/" or for
// "/v1/chat/completions". Publishing it costs on both surfaces at once: the
// metric gains one bucket holding the entire edge, and — because a non-empty
// route makes edgeSpanName render "{method} /" — the span name LOSES the
// operation, the only label that said which edge produced it. That is strictly
// less information than the constant it replaced, which makes "/" the one route
// worth refusing.
//
// The shape is live, not hypothetical. The proxy edge registers
// `mux.HandleFunc("/", proxy.ServeHTTP)` as its terminal route
// (cmd/helm-ai-kernel/proxy_cmd.go), so every governed LLM call lands there;
// without this drop the whole proxy would report as "POST /". Dropping it keeps
// that edge on "helm.proxy" with no http.route — which is honest, because
// nothing discriminating matched.
//
// An exact match on the root path is a different pattern and survives: net/http
// spells it "/{$}", which stamps r.Pattern as "/{$}" and normalises to "/{$}",
// not "/". So a route that genuinely means "the root document" keeps its own
// span name and attribute, and — verified against net/http's precedence — it
// also WINS over a "/" registered on the same mux, so registering the catch-all
// never costs an exact root route its identity. There is no spelling of "exact
// root" that reaches this branch, which is what makes the drop safe rather than
// a trade.
//
// The method-scoped ("GET /") and host-scoped ("example.com/") spellings of the
// catch-all normalise to "/" too and go with it. That is right: restricting a
// catch-all by verb or by host does not make it discriminate on path, and the
// method already rides in the span name and in http.request.method.
func edgeRoute(pattern string) string {
	route := routeFromPattern(pattern)
	if rootCatchAll(route) {
		return ""
	}
	return route
}

// rootCatchAll reports whether a normalised route matches every path, and so
// discriminates nothing.
//
// net/http has TWO spellings that mean "everything", and keying the drop on the
// first alone left the second reproducing the exact regression the drop exists
// to prevent:
//
//	"/"           the classic prefix pattern
//	"/{rest...}"  the trailing-wildcard form, for any wildcard name
//
// The second is not hypothetical in the way it looks: rewriting a terminal "/"
// as "/{path...}" reads like a harmless modernisation, and it would silently put
// the whole proxy edge back into one bucket named "POST /{path...}".
//
// "/{$}" is deliberately NOT one of them. It matches the root path and nothing
// else, which is as discriminating as any other exact route, so it keeps its own
// name and attribute. Nor is a wildcard deeper in the path a catch-all:
// "/a/{rest...}" is a genuine subtree and survives.
func rootCatchAll(route string) bool {
	if route == "/" {
		return true
	}
	if !strings.HasPrefix(route, "/{") || !strings.HasSuffix(route, "...}") {
		return false
	}
	// Everything between "/{" and "...}" must be a single wildcard name: no
	// slash (that would make it a subtree) and no brace (that would make it a
	// multi-segment pattern such as "/{a}/{b...}").
	name := route[2 : len(route)-4]
	return name != "" && !strings.ContainsAny(name, "/{}")
}

// routeFromPattern normalises an http.ServeMux pattern into an http.route
// value.
//
// This is a deliberate mirror of otelhttp's own normaliser, httpRoute in
// internal/semconv/util.go:79-84 — the same "everything from the first slash"
// rule, so a route we stamp is byte-identical to one the library would stamp if
// it ever saw a routed request. It drops the method of a method-scoped pattern
// ("GET /probe/{id}" -> "/probe/{id}") and the host of a host-scoped one, and
// returns "" for a pattern with no path at all, including the empty pattern of
// an unrouted request.
//
// It is deliberately kept as the bare mirror — no policy — so the mirror can be
// pinned against the library on its own. Callers go through edgeRoute, which
// adds the one deviation this package makes.
func routeFromPattern(pattern string) string {
	if idx := strings.IndexByte(pattern, '/'); idx >= 0 {
		return pattern[idx:]
	}
	return ""
}

// standardMethod folds an HTTP method onto the set the OTel HTTP convention
// recognises, mirroring otelhttp's standardizeHTTPMethod
// (internal/semconv/util.go). Anything else becomes "_OTHER" rather than
// reaching a span name.
func standardMethod(method string) string {
	upper := strings.ToUpper(method)
	switch upper {
	case http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead,
		http.MethodOptions, http.MethodPatch, http.MethodPost, http.MethodPut,
		http.MethodTrace:
		return upper
	default:
		return "_OTHER"
	}
}
