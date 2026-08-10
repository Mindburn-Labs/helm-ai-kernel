package tracing

import (
	"net/http"
	"testing"
)

// TestRouteFromPatternMirrorsOtelhttp pins the normaliser against the one the
// instrumentation library applies to the same input, otelhttp v0.65.0
// internal/semconv/util.go:79-84 httpRoute():
//
//	if idx := strings.IndexByte(pattern, '/'); idx >= 0 { return pattern[idx:] }
//	return ""
//
// The rule matters because http.route has to be the SAME string in three
// places: the span attribute we stamp, the metric attribute we contribute, and
// the value the library itself would produce. A method-scoped ServeMux pattern
// carries its method ("GET /probe/{id}"), and stamping that verbatim bakes the
// method into http.route — splitting one route across as many buckets as it has
// verbs and making it disagree with the library's own output.
func TestRouteFromPatternMirrorsOtelhttp(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		want    string
	}{
		{"bare path", "/api/v1/receipts", "/api/v1/receipts"},
		{"bare path with wildcard", "/probe/{id}", "/probe/{id}"},
		{"method scoped", "GET /probe/{id}", "/probe/{id}"},
		{"method scoped post", "POST /api/v1/approvals/{id}/consume", "/api/v1/approvals/{id}/consume"},
		{"host scoped", "example.com/probe", "/probe"},
		{"method and host scoped", "GET example.com/probe", "/probe"},
		{"trailing wildcard", "/static/", "/static/"},
		{"root", "/", "/"},
		{"unrouted request", "", ""},
		{"no path at all", "GET", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeFromPattern(tc.pattern); got != tc.want {
				t.Errorf("routeFromPattern(%q) = %q, want %q", tc.pattern, got, tc.want)
			}
		})
	}
}

// TestEdgeRouteDropsOnlyTheCatchAll pins the single deviation this package makes
// from the library normaliser above, and — just as importantly — its narrowness.
//
// The bare "/" pattern is a SUBTREE match: it matches every path, so r.Pattern
// is "/" for "/v1/chat/completions" as much as for "/". Publishing that as
// http.route buys one aggregation bucket holding an entire edge, and costs the
// span its operation name, since a non-empty route makes edgeSpanName render
// "{method} /" instead. The proxy edge (cmd/helm-ai-kernel/proxy_cmd.go
// registers `mux.HandleFunc("/", proxy.ServeHTTP)` as its terminal route) is
// where that lands in production: without the drop, all governed LLM traffic
// reports as "POST /" instead of "helm.proxy".
//
// The rest of the table is the containment: an exact root route is spelled
// "/{$}" in net/http, never "/", so it keeps its identity; "/static/" is a
// subtree too but a discriminating one; and no ordinary route is touched. If a
// future edit widens the deviation — dropping every trailing-slash pattern, say
// — the "/static/" and "/{$}" rows fail.
func TestEdgeRouteDropsOnlyTheCatchAll(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		want    string
	}{
		{"catch-all", "/", ""},
		{"method scoped catch-all", "GET /", ""},
		{"host scoped catch-all", "example.com/", ""},
		{"method and host scoped catch-all", "POST example.com/", ""},
		// The trailing-wildcard spelling of the same thing. Rewriting a
		// terminal "/" this way reads like a modernisation and would otherwise
		// put a whole edge back into one bucket.
		{"trailing wildcard catch-all", "/{path...}", ""},
		{"trailing wildcard catch-all, other name", "/{rest...}", ""},
		{"method scoped trailing wildcard catch-all", "POST /{path...}", ""},
		{"exact root is not the catch-all", "/{$}", "/{$}"},
		{"method scoped exact root", "GET /{$}", "/{$}"},
		// A wildcard below the root still discriminates: it says the request
		// went to /static, whatever followed.
		{"trailing wildcard in a subtree", "/static/{path...}", "/static/{path...}"},
		{"multi segment wildcard route", "/a/{b}/{rest...}", "/a/{b}/{rest...}"},
		{"discriminating subtree", "/static/", "/static/"},
		{"ordinary route", "/api/v1/receipts", "/api/v1/receipts"},
		{"wildcard route", "/probe/{id}", "/probe/{id}"},
		{"unrouted request", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := edgeRoute(tc.pattern); got != tc.want {
				t.Errorf("edgeRoute(%q) = %q, want %q", tc.pattern, got, tc.want)
			}
		})
	}
}

// TestStandardMethodFoldsUnknownVerbs pins the span-name method against
// otelhttp's standardizeHTTPMethod (internal/semconv/util.go). A bare-path
// ServeMux pattern matches ANY method, so without the fold an unauthenticated
// caller can mint a distinct span name per request by varying the request-line
// token — the same unbounded-cardinality problem the route normalisation exists
// to avoid, arriving through the other half of the name.
func TestStandardMethodFoldsUnknownVerbs(t *testing.T) {
	for _, tc := range []struct {
		method string
		want   string
	}{
		{http.MethodGet, "GET"},
		{http.MethodPost, "POST"},
		{http.MethodDelete, "DELETE"},
		{http.MethodPatch, "PATCH"},
		{http.MethodConnect, "CONNECT"},
		{"get", "GET"},
		{"PoSt", "POST"},
		{"PROPFIND", "_OTHER"},
		{"HELM-EXFIL-7f3a", "_OTHER"},
		{"", "_OTHER"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			if got := standardMethod(tc.method); got != tc.want {
				t.Errorf("standardMethod(%q) = %q, want %q", tc.method, got, tc.want)
			}
		})
	}
}
