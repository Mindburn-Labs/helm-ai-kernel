package tracing_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

// recordEdgeSpans installs an in-memory TracerProvider as the global one.
// WrapEdgeHandler passes no WithTracerProvider option, so this is the provider
// the wrapped edge will resolve per request.
func recordEdgeSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	return sr
}

// recordEdgeMetrics installs an SDK MeterProvider backed by a ManualReader as
// the global one.
//
// Unlike the tracer, otelhttp resolves its meter at CONSTRUCTION time (newConfig
// calls otel.GetMeterProvider().Meter(...) while applying the options), so this
// must run before the WrapEdgeHandler call under test.
func recordEdgeMetrics(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(mp)
	t.Cleanup(func() {
		otel.SetMeterProvider(prev)
		_ = mp.Shutdown(context.Background())
	})
	return reader
}

// routeAbsent is what durationRoutes reports for a datapoint that carries no
// http.route attribute at all.
//
// Deliberately not "". An ABSENT attribute and a PRESENT-but-empty one are
// different regressions — an empty route mints a bogus bucket that reads like a
// real one — and collapsing both to "" would leave the "no route" assertions
// below unable to fail. A real route always begins with "/", so this sentinel
// cannot collide with one.
const routeAbsent = "<absent>"

// durationRoutes returns the http.route attribute of every
// http.server.request.duration datapoint the reader holds, with routeAbsent
// standing in for a datapoint that carries no route attribute.
func durationRoutes(t *testing.T, reader *sdkmetric.ManualReader) []string {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	var routes []string
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "http.server.request.duration" {
				continue
			}
			hist, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				t.Fatalf("http.server.request.duration is %T, want metricdata.Histogram[float64]", m.Data)
			}
			for _, dp := range hist.DataPoints {
				value, ok := dp.Attributes.Value(semconv.HTTPRouteKey)
				if !ok {
					routes = append(routes, routeAbsent)
					continue
				}
				routes = append(routes, value.AsString())
			}
		}
	}
	return routes
}

// routeAttrs returns the http.route attributes on the span. A slice rather than
// a bare string so a failure message can tell "attribute absent" ([]) apart
// from "attribute present with the wrong value". In practice the length is 0 or
// 1: the SDK deduplicates attributes by key when they are read (sdk/trace
// span.go SetAttributes).
func routeAttrs(span sdktrace.ReadOnlySpan) []string {
	var got []string
	for _, attr := range span.Attributes() {
		if attr.Key == semconv.HTTPRouteKey {
			got = append(got, attr.Value.AsString())
		}
	}
	return got
}

// TestWrapEdgeHandlerNamesAndStampsRoute is the HELM-495 finding-1 guard at the
// wrapper level: a routed request must come out of the edge with a per-route
// span name AND a method-stripped http.route attribute.
//
// The two normalisations differ and only one of them was ever wrong, so both
// pattern shapes are exercised. A bare-path registration ("/probe/{id}") is the
// overwhelming majority of the daemon's routes and normalises to itself; a
// method-scoped one ("POST /probe/{id}") carries its verb in r.Pattern, and
// stamping that verbatim — which is what the previous call-site middleware did
// — put "POST " inside http.route.
func TestWrapEdgeHandlerNamesAndStampsRoute(t *testing.T) {
	for _, tc := range []struct {
		name      string
		pattern   string
		method    string
		target    string
		wantName  string
		wantRoute string
	}{
		{
			name:      "bare path pattern",
			pattern:   "/probe/{id}",
			method:    http.MethodGet,
			target:    "/probe/abc123",
			wantName:  "GET /probe/{id}",
			wantRoute: "/probe/{id}",
		},
		{
			name:      "method scoped pattern",
			pattern:   "POST /probe/{id}",
			method:    http.MethodPost,
			target:    "/probe/abc123",
			wantName:  "POST /probe/{id}",
			wantRoute: "/probe/{id}",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sr := recordEdgeSpans(t)

			mux := http.NewServeMux()
			mux.HandleFunc(tc.pattern, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})
			h := tracing.WrapEdgeHandler(mux, "test.edge")

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d: the request never reached the route",
					rec.Code, http.StatusNoContent)
			}

			ended := sr.Ended()
			if len(ended) != 1 {
				t.Fatalf("recorded %d spans, want 1", len(ended))
			}
			if got := ended[0].Name(); got != tc.wantName {
				t.Errorf("span name = %q, want %q — every route collapses onto one constant name, "+
					"which is the whole defect", got, tc.wantName)
			}
			got := routeAttrs(ended[0])
			if len(got) != 1 || got[0] != tc.wantRoute {
				t.Errorf("span http.route = %q, want exactly [%q]. The value must be the "+
					"method-stripped route otelhttp's own httpRoute() would produce; anything "+
					"else disagrees with the metric attribute and splits the route's buckets",
					got, tc.wantRoute)
			}
		})
	}
}

// TestWrapEdgeHandlerLeavesUnroutedRequestAlone covers the fallback branch of
// both options. A handler that is not a mux never sets r.Pattern — that is the
// api.NewServer edge, which dispatches internally — and so does a 404. Such a
// request keeps the operation name and must NOT carry http.route: an empty
// route attribute is worse than an absent one, because it mints a bogus
// aggregation bucket that looks like a real route.
func TestWrapEdgeHandlerLeavesUnroutedRequestAlone(t *testing.T) {
	t.Run("handler without a mux", func(t *testing.T) {
		sr := recordEdgeSpans(t)

		inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		h := tracing.WrapEdgeHandler(inner, "test.edge")
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/anything", nil))

		ended := sr.Ended()
		if len(ended) != 1 {
			t.Fatalf("recorded %d spans, want 1", len(ended))
		}
		if got := ended[0].Name(); got != "test.edge" {
			t.Errorf("span name = %q, want the operation %q", got, "test.edge")
		}
		if got := routeAttrs(ended[0]); len(got) != 0 {
			t.Errorf("span carries http.route = %q for a request that was never routed, "+
				"want the attribute absent", got)
		}
	})

	// The api.NewServer edge shape, and the case a reader is most likely to get
	// wrong: serveEdge DOES route through a mux, but hands it
	// r.WithContext(ctx) — a shallow copy. ServeMux stamps Pattern onto the
	// copy, so the request otelhttp holds never sees it. That, not the absence
	// of a mux, is why that edge keeps its operation name.
	//
	// It is also the mechanism the daemon's middleware ordering depends on:
	// the wrapper sits below RequestIDMiddleware precisely because that
	// middleware copies the same way.
	t.Run("mux behind a cloning middleware", func(t *testing.T) {
		sr := recordEdgeSpans(t)

		mux := http.NewServeMux()
		mux.HandleFunc("/probe/{id}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		cloning := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mux.ServeHTTP(w, r.WithContext(r.Context()))
		})
		h := tracing.WrapEdgeHandler(cloning, "test.edge")
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/probe/abc", nil))

		ended := sr.Ended()
		if len(ended) != 1 {
			t.Fatalf("recorded %d spans, want 1", len(ended))
		}
		if got := ended[0].Name(); got != "test.edge" {
			t.Errorf("span name = %q, want the operation %q: a middleware that copies the "+
				"request keeps ServeMux's Pattern off the request otelhttp holds", got, "test.edge")
		}
		if got := routeAttrs(ended[0]); len(got) != 0 {
			t.Errorf("span carries http.route = %q behind a cloning middleware, "+
				"want the attribute absent", got)
		}
	})

	t.Run("mux miss", func(t *testing.T) {
		sr := recordEdgeSpans(t)

		mux := http.NewServeMux()
		mux.HandleFunc("/probe/{id}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		h := tracing.WrapEdgeHandler(mux, "test.edge")

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/no/such/route", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
		}

		ended := sr.Ended()
		if len(ended) != 1 {
			t.Fatalf("recorded %d spans, want 1", len(ended))
		}
		if got := ended[0].Name(); got != "test.edge" {
			t.Errorf("span name = %q, want the operation %q", got, "test.edge")
		}
		if got := routeAttrs(ended[0]); len(got) != 0 {
			t.Errorf("404 span carries http.route = %q, want the attribute absent", got)
		}
	})
}

// proxyShapedMux builds the shape cmd/helm-ai-kernel/proxy_cmd.go serves: a
// bare *http.ServeMux with a couple of real endpoints plus a terminal "/"
// catch-all that swallows everything else, including every governed LLM call.
// Registration order mirrors that file (catch-all last), though net/http
// resolves by specificity rather than by order.
func proxyShapedMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/helm/proofgraph", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// TestWrapEdgeHandlerKeepsOperationNameOnCatchAll guards the SECOND edge through
// this shared wrapper: the proxy (proxy_cmd.go wraps a bare *http.ServeMux with
// operation "helm.proxy", and that mux ends in `mux.HandleFunc("/",
// proxy.ServeHTTP)`).
//
// Per-route naming is an unambiguous win on a mux of real routes, and an
// unambiguous LOSS on a catch-all: "/" matches every path, so naive naming
// renames every proxy span away from "helm.proxy" and collapses all governed
// LLM traffic onto "POST /" — a label that identifies neither the request nor
// the edge. The guard is therefore two-sided, and both sides run against the
// SAME mux: the catch-all must keep the constant and stamp nothing, while a real
// route beside it must still get its own name and route. A fix that bought the
// first by disabling the feature fails the second.
//
// All three surfaces are asserted per request — span name, span http.route,
// metric http.route — because they are supplied by three different hooks and
// can regress independently.
func TestWrapEdgeHandlerKeepsOperationNameOnCatchAll(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		target string
		// wantName is the span name; wantRoute is "" when the http.route
		// attribute must be absent from BOTH the span and the metric.
		wantName  string
		wantRoute string
	}{
		{
			name:     "governed traffic through the catch-all",
			method:   http.MethodPost,
			target:   "/v1/chat/completions",
			wantName: "helm.proxy",
		},
		{
			name:     "literal root through the catch-all",
			method:   http.MethodGet,
			target:   "/",
			wantName: "helm.proxy",
		},
		{
			name:      "real route on the same mux",
			method:    http.MethodGet,
			target:    "/helm/proofgraph",
			wantName:  "GET /helm/proofgraph",
			wantRoute: "/helm/proofgraph",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The meter is resolved when the handler is built; the tracer per
			// request. So the reader has to be installed before the wrap.
			reader := recordEdgeMetrics(t)
			sr := recordEdgeSpans(t)

			h := tracing.WrapEdgeHandler(proxyShapedMux(), "helm.proxy")

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d: the request never reached a handler",
					rec.Code, http.StatusNoContent)
			}

			ended := sr.Ended()
			if len(ended) != 1 {
				t.Fatalf("recorded %d spans for one request, want 1", len(ended))
			}
			if got := ended[0].Name(); got != tc.wantName {
				t.Errorf("span name = %q, want %q — a route of \"/\" carries no information, so "+
					"renaming the span after it trades the one label that identified the edge for "+
					"nothing", got, tc.wantName)
			}

			wantSpanRoutes := []string{tc.wantRoute}
			wantMetricRoutes := []string{tc.wantRoute}
			if tc.wantRoute == "" {
				wantSpanRoutes = nil
				wantMetricRoutes = []string{routeAbsent}
			}
			if got := routeAttrs(ended[0]); !equalStrings(got, wantSpanRoutes) {
				t.Errorf("span http.route = %v, want %v — the catch-all must stamp no route at all; "+
					"http.route=\"/\" is one aggregation bucket holding every path the proxy serves",
					got, wantSpanRoutes)
			}
			if got := durationRoutes(t, reader); !equalStrings(got, wantMetricRoutes) {
				t.Errorf("http.server.request.duration http.route = %v, want %v (%q means the "+
					"attribute is absent). The span and the metric are fed by different hooks and "+
					"must agree, or a trace cannot be joined to its latency histogram",
					got, wantMetricRoutes, routeAbsent)
			}
		})
	}
}

// TestWrapEdgeHandlerKeepsExactRootRoute is the containment half of the drop
// above: the catch-all loses its name, and NOTHING else does.
//
// It is the case a reader is most likely to worry about — "does this mean a
// route on the root path can never be named?" — and the answer is no, because
// net/http does not spell those two things the same way. A bare "/" is the
// subtree catch-all; an exact match on the root document is "/{$}", a distinct
// pattern that normalises to "/{$}". Registering both on one mux, as here,
// shows net/http hand the root request to the exact route, so adding a
// catch-all never costs an exact root route its identity.
func TestWrapEdgeHandlerKeepsExactRootRoute(t *testing.T) {
	reader := recordEdgeMetrics(t)
	sr := recordEdgeSpans(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := tracing.WrapEdgeHandler(mux, "helm.proxy")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	ended := sr.Ended()
	if len(ended) != 1 {
		t.Fatalf("recorded %d spans for one request, want 1", len(ended))
	}
	if got := ended[0].Name(); got != "GET /{$}" {
		t.Errorf("span name = %q, want %q — an exact root route is a different pattern from the "+
			"catch-all and must keep its own name", got, "GET /{$}")
	}
	if got := routeAttrs(ended[0]); !equalStrings(got, []string{"/{$}"}) {
		t.Errorf("span http.route = %v, want [%q]", got, "/{$}")
	}
	if got := durationRoutes(t, reader); !equalStrings(got, []string{"/{$}"}) {
		t.Errorf("http.server.request.duration http.route = %v, want [%q]", got, "/{$}")
	}
}

// equalStrings compares two attribute-value slices, treating nil and empty as
// the same "attribute absent" answer.
func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestWrapEdgeHandlerFoldsUnknownMethodInSpanName closes the cardinality hole in
// the other half of the name. A bare-path ServeMux pattern matches every
// method, so a caller controls the verb on any of the daemon's bare-path routes
// and, without the fold, controls part of the span name — an unbounded stream
// of distinct names from a single route, which is exactly what per-route naming
// was introduced to stop.
func TestWrapEdgeHandlerFoldsUnknownMethodInSpanName(t *testing.T) {
	sr := recordEdgeSpans(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/probe/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := tracing.WrapEdgeHandler(mux, "test.edge")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("HELM-EXFIL-7f3a", "/probe/abc123", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: a bare-path pattern is expected to match any method",
			rec.Code, http.StatusNoContent)
	}

	ended := sr.Ended()
	if len(ended) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(ended))
	}
	if got := ended[0].Name(); got != "_OTHER /probe/{id}" {
		t.Errorf("span name = %q, want %q — a caller-supplied request-line token reached the "+
			"span name unfolded", got, "_OTHER /probe/{id}")
	}
	if got := routeAttrs(ended[0]); len(got) != 1 || got[0] != "/probe/{id}" {
		t.Errorf("span http.route = %q, want [%q]", got, "/probe/{id}")
	}
}
