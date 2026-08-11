package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	helmapi "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// recordMetrics installs an SDK MeterProvider backed by a ManualReader as the
// global one and returns the reader.
//
// otelhttp resolves its meter at CONSTRUCTION time — newConfig (config.go) calls
// otel.GetMeterProvider().Meter(...) while the options are applied — so this
// must run before buildAPIHandler, unlike the tracer, which is resolved per
// request.
func recordMetrics(t *testing.T) *sdkmetric.ManualReader {
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

// routeAbsent is what durationRoutes reports for a datapoint carrying no
// http.route attribute at all.
//
// Deliberately not "". An ABSENT attribute and a PRESENT-but-empty one are
// different regressions with different consequences — an empty route mints a
// bogus aggregation bucket that reads like a real one — and collapsing both to
// "" left the unrouted-request assertion below unable to fail: dropping the
// empty-route guard in edgeMetricAttributes kept it green. A real route always
// begins with "/" (routeFromPattern returns everything from the first slash),
// so this sentinel cannot collide with one.
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

// spanRoutes returns the http.route attributes on the span. A slice, not a
// bare string, so a failure message can tell "attribute absent" ([]) apart from
// "attribute present with the wrong value" — the two regressions here have
// different causes. In practice the length is 0 or 1: the SDK deduplicates
// attributes by key when they are read (sdk/trace span.go SetAttributes).
func spanRoutes(span sdktrace.ReadOnlySpan) []string {
	var routes []string
	for _, attr := range span.Attributes() {
		if attr.Key == semconv.HTTPRouteKey {
			routes = append(routes, attr.Value.AsString())
		}
	}
	return routes
}

// recordSpans installs an in-memory TracerProvider as the global one and
// returns its recorder. otelhttp resolves the tracer per request from the
// global provider, so this is what the daemon's handler will use.
func recordSpans(t *testing.T) *tracetest.SpanRecorder {
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

// TestBuildAPIHandlerStartsServerSpan is the regression guard for HELM-495: the
// daemon exported zero spans because nothing on its request path ever started
// one — api.NewServer carried the only WrapEdgeHandler call and the daemon does
// not use api.NewServer. If the wrapper is dropped from buildAPIHandler again,
// no span is recorded and this test fails.
func TestBuildAPIHandlerStartsServerSpan(t *testing.T) {
	sr := recordSpans(t)

	var seen oteltrace.SpanContext
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/probe", func(w http.ResponseWriter, r *http.Request) {
		seen = oteltrace.SpanContextFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})

	h := buildAPIHandler(mux, helmapi.NewGlobalRateLimiter(100, 100))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/probe", nil))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("handler status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if !seen.IsValid() {
		t.Error("route handler saw no span in r.Context(): the request path is untraced, " +
			"so *Context log call sites cannot stamp trace_id")
	}

	ended := sr.Ended()
	if len(ended) == 0 {
		t.Fatal("no span recorded for a served request: buildAPIHandler is not wrapped in tracing.WrapEdgeHandler")
	}
	span := ended[0]
	// Per-route, not the "helm.api" operation: the operation is the fallback for
	// a request the mux never matched. Dropping WithSpanNameFormatter from
	// tracing.WrapEdgeHandler puts "helm.api" back here.
	if got := span.Name(); got != "GET /api/v1/probe" {
		t.Errorf("span name = %q, want %q", got, "GET /api/v1/probe")
	}
	if got := span.SpanKind(); got != oteltrace.SpanKindServer {
		t.Errorf("span kind = %v, want %v", got, oteltrace.SpanKindServer)
	}
}

// TestBuildAPIHandlerRootsInboundTraceparent proves an external caller cannot
// choose the daemon's trace ID or suppress its server span via remote sampling.
func TestBuildAPIHandlerRootsInboundTraceparent(t *testing.T) {
	sr := recordSpans(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/probe", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := buildAPIHandler(mux, helmapi.NewGlobalRateLimiter(100, 100))

	const inboundTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	req := httptest.NewRequest(http.MethodGet, "/api/v1/probe", nil)
	req.Header.Set("traceparent", "00-"+inboundTraceID+"-00f067aa0ba902b7-00")
	h.ServeHTTP(httptest.NewRecorder(), req)

	ended := sr.Ended()
	if len(ended) == 0 {
		t.Fatal("no span recorded for a served request")
	}
	if got := ended[0].SpanContext().TraceID().String(); got == inboundTraceID {
		t.Errorf("server span adopted untrusted trace_id %s", got)
	}
	links := ended[0].Links()
	if len(links) != 1 || links[0].SpanContext.TraceID().String() != inboundTraceID {
		t.Errorf("server span links = %+v, want one link to inbound trace %s", links, inboundTraceID)
	}
}

// TestBuildAPIHandlerTracesRateLimitedRequest pins the wrapper's POSITION, not
// just its presence: the span must be started OUTSIDE the rate limiter, so a
// rejected request is still visible in the trace. Moving
// tracing.WrapEdgeHandler inside rateLimiter.Middleware keeps the first test
// green and makes this one fail.
func TestBuildAPIHandlerTracesRateLimitedRequest(t *testing.T) {
	sr := recordSpans(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/probe", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// One token, no refill worth waiting for: the second request is denied
	// by the limiter and never reaches the mux.
	h := buildAPIHandler(mux, helmapi.NewGlobalRateLimiter(1, 1))

	var lastCode int
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/probe", nil))
		lastCode = rec.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("last request status = %d, want %d — the limiter did not reject, "+
			"so this test is not exercising the rejected path", lastCode, http.StatusTooManyRequests)
	}

	if got := len(sr.Ended()); got != 3 {
		t.Errorf("recorded %d spans for 3 requests (one rejected by the rate limiter), want 3: "+
			"the tracing wrapper must sit outside rateLimiter.Middleware", got)
	}
}

// TestServedPathLogRecordCarriesTraceID is the end-to-end proof of the whole
// point of HELM-495: a log line emitted while serving a request can be joined
// to its span on trace_id. It fails if EITHER half regresses — the span (the
// wrapper in buildAPIHandler) or the context (a *Context slog call site, here
// api.WriteInternalR).
func TestServedPathLogRecordCarriesTraceID(t *testing.T) {
	sr := recordSpans(t)

	var buf bytes.Buffer
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(tracing.NewSlogHandler(slog.NewTextHandler(&buf, nil))))
	t.Cleanup(func() { slog.SetDefault(prevLogger) })

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/probe", func(w http.ResponseWriter, r *http.Request) {
		helmapi.WriteInternalR(w, r, errors.New("boom"))
	})
	h := buildAPIHandler(mux, helmapi.NewGlobalRateLimiter(100, 100))

	const inboundTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	req := httptest.NewRequest(http.MethodGet, "/api/v1/probe", nil)
	req.Header.Set("traceparent", "00-"+inboundTraceID+"-00f067aa0ba902b7-01")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	ended := sr.Ended()
	if len(ended) == 0 {
		t.Fatal("no span recorded for a served request")
	}
	wantTraceID := ended[0].SpanContext().TraceID().String()

	logged := buf.String()
	if !strings.Contains(logged, "trace_id="+wantTraceID) {
		t.Errorf("served-path log record does not carry the span's trace_id.\nwant trace_id=%s\ngot: %s",
			wantTraceID, logged)
	}
	if strings.Contains(logged, "trace_id="+inboundTraceID) {
		t.Errorf("served-path log record adopted the untrusted trace_id %s: %s", inboundTraceID, logged)
	}
}

// TestBuildAPIHandlerDoesNotTraceCORSPreflight pins the OTHER end of the
// wrapper's position, and records the accepted cost of moving it inside the
// middleware stack.
//
// CORSMiddleware answers a preflight itself, before the span starts, so a
// preflight is no longer a span. That trade was taken deliberately: the wrapper
// has to sit inside RequestIDMiddleware for per-route naming to be possible at
// all (see buildAPIHandler), and a preflight carries no governance decision.
// If this test starts failing, the wrapper has drifted back outside CORS and the
// http.route guard below is about to stop working.
func TestBuildAPIHandlerDoesNotTraceCORSPreflight(t *testing.T) {
	sr := recordSpans(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/probe", func(http.ResponseWriter, *http.Request) {
		t.Error("preflight reached the route handler")
	})
	h := buildAPIHandler(mux, helmapi.NewGlobalRateLimiter(100, 100))

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/probe", nil)
	req.Header.Set("Origin", "https://console.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got := len(sr.Ended()); got != 0 {
		t.Errorf("CORS preflight produced %d span(s), want 0: the tracing wrapper has moved back "+
			"outside CORSMiddleware, which puts it outside RequestIDMiddleware's request clone too "+
			"and makes http.route unreachable", got)
	}
}

// TestServedRouteIsNamedAndMeasured is the HELM-495 finding-1 end-to-end proof,
// taken through the real buildAPIHandler with a live SDK TracerProvider and an
// sdkmetric.ManualReader. One routed request has to come out carrying all three
// facts at once:
//
//   - the span NAME is per-route, not the constant "helm.api" operation;
//   - the span's http.route ATTRIBUTE is the method-stripped route;
//   - the http.server.request.duration datapoint carries the SAME http.route,
//     so a trace and its latency histogram join on one key.
//
// Asserting them together is the point. Each is supplied by a different otelhttp
// hook (WithSpanNameFormatter, withRouteAttribute inside the wrapper,
// WithMetricAttributesFn), and the failure that mattered was the three
// disagreeing rather than any one being absent.
//
// Both pattern shapes are exercised because they normalise differently and only
// one of them was ever broken. r.Pattern for a method-scoped registration is
// "POST /probe/{id}" — method included — while otelhttp's own normaliser
// (internal/semconv/util.go httpRoute) returns everything from the first slash.
// Stamping Pattern verbatim, which is what the previous middleware did, put
// "POST " inside http.route for exactly those routes and left the bare-path
// majority looking correct.
func TestServedRouteIsNamedAndMeasured(t *testing.T) {
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
			pattern:   "/api/v1/probe/{id}",
			method:    http.MethodGet,
			target:    "/api/v1/probe/abc123",
			wantName:  "GET /api/v1/probe/{id}",
			wantRoute: "/api/v1/probe/{id}",
		},
		{
			name:      "method scoped pattern",
			pattern:   "POST /api/v1/probe/{id}",
			method:    http.MethodPost,
			target:    "/api/v1/probe/abc123",
			wantName:  "POST /api/v1/probe/{id}",
			wantRoute: "/api/v1/probe/{id}",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The meter is resolved when the handler is built, so the reader has
			// to be installed first.
			reader := recordMetrics(t)
			sr := recordSpans(t)

			mux := http.NewServeMux()
			mux.HandleFunc(tc.pattern, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})
			h := buildAPIHandler(mux, helmapi.NewGlobalRateLimiter(100, 100))

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d: the request never reached the route",
					rec.Code, http.StatusNoContent)
			}

			ended := sr.Ended()
			if len(ended) != 1 {
				t.Fatalf("recorded %d spans for one request, want 1", len(ended))
			}

			if got := ended[0].Name(); got != tc.wantName {
				t.Errorf("span name = %q, want %q — without a per-route name every one of the "+
					"daemon's routes shares one span name and the trace view cannot separate them",
					got, tc.wantName)
			}
			if got := spanRoutes(ended[0]); len(got) != 1 || got[0] != tc.wantRoute {
				t.Errorf("span http.route = %q, want exactly [%q]", got, tc.wantRoute)
			}
			if got := durationRoutes(t, reader); len(got) != 1 || got[0] != tc.wantRoute {
				t.Errorf("http.server.request.duration http.route = %q, want exactly [%q] — the "+
					"latency histogram cannot be split per route, and does not join the span",
					got, tc.wantRoute)
			}
		})
	}
}

// TestBuildAPIHandlerLeavesUnroutedRequestsAlone checks the fallback branch on
// all three surfaces: a 404 has no pattern, so it keeps the operation name and
// carries no http.route anywhere. An empty route is worse than an absent one —
// it mints a bogus aggregation bucket that reads as a real route.
func TestBuildAPIHandlerLeavesUnroutedRequestsAlone(t *testing.T) {
	reader := recordMetrics(t)
	sr := recordSpans(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /probe/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := buildAPIHandler(mux, helmapi.NewGlobalRateLimiter(100, 100))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/no/such/route", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	ended := sr.Ended()
	if len(ended) != 1 {
		t.Fatalf("recorded %d spans for an unrouted request, want 1", len(ended))
	}
	if got := ended[0].Name(); got != "helm.api" {
		t.Errorf("unrouted span name = %q, want the operation %q", got, "helm.api")
	}
	if got := spanRoutes(ended[0]); len(got) != 0 {
		t.Errorf("unrouted request carries span http.route = %q, want the attribute absent", got)
	}
	if got := durationRoutes(t, reader); len(got) != 1 || got[0] != routeAbsent {
		t.Errorf("http.server.request.duration http.route = %q for an unrouted request, "+
			"want exactly one datapoint with the attribute ABSENT (%q). A present-but-empty "+
			"route is the regression this distinguishes: it mints an aggregation bucket that "+
			"reads like a real route on every 404.", got, routeAbsent)
	}
}
