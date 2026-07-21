package tracing

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/propagation"
)

// WrapEdgeHandler wraps an external HTTP edge in an otelhttp server-span
// handler (HELM-333). An inbound W3C traceparent is continued into the server
// span; the propagator is explicit so the edge behaves the same whether or
// not a global propagator was configured. The tracer is resolved from the
// global TracerProvider at wrap time, so configure OTel before calling this.
func WrapEdgeHandler(h http.Handler, operation string) http.Handler {
	return otelhttp.NewHandler(h, operation,
		otelhttp.WithPropagators(propagation.TraceContext{}),
	)
}
