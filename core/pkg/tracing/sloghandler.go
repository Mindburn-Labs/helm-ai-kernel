package tracing

import (
	"context"
	"log/slog"

	oteltrace "go.opentelemetry.io/otel/trace"
)

// slogHandler decorates a slog.Handler so every record carries the request
// identity found in the context. Call sites only need to use the Context
// variants (slog.InfoContext etc.) — no per-callsite attributes.
type slogHandler struct {
	slog.Handler
}

// NewSlogHandler wraps h so records logged with a context are stamped with
// the identity fields present in that context: correlation_id (product
// identity, telemetry contract §2.2) and trace_id/span_id (W3C trace
// context) when a recording span is active. Install it as the root handler.
// Caveat: under an open WithGroup the stamped fields land inside that group;
// keep identity-bearing loggers ungrouped.
func NewSlogHandler(h slog.Handler) slog.Handler {
	return &slogHandler{Handler: h}
}

func (h *slogHandler) Handle(ctx context.Context, r slog.Record) error {
	if corr, ok := GetCorrelationID(ctx); ok {
		r.AddAttrs(slog.String("correlation_id", string(corr)))
	}
	if sc := oteltrace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	return h.Handler.Handle(ctx, r)
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &slogHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *slogHandler) WithGroup(name string) slog.Handler {
	return &slogHandler{Handler: h.Handler.WithGroup(name)}
}
