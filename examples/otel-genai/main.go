// This example records an OpenTelemetry GenAI tool-call span with HELM
// governance attributes. The receipt correlation ID also appears as
// gen_ai.tool.call.id.
//
// Run:
//
//	cd examples/otel-genai && go run .
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	helmotel "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/otel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
	otelapi "go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// run records one tool-call span and prints its attributes.
func run(out io.Writer) error {
	ctx := context.Background()

	// NoopTracer uses the global provider, so install the in-memory exporter
	// before constructing the tracer.
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	otelapi.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(ctx) }()

	gt := helmotel.NoopTracer()

	corr := tracing.NewCorrelationID()

	gt.TraceGenAIToolCall(ctx, helmotel.GenAIToolCallEvent{
		System:        observability.GenAISystemOpenAI,
		RequestModel:  "gpt-6-sol",
		ResponseModel: "gpt-6-sol",
		ResponseID:    "chatcmpl-example",
		OperationName: observability.GenAIOperationToolCall,
		ToolName:      "search_web",
		ToolCallID:    string(corr),
		InputTokens:   120,
		OutputTokens:  35,
		FinishReason:  "tool_calls",
		Verdict:       "ALLOW",
		ReasonCode:    "NONE",
		PolicyID:      "bundle-001/rule-001",
		ProofNodeID:   "pg-node-99",
		CorrelationID: string(corr),
		ReceiptID:     "rcpt-proxy-example",
		TenantID:      "tenant-A",
		LatencyMs:     1.2,
	})

	if err := tp.ForceFlush(ctx); err != nil {
		return fmt.Errorf("flush: %w", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		return fmt.Errorf("expected 1 span, got %d", len(spans))
	}
	span := spans[0]

	fmt.Fprintf(out, "Span: %s\n", span.Name)
	fmt.Fprintf(out, "Attributes:\n")
	for _, kv := range span.Attributes {
		fmt.Fprintf(out, "  %-32s %s\n", kv.Key, kv.Value.Emit())
	}
	fmt.Fprintf(out, "\nhelm correlation_id == gen_ai.tool.call.id: %s\n", corr)
	return nil
}
