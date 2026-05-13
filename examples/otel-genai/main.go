// Example: helm-ai-kernel governance tracer emitting OTel GenAI semconv spans.
//
// This program is the canonical end-to-end smoke test for Workstream C of
// the helm-ai-kernel SOTA execution plan. It demonstrates that:
//
//  1. helm-ai-kernel governance spans carry the stable OTel GenAI attribute keys
//     (gen_ai.system, gen_ai.request.model, gen_ai.tool.call.id, ...).
//  2. The helm correlation_id is mirrored into gen_ai.tool.call.id, giving
//     a 1:1 cross-reference between OTel traces and helm-ai-kernel receipts.
//  3. helm-specific governance attributes (helm.verdict, helm.policy_id,
//     helm.proof_node_id) live under the helm.* namespace alongside the
//     gen_ai.* keys on the same span.
//
// Run:
//
//	cd examples/otel-genai && go run .
//
// Smoke test (asserts the same contract):
//
//	cd examples/otel-genai && go test ./...
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

// run wires an in-memory exporter, emits one governed tool-call span, and
// prints the recorded attributes so an operator can eyeball the contract.
// It returns the recorded SpanStubs so the smoke test can assert against
// the exact attribute set.
func run(out io.Writer) error {
	ctx := context.Background()

	// Wire an in-memory exporter so the example is self-contained — no OTel
	// collector needed to demo the contract. Setting the global provider
	// means helmotel.NoopTracer (which calls otel.Tracer("helm.governance.noop"))
	// will pick up our exporter automatically.
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	otelapi.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(ctx) }()

	gt := helmotel.NoopTracer()

	// Generate a helm correlation_id, the same way the helm-ai-kernel proxy does.
	corr := tracing.NewCorrelationID()

	// Emit a governed GenAI tool-call span. This is the wire shape every
	// SIEM exporter consumes.
	gt.TraceGenAIToolCall(ctx, helmotel.GenAIToolCallEvent{
		System:        observability.GenAISystemOpenAI,
		RequestModel:  "gpt-4o",
		ResponseModel: "gpt-4o-2024-08-06",
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

	// Force-flush the exporter pipeline so all spans are visible.
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
