package guardian

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestNewOTelInstrumentation(t *testing.T) {
	inst, err := newOTelInstrumentation()
	if err != nil {
		t.Fatalf("newOTelInstrumentation() error: %v", err)
	}
	if inst == nil {
		t.Fatal("expected non-nil instrumentation")
	}
	if inst.tracer == nil {
		t.Error("tracer is nil")
	}
	if inst.meter == nil {
		t.Error("meter is nil")
	}
	if inst.decisionsTotal == nil {
		t.Error("decisionsTotal counter is nil")
	}
	if inst.gateDenialsTotal == nil {
		t.Error("gateDenialsTotal counter is nil")
	}
	if inst.decisionDuration == nil {
		t.Error("decisionDuration histogram is nil")
	}
	if inst.gateDuration == nil {
		t.Error("gateDuration histogram is nil")
	}
}

func TestNilOTelSafe(t *testing.T) {
	// All methods must be safe to call on nil receiver.
	var inst *OTelInstrumentation
	ctx := context.Background()

	ctx2, span := inst.StartDecision(ctx, "agent-1", "read")
	if ctx2 != ctx {
		t.Error("StartDecision should return same context when nil")
	}
	span.End() // Must not panic.

	inst.EndDecision(span, "ALLOW", "ok")

	ctx3, gateSpan := inst.StartGate(ctx, "freeze")
	if ctx3 != ctx {
		t.Error("StartGate should return same context when nil")
	}
	gateSpan.End()

	inst.EndGate(gateSpan, true)

	ctx4, pdpSpan := inst.StartPDP(ctx)
	if ctx4 != ctx {
		t.Error("StartPDP should return same context when nil")
	}
	pdpSpan.End()

	ctx5, signSpan := inst.StartSign(ctx)
	if ctx5 != ctx {
		t.Error("StartSign should return same context when nil")
	}
	signSpan.End()

	// Metric helpers must not panic on nil.
	inst.RecordDecision(ctx, "ALLOW", time.Millisecond)
	inst.RecordGateDenial(ctx, "freeze")
	inst.RecordGateDuration(ctx, "freeze", time.Microsecond)
}

func TestOTelSpanNames(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	inst := &OTelInstrumentation{
		tracer: tp.Tracer("helm.guardian.test"),
	}
	// Metrics aren't needed for span name testing; leave counters nil
	// but since RecordDecision etc. are not called, this is safe.

	ctx := context.Background()

	// Root decision span.
	ctx, rootSpan := inst.StartDecision(ctx, "test-agent", "execute")
	inst.EndDecision(rootSpan, "ALLOW", "policy_match")

	// Gate span.
	_, gateSpan := inst.StartGate(ctx, "threat")
	inst.EndGate(gateSpan, true)

	// PDP span.
	_, pdpSpan := inst.StartPDP(ctx)
	pdpSpan.End()

	// Sign span.
	_, signSpan := inst.StartSign(ctx)
	signSpan.End()

	spans := exporter.GetSpans()
	if len(spans) != 4 {
		t.Fatalf("expected 4 spans, got %d", len(spans))
	}

	expectedNames := map[string]bool{
		"guardian.evaluate_decision": false,
		"guardian.gate.threat":       false,
		"guardian.pdp":               false,
		"guardian.sign":              false,
	}
	for _, s := range spans {
		if _, ok := expectedNames[s.Name]; ok {
			expectedNames[s.Name] = true
		}
	}
	for name, found := range expectedNames {
		if !found {
			t.Errorf("expected span %q not found", name)
		}
	}
}

func TestOTelSpanAttributes(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	inst := &OTelInstrumentation{
		tracer: tp.Tracer("helm.guardian.test"),
	}

	ctx := context.Background()
	ctx, rootSpan := inst.StartDecision(ctx, "principal-42", "delete_file")
	inst.EndDecision(rootSpan, "DENY", "budget_exceeded")

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	s := spans[0]
	assertAttr(t, s.Attributes, attrPrincipal, "principal-42")
	assertAttr(t, s.Attributes, attrAction, "delete_file")
	assertAttr(t, s.Attributes, attrVerdict, "DENY")
	assertAttr(t, s.Attributes, attrReasonCode, "budget_exceeded")
}

func TestOTelGatePassedAttribute(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	inst := &OTelInstrumentation{
		tracer: tp.Tracer("helm.guardian.test"),
	}

	ctx := context.Background()
	_, span := inst.StartGate(ctx, "egress")
	inst.EndGate(span, false)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	assertAttrBool(t, spans[0].Attributes, attrGatePassed, false)
}

func TestOTelMetricsRecorded(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer func() { _ = mp.Shutdown(context.Background()) }()

	inst := &OTelInstrumentation{
		meter: mp.Meter("helm.guardian.test"),
	}

	var err error
	inst.decisionsTotal, err = inst.meter.Int64Counter("helm.guardian.decisions_total")
	if err != nil {
		t.Fatal(err)
	}
	inst.gateDenialsTotal, err = inst.meter.Int64Counter("helm.guardian.gate_denials_total")
	if err != nil {
		t.Fatal(err)
	}
	inst.decisionDuration, err = inst.meter.Float64Histogram("helm.guardian.decision_duration_ms")
	if err != nil {
		t.Fatal(err)
	}
	inst.gateDuration, err = inst.meter.Float64Histogram("helm.guardian.gate_duration_ms")
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	inst.RecordDecision(ctx, "ALLOW", 5*time.Millisecond)
	inst.RecordDecision(ctx, "DENY", 2*time.Millisecond)
	inst.RecordGateDenial(ctx, "freeze")
	inst.RecordGateDuration(ctx, "freeze", 100*time.Microsecond)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}

	// Verify we have metrics recorded.
	if len(rm.ScopeMetrics) == 0 {
		t.Fatal("expected scope metrics")
	}

	metricNames := make(map[string]bool)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			metricNames[m.Name] = true
		}
	}

	for _, name := range []string{
		"helm.guardian.decisions_total",
		"helm.guardian.gate_denials_total",
		"helm.guardian.decision_duration_ms",
		"helm.guardian.gate_duration_ms",
	} {
		if !metricNames[name] {
			t.Errorf("metric %q not found", name)
		}
	}
}

func TestWithOTelOption(t *testing.T) {
	opt := WithOTel()
	g := &Guardian{}
	opt(g)
	if g.otel == nil {
		t.Error("WithOTel should set otel field")
	}
}

func TestWithOTelInstrumentationOption(t *testing.T) {
	inst, err := newOTelInstrumentation()
	if err != nil {
		t.Fatal(err)
	}
	opt := WithOTelInstrumentation(inst)
	g := &Guardian{}
	opt(g)
	if g.otel != inst {
		t.Error("WithOTelInstrumentation should set exact instance")
	}
}

// assertAttr checks that a string attribute exists with the expected value.
func assertAttr(t *testing.T, attrs []attribute.KeyValue, key, want string) {
	t.Helper()
	for _, a := range attrs {
		if string(a.Key) == key {
			if got := a.Value.AsString(); got != want {
				t.Errorf("attribute %q = %q, want %q", key, got, want)
			}
			return
		}
	}
	t.Errorf("attribute %q not found", key)
}

// assertAttrBool checks that a bool attribute exists with the expected value.
func assertAttrBool(t *testing.T, attrs []attribute.KeyValue, key string, want bool) {
	t.Helper()
	for _, a := range attrs {
		if string(a.Key) == key {
			if got := a.Value.AsBool(); got != want {
				t.Errorf("attribute %q = %v, want %v", key, got, want)
			}
			return
		}
	}
	t.Errorf("attribute %q not found", key)
}
