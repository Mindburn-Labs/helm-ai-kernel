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
	if inst.decisionDuration == nil {
		t.Error("decisionDuration histogram is nil")
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

	ctx3, pdpSpan := inst.StartPDP(ctx)
	if ctx3 != ctx {
		t.Error("StartPDP should return same context when nil")
	}
	pdpSpan.End()

	ctx4, signSpan := inst.StartSign(ctx)
	if ctx4 != ctx {
		t.Error("StartSign should return same context when nil")
	}
	signSpan.End()

	// Metric helpers must not panic on nil.
	inst.RecordDecision(ctx, "ALLOW", time.Millisecond)
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

	// PDP span.
	_, pdpSpan := inst.StartPDP(ctx)
	pdpSpan.End()

	// Sign span.
	_, signSpan := inst.StartSign(ctx)
	signSpan.End()

	spans := exporter.GetSpans()
	if len(spans) != 3 {
		t.Fatalf("expected 3 spans, got %d", len(spans))
	}

	expectedNames := map[string]bool{
		"guardian.evaluate_decision": false,
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
	assertAttrAbsent(t, s.Attributes, "helm.principal")
	assertAttrAbsent(t, s.Attributes, "helm.action")
	assertAttr(t, s.Attributes, attrVerdict, "DENY")
	assertAttr(t, s.Attributes, attrReasonCode, "budget_exceeded")
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
	inst.decisionDuration, err = inst.meter.Float64Histogram("helm.guardian.decision_duration_ms")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	inst.RecordDecision(ctx, "ALLOW", 5*time.Millisecond)
	inst.RecordDecision(ctx, "DENY", 2*time.Millisecond)

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
		"helm.guardian.decision_duration_ms",
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

func TestEvaluateDecisionRecordsGuardianOTelMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer func() { _ = mp.Shutdown(context.Background()) }()
	tp := sdktrace.NewTracerProvider()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	inst := &OTelInstrumentation{tracer: tp.Tracer("helm.guardian.test"), meter: mp.Meter("helm.guardian.test")}
	var err error
	inst.decisionsTotal, err = inst.meter.Int64Counter("helm.guardian.decisions_total")
	if err != nil {
		t.Fatal(err)
	}
	inst.decisionDuration, err = inst.meter.Float64Histogram("helm.guardian.decision_duration_ms")
	if err != nil {
		t.Fatal(err)
	}

	guard := NewGuardian(&MockSigner{}, nil, nil, WithOTelInstrumentation(inst), WithClock(wallClock{}))
	_, _ = guard.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent",
		Action:    "read",
		Resource:  "resource",
	})

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, metric := range sm.Metrics {
			if metric.Name == "helm.guardian.decisions_total" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("EvaluateDecision did not record helm.guardian.decisions_total")
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

func assertAttrAbsent(t *testing.T, attrs []attribute.KeyValue, key string) {
	t.Helper()
	for _, a := range attrs {
		if string(a.Key) == key {
			t.Errorf("attribute %q must not be exported", key)
			return
		}
	}
}
