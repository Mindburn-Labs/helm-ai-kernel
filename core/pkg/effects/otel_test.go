package effects

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestNewEffectsOTelInstrumentation(t *testing.T) {
	inst, err := NewEffectsOTelInstrumentation()
	if err != nil {
		t.Fatalf("NewEffectsOTelInstrumentation() error: %v", err)
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
	if inst.executionsTotal == nil {
		t.Error("executionsTotal counter is nil")
	}
	if inst.executionDuration == nil {
		t.Error("executionDuration histogram is nil")
	}
}

func TestNilEffectsOTelSafe(t *testing.T) {
	var inst *EffectsOTelInstrumentation
	ctx := context.Background()

	ctx2, span := inst.StartExecution(ctx, EffectTypeRead, "github")
	if ctx2 != ctx {
		t.Error("StartExecution should return same context when nil")
	}
	span.End()

	inst.EndSpan(span)
	inst.MarkSuccess(span, true)
	inst.RecordExecution(ctx, EffectTypeRead, "github", true, time.Millisecond)
}

func TestEffectsOTelSpanNames(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	inst := &EffectsOTelInstrumentation{
		tracer: tp.Tracer("helm.effects.test"),
	}

	ctx := context.Background()

	ctx, execSpan := inst.StartExecution(ctx, EffectTypeWrite, "linear")
	inst.MarkSuccess(execSpan, true)
	execSpan.End()

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	expectedNames := map[string]bool{
		"effects.execute": false,
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

func TestEffectsOTelMetricsRecorded(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer func() { _ = mp.Shutdown(context.Background()) }()

	inst := &EffectsOTelInstrumentation{
		meter: mp.Meter("helm.effects.test"),
	}

	var err error
	inst.executionsTotal, err = inst.meter.Int64Counter("helm.effects.executions_total")
	if err != nil {
		t.Fatal(err)
	}
	inst.executionDuration, err = inst.meter.Float64Histogram("helm.effects.execution_duration_ms")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	inst.RecordExecution(ctx, EffectTypeRead, "github", true, 10*time.Millisecond)
	inst.RecordExecution(ctx, EffectTypeWrite, "linear", false, 50*time.Millisecond)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}

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
		"helm.effects.executions_total",
		"helm.effects.execution_duration_ms",
	} {
		if !metricNames[name] {
			t.Errorf("metric %q not found", name)
		}
	}
}
