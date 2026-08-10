package observability

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// slowSpanProcessor stalls Shutdown until either its delay elapses or the
// caller's context expires. With a delay longer than any budget under test it
// is a deterministic stand-in for the real failure mode: the batch span
// processor drains on its own context.Background() with a 30s export timeout,
// so against an unreachable collector it sits on whatever deadline it is given.
type slowSpanProcessor struct{ delay time.Duration }

func (slowSpanProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (slowSpanProcessor) OnEnd(sdktrace.ReadOnlySpan)                     {}
func (slowSpanProcessor) ForceFlush(context.Context) error                { return nil }

func (p slowSpanProcessor) Shutdown(ctx context.Context) error {
	select {
	case <-time.After(p.delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// recordingMetricExporter captures the state of the context the metric pipeline
// is shut down with. PeriodicReader.Shutdown always calls exporter.Shutdown, so
// this observation does not depend on there being pending metric data.
type recordingMetricExporter struct {
	mu             sync.Mutex
	shutdownCalled bool
	shutdownCtxErr error
}

func (e *recordingMetricExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return sdkmetric.DefaultTemporalitySelector(k)
}

func (e *recordingMetricExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(k)
}

func (e *recordingMetricExporter) Export(context.Context, *metricdata.ResourceMetrics) error {
	return nil
}

func (e *recordingMetricExporter) ForceFlush(context.Context) error { return nil }

func (e *recordingMetricExporter) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.shutdownCalled = true
	e.shutdownCtxErr = ctx.Err()
	return nil
}

func (e *recordingMetricExporter) observed() (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.shutdownCalled, e.shutdownCtxErr
}

// TestProviderShutdownReportsTraceFailure pins that Shutdown surfaces the
// failure instead of swallowing it. It used to `return nil` unconditionally,
// which made every caller's error branch — including the daemon's
// "[helm] observability shutdown error:" log line — unreachable, so an operator
// grepping for that line concluded a dropped flush had succeeded.
func TestProviderShutdownReportsTraceFailure(t *testing.T) {
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(slowSpanProcessor{delay: time.Minute}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	p := &Provider{tracerProvider: tp, logger: slog.Default()}
	if err := p.Shutdown(ctx); err == nil {
		t.Error("Shutdown returned nil while the trace provider failed to flush: " +
			"the caller's error branch is unreachable and a dropped batch looks like a clean shutdown")
	}
}

// TestProviderShutdownReportsMetricFailure is the same guard for the metric
// half, which had the identical swallow.
func TestProviderShutdownReportsMetricFailure(t *testing.T) {
	exp := &recordingMetricExporter{}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)),
	)

	expired, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-expired.Done()

	p := &Provider{meterProvider: mp, logger: slog.Default()}
	if err := p.Shutdown(expired); err == nil {
		t.Error("Shutdown returned nil while the metric provider was handed a dead context: " +
			"a starved RED-metric flush is reported as success")
	}
}

// TestProviderShutdownTraceCannotStarveMetrics pins the per-provider budget
// split. The two providers are shut down sequentially; sharing one deadline lets
// a stuck trace export consume the entire budget, and the metric flush then gets
// a context that is already done — dropping up to a full PeriodicReader interval
// (15s) of helm.requests/errors/duration on every SIGTERM against a degraded
// collector.
func TestProviderShutdownTraceCannotStarveMetrics(t *testing.T) {
	tp := sdktrace.NewTracerProvider(
		// Never completes inside the budget: the trace half will always sit on
		// its deadline, which is exactly the degraded-collector case.
		sdktrace.WithSpanProcessor(slowSpanProcessor{delay: time.Minute}),
	)
	exp := &recordingMetricExporter{}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	p := &Provider{tracerProvider: tp, meterProvider: mp, logger: slog.Default()}
	_ = p.Shutdown(ctx)

	called, ctxErr := exp.observed()
	if !called {
		t.Fatal("the metric exporter was never shut down")
	}
	if ctxErr != nil {
		t.Errorf("metric flush ran on an exhausted context (%v): the trace shutdown consumed "+
			"the whole budget, so RED metrics are dropped. Each provider must get its own slice.", ctxErr)
	}
}

// TestTraceFlushBudgetLeavesRoomForTheSecondProvider covers the splitter
// directly, including the shapes the daemon can hand it.
func TestTraceFlushBudgetLeavesRoomForTheSecondProvider(t *testing.T) {
	t.Run("reserve is held back, not half the budget", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		child, childCancel := traceFlushBudget(parent, 100*time.Millisecond)
		defer childCancel()

		childDeadline, ok := child.Deadline()
		if !ok {
			t.Fatal("traceFlushBudget dropped the deadline")
		}
		parentDeadline, _ := parent.Deadline()
		if !childDeadline.Before(parentDeadline) {
			t.Errorf("child deadline %v is not earlier than the parent's %v: the second "+
				"provider is left with nothing", childDeadline, parentDeadline)
		}
		// The point of the change: with a 100ms reserve out of 1s the trace
		// flush keeps ~900ms, not the 500ms an unconditional halving gave it.
		// Anything at or below half means the reserve is being ignored and the
		// budget is still being split down the middle.
		if remaining := time.Until(childDeadline); remaining <= 500*time.Millisecond {
			t.Errorf("trace flush kept %v of a 1s budget with a 100ms reserve, want ~900ms: "+
				"half the budget is being discarded even though the metric flush cannot use it",
				remaining)
		}
	})

	t.Run("reserve cannot exceed half the remaining budget", func(t *testing.T) {
		// A reserve larger than the whole budget must not hand the trace flush a
		// negative (i.e. already-expired) timeout, and must not swallow the
		// budget either: it degrades to the old even split.
		parent, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		child, childCancel := traceFlushBudget(parent, time.Minute)
		defer childCancel()

		childDeadline, ok := child.Deadline()
		if !ok {
			t.Fatal("traceFlushBudget dropped the deadline")
		}
		remaining := time.Until(childDeadline)
		if remaining <= 0 {
			t.Fatalf("trace flush got %v: an oversized reserve produced a dead context, so the "+
				"trace half is skipped entirely", remaining)
		}
		if remaining > 150*time.Millisecond {
			t.Errorf("trace flush kept %v of a 200ms budget, want at most half: an oversized "+
				"reserve must still leave the metric flush its share", remaining)
		}
	})

	t.Run("no deadline is passed through", func(t *testing.T) {
		child, cancel := traceFlushBudget(context.Background(), metricFlushReserve)
		defer cancel()
		if _, ok := child.Deadline(); ok {
			t.Error("traceFlushBudget invented a deadline for a context that had none")
		}
	})

	t.Run("expired parent stays expired", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		<-parent.Done()

		child, childCancel := traceFlushBudget(parent, metricFlushReserve)
		defer childCancel()
		if child.Err() == nil {
			t.Error("traceFlushBudget handed out a live context derived from an expired one")
		}
	})
}

// deadlineRecordingSpanProcessor captures how much time the trace flush was
// actually given, and returns immediately. Observing the DEADLINE rather than
// waiting to see whether a slow flush completes keeps this deterministic: the
// property under test ("the trace flush is not capped at half the budget") is a
// statement about the budget, not about wall-clock luck on a loaded CI box.
type deadlineRecordingSpanProcessor struct {
	mu        sync.Mutex
	seen      bool
	remaining time.Duration
	hadNone   bool
}

func (*deadlineRecordingSpanProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (*deadlineRecordingSpanProcessor) OnEnd(sdktrace.ReadOnlySpan)                     {}
func (*deadlineRecordingSpanProcessor) ForceFlush(context.Context) error                { return nil }

func (p *deadlineRecordingSpanProcessor) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = true
	deadline, ok := ctx.Deadline()
	if !ok {
		p.hadNone = true
		return nil
	}
	p.remaining = time.Until(deadline)
	return nil
}

func (p *deadlineRecordingSpanProcessor) observed() (bool, time.Duration, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen, p.remaining, p.hadNone
}

// TestProviderShutdownGivesTraceMoreThanHalfTheBudget is the MAJOR-finding
// guard: the trace flush used to be capped at half the caller's budget
// unconditionally, so on the daemon's 5s observabilityFlushTimeout a collector
// that needed 2.5-5s to accept the final batch lost it — while the other 2.5s
// sat unused, since the metric flush is one Collect plus one export.
//
// The budget below is the daemon's real 5s so the numbers in the failure
// message are the ones an operator would be losing.
func TestProviderShutdownGivesTraceMoreThanHalfTheBudget(t *testing.T) {
	const budget = 5 * time.Second

	proc := &deadlineRecordingSpanProcessor{}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(proc))
	exp := &recordingMetricExporter{}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)))

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	p := &Provider{tracerProvider: tp, meterProvider: mp, logger: slog.Default()}
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	seen, remaining, hadNone := proc.observed()
	if !seen {
		t.Fatal("the trace provider was never shut down")
	}
	if hadNone {
		t.Fatal("the trace flush got a context with no deadline: the caller's budget is not being " +
			"applied to it at all")
	}
	if remaining <= budget/2 {
		t.Errorf("trace flush was given %v of a %v budget, want more than half (~%v): capping it at "+
			"half throws away time the metric flush cannot use, and drops the final span batch "+
			"against any collector that needs longer than %v",
			remaining, budget, budget-metricFlushReserve, budget/2)
	}
	if remaining > budget-metricFlushReserve {
		t.Errorf("trace flush was given %v of a %v budget, want at most %v: the metric flush must "+
			"keep its %v reserve", remaining, budget, budget-metricFlushReserve, metricFlushReserve)
	}
}
