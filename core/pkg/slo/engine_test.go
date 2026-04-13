package slo

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func advancingClock(start time.Time, step time.Duration) func() time.Time {
	current := start
	var mu sync.Mutex
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now := current
		current = current.Add(step)
		return now
	}
}

func TestEngine_RegisterSLO(t *testing.T) {
	e := NewEngine()

	err := e.Register(Objective{
		Name:         "decision-latency",
		Target:       0.999,
		Window:       24 * time.Hour,
		MetricType:   MetricTypeLatency,
		LatencyBound: 50 * time.Millisecond,
	})
	require.NoError(t, err)

	// Verify it appears in AllStatuses.
	statuses := e.AllStatuses()
	require.Len(t, statuses, 1)
	assert.Equal(t, "decision-latency", statuses[0].ObjectiveName)
	assert.Equal(t, 0.999, statuses[0].Target)
}

func TestEngine_RegisterDuplicate(t *testing.T) {
	e := NewEngine()

	obj := Objective{
		Name:       "error-rate",
		Target:     0.99,
		Window:     time.Hour,
		MetricType: MetricTypeErrorRate,
	}
	require.NoError(t, e.Register(obj))

	err := e.Register(obj)
	require.Error(t, err)
	assert.IsType(t, &ErrDuplicateObjective{}, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestEngine_RegisterInvalid(t *testing.T) {
	e := NewEngine()

	tests := []struct {
		name string
		obj  Objective
		want string
	}{
		{
			name: "empty name",
			obj:  Objective{Name: "", Target: 0.99, Window: time.Hour, MetricType: MetricTypeErrorRate},
			want: "name is required",
		},
		{
			name: "zero target",
			obj:  Objective{Name: "x", Target: 0, Window: time.Hour, MetricType: MetricTypeErrorRate},
			want: "target must be in (0, 1]",
		},
		{
			name: "target > 1",
			obj:  Objective{Name: "x", Target: 1.5, Window: time.Hour, MetricType: MetricTypeErrorRate},
			want: "target must be in (0, 1]",
		},
		{
			name: "zero window",
			obj:  Objective{Name: "x", Target: 0.99, Window: 0, MetricType: MetricTypeErrorRate},
			want: "window must be positive",
		},
		{
			name: "unknown metric type",
			obj:  Objective{Name: "x", Target: 0.99, Window: time.Hour, MetricType: "THROUGHPUT"},
			want: "unknown metric type",
		},
		{
			name: "latency without bound",
			obj:  Objective{Name: "x", Target: 0.99, Window: time.Hour, MetricType: MetricTypeLatency},
			want: "latency_bound must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := e.Register(tt.obj)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestEngine_RecordLatencyWithinBound(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	e := NewEngine(WithEngineClock(fixedClock(now)))

	require.NoError(t, e.Register(Objective{
		Name:         "latency-slo",
		Target:       0.99,
		Window:       time.Hour,
		MetricType:   MetricTypeLatency,
		LatencyBound: 50 * time.Millisecond,
	}))

	// Record 10 latencies all within bound.
	for i := 0; i < 10; i++ {
		e.RecordLatency("latency-slo", 30*time.Millisecond)
	}

	status, err := e.Status("latency-slo")
	require.NoError(t, err)
	assert.Equal(t, int64(10), status.TotalEvents)
	assert.Equal(t, int64(10), status.GoodEvents)
	assert.Equal(t, int64(0), status.BadEvents)
	assert.Equal(t, 1.0, status.Current)
	assert.Equal(t, 1.0, status.Remaining)
	assert.False(t, status.Exhausted)
}

func TestEngine_RecordLatencyAboveBound(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	e := NewEngine(WithEngineClock(fixedClock(now)))

	require.NoError(t, e.Register(Objective{
		Name:         "latency-slo",
		Target:       0.90, // 90% target
		Window:       time.Hour,
		MetricType:   MetricTypeLatency,
		LatencyBound: 50 * time.Millisecond,
	}))

	// Record 9 good + 1 bad = 90% compliance.
	for i := 0; i < 9; i++ {
		e.RecordLatency("latency-slo", 30*time.Millisecond)
	}
	e.RecordLatency("latency-slo", 100*time.Millisecond) // Above bound.

	status, err := e.Status("latency-slo")
	require.NoError(t, err)
	assert.Equal(t, int64(10), status.TotalEvents)
	assert.Equal(t, int64(9), status.GoodEvents)
	assert.Equal(t, int64(1), status.BadEvents)
	assert.InDelta(t, 0.9, status.Current, 0.001)
	// Error budget: allowed = 10 * 0.1 = 1 bad event. Used 1. Remaining = 0.
	assert.InDelta(t, 0.0, status.Remaining, 0.001)
	assert.True(t, status.Exhausted)
}

func TestEngine_ErrorBudgetCalculation(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	e := NewEngine(WithEngineClock(fixedClock(now)))

	require.NoError(t, e.Register(Objective{
		Name:       "error-slo",
		Target:     0.90, // 10% error budget
		Window:     time.Hour,
		MetricType: MetricTypeErrorRate,
	}))

	// 20 events: 19 good, 1 bad.
	for i := 0; i < 19; i++ {
		e.RecordOutcome("error-slo", true)
	}
	e.RecordOutcome("error-slo", false)

	status, err := e.Status("error-slo")
	require.NoError(t, err)

	// Current = 19/20 = 0.95 (above 0.90 target, so within SLO).
	assert.InDelta(t, 0.95, status.Current, 0.001)
	// Budget: allowed bad = 20 * 0.10 = 2. Used 1. Remaining = 1 - 1/2 = 0.5.
	assert.InDelta(t, 0.5, status.Remaining, 0.001)
	assert.False(t, status.Exhausted)
}

func TestEngine_WindowExpiry(t *testing.T) {
	baseTime := time.Date(2026, 4, 13, 10, 0, 0, 0, time.UTC)
	clock := advancingClock(baseTime, 30*time.Minute)
	e := NewEngine(WithEngineClock(clock))

	require.NoError(t, e.Register(Objective{
		Name:       "windowed-slo",
		Target:     0.99,
		Window:     time.Hour,
		MetricType: MetricTypeErrorRate,
	}))

	// Event 1 at T+0min: bad (clock advances to T+30min after).
	e.RecordOutcome("windowed-slo", false)
	// Event 2 at T+30min: good (clock advances to T+60min after).
	e.RecordOutcome("windowed-slo", true)
	// Event 3 at T+60min: good (clock advances to T+90min after).
	e.RecordOutcome("windowed-slo", true)

	// Status is computed at T+90min (next clock call).
	// Window = [T+30min, T+90min]. Event 1 at T+0 is outside.
	// In-window: 2 good, 0 bad.
	status, err := e.Status("windowed-slo")
	require.NoError(t, err)
	assert.Equal(t, int64(2), status.TotalEvents)
	assert.Equal(t, int64(2), status.GoodEvents)
	assert.Equal(t, int64(0), status.BadEvents)
	assert.Equal(t, 1.0, status.Current)
}

func TestEngine_BudgetExhaustionCallback(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)

	var exhaustedStatus *BudgetStatus
	e := NewEngine(
		WithEngineClock(fixedClock(now)),
		WithExhaustedCallback(func(status BudgetStatus) {
			copied := status
			exhaustedStatus = &copied
		}),
	)

	require.NoError(t, e.Register(Objective{
		Name:       "callback-slo",
		Target:     0.50, // 50% target for easy exhaustion
		Window:     time.Hour,
		MetricType: MetricTypeErrorRate,
	}))

	// 1 good event — budget is fine.
	e.RecordOutcome("callback-slo", true)
	assert.Nil(t, exhaustedStatus, "callback should not fire yet")

	// 1 bad event — budget: allowed = 2*0.5=1, used=1, remaining=0 → exhausted.
	e.RecordOutcome("callback-slo", false)
	require.NotNil(t, exhaustedStatus, "callback should fire on exhaustion")
	assert.Equal(t, "callback-slo", exhaustedStatus.ObjectiveName)
	assert.True(t, exhaustedStatus.Exhausted)
}

func TestEngine_MultipleSLOs(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	e := NewEngine(WithEngineClock(fixedClock(now)))

	require.NoError(t, e.Register(Objective{
		Name:         "latency",
		Target:       0.99,
		Window:       time.Hour,
		MetricType:   MetricTypeLatency,
		LatencyBound: 50 * time.Millisecond,
	}))
	require.NoError(t, e.Register(Objective{
		Name:       "errors",
		Target:     0.999,
		Window:     24 * time.Hour,
		MetricType: MetricTypeErrorRate,
	}))

	e.RecordLatency("latency", 30*time.Millisecond)
	e.RecordOutcome("errors", true)

	statuses := e.AllStatuses()
	require.Len(t, statuses, 2)
	// Sorted by name.
	assert.Equal(t, "errors", statuses[0].ObjectiveName)
	assert.Equal(t, "latency", statuses[1].ObjectiveName)
}

func TestEngine_ConcurrentRecording(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	e := NewEngine(WithEngineClock(fixedClock(now)))

	require.NoError(t, e.Register(Objective{
		Name:       "concurrent-slo",
		Target:     0.99,
		Window:     time.Hour,
		MetricType: MetricTypeErrorRate,
	}))

	var wg sync.WaitGroup
	const goroutines = 100

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			e.RecordOutcome("concurrent-slo", idx%10 != 0) // 10% failure rate
		}(i)
	}
	wg.Wait()

	status, err := e.Status("concurrent-slo")
	require.NoError(t, err)
	assert.Equal(t, int64(goroutines), status.TotalEvents)
	assert.Equal(t, int64(90), status.GoodEvents)
	assert.Equal(t, int64(10), status.BadEvents)
}

func TestEngine_StatusUnknownObjective(t *testing.T) {
	e := NewEngine()

	_, err := e.Status("nonexistent")
	require.Error(t, err)
	assert.IsType(t, &ErrObjectiveNotFound{}, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestEngine_EmptyEngine(t *testing.T) {
	e := NewEngine()

	statuses := e.AllStatuses()
	assert.Empty(t, statuses)
}

func TestEngine_NoEventsYieldsPerfectCompliance(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	e := NewEngine(WithEngineClock(fixedClock(now)))

	require.NoError(t, e.Register(Objective{
		Name:       "empty-slo",
		Target:     0.99,
		Window:     time.Hour,
		MetricType: MetricTypeErrorRate,
	}))

	status, err := e.Status("empty-slo")
	require.NoError(t, err)
	assert.Equal(t, 1.0, status.Current)
	assert.Equal(t, 1.0, status.Remaining)
	assert.Equal(t, int64(0), status.TotalEvents)
	assert.False(t, status.Exhausted)
}

func TestEngine_LatencyAtExactBound(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	e := NewEngine(WithEngineClock(fixedClock(now)))

	require.NoError(t, e.Register(Objective{
		Name:         "exact-bound",
		Target:       0.99,
		Window:       time.Hour,
		MetricType:   MetricTypeLatency,
		LatencyBound: 50 * time.Millisecond,
	}))

	// Latency exactly at bound should be "good" (<= bound).
	e.RecordLatency("exact-bound", 50*time.Millisecond)

	status, err := e.Status("exact-bound")
	require.NoError(t, err)
	assert.Equal(t, int64(1), status.GoodEvents)
	assert.Equal(t, int64(0), status.BadEvents)
}

func TestEngine_RecordLatencyOnErrorRateObjective(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	e := NewEngine(WithEngineClock(fixedClock(now)))

	require.NoError(t, e.Register(Objective{
		Name:       "error-slo",
		Target:     0.99,
		Window:     time.Hour,
		MetricType: MetricTypeErrorRate,
	}))

	// Should be a no-op (wrong metric type).
	e.RecordLatency("error-slo", 30*time.Millisecond)

	status, err := e.Status("error-slo")
	require.NoError(t, err)
	assert.Equal(t, int64(0), status.TotalEvents, "latency recording on error-rate SLO should be ignored")
}

func TestEngine_RecordOutcomeOnLatencyObjective(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	e := NewEngine(WithEngineClock(fixedClock(now)))

	require.NoError(t, e.Register(Objective{
		Name:         "latency-slo",
		Target:       0.99,
		Window:       time.Hour,
		MetricType:   MetricTypeLatency,
		LatencyBound: 50 * time.Millisecond,
	}))

	// Should be a no-op (wrong metric type).
	e.RecordOutcome("latency-slo", true)

	status, err := e.Status("latency-slo")
	require.NoError(t, err)
	assert.Equal(t, int64(0), status.TotalEvents, "outcome recording on latency SLO should be ignored")
}
