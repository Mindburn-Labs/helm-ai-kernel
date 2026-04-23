package kernel

import (
	"context"
	"sync/atomic"
	"testing"
)

func TestCriticalPathMetricGetTotalCriticalSteps(t *testing.T) {
	metric := NewCriticalPathMetric()

	// Initially 0
	if metric.GetTotalCriticalSteps() != 0 {
		t.Errorf("Initial steps = %d, want 0", metric.GetTotalCriticalSteps())
	}

	// After recording stages
	metric.RecordStage(2, []int{5, 3, 4}) // orchestration=2, max branch=5
	if metric.GetTotalCriticalSteps() != 7 {
		t.Errorf("After stage 1, steps = %d, want 7", metric.GetTotalCriticalSteps())
	}

	metric.RecordStage(1, []int{2, 6}) // orchestration=1, max branch=6
	if metric.GetTotalCriticalSteps() != 14 {
		t.Errorf("After stage 2, steps = %d, want 14", metric.GetTotalCriticalSteps())
	}
}

func TestCriticalPathSchedulerGetMetrics(t *testing.T) {
	scheduler := NewCriticalPathScheduler(4)

	metrics := scheduler.GetMetrics()
	if metrics == nil {
		t.Error("GetMetrics should not return nil")
	}
	if metrics.GetTotalCriticalSteps() != 0 {
		t.Error("Initial metrics should have 0 total steps")
	}
}

func TestCriticalPathSchedulerScheduleBatch(t *testing.T) {
	scheduler := NewCriticalPathScheduler(2)
	ctx := context.Background()

	events := []*SchedulerEvent{
		{EventID: "e1", EventType: "test", LoopID: "loop1"},
		{EventID: "e2", EventType: "test", LoopID: "loop1"},
		{EventID: "e3", EventType: "test", LoopID: "loop2"},
	}

	err := scheduler.ScheduleBatch(ctx, events)
	if err != nil {
		t.Fatalf("ScheduleBatch failed: %v", err)
	}

	// Check metrics were recorded
	if scheduler.GetMetrics().GetTotalCriticalSteps() == 0 {
		t.Error("Should have recorded critical steps")
	}
}

func TestCriticalPathSchedulerParallelExecute(t *testing.T) {
	scheduler := NewCriticalPathScheduler(3)
	ctx := context.Background()

	events := []*SchedulerEvent{
		{EventID: "e1", EventType: "test", LoopID: "loop1"},
		{EventID: "e2", EventType: "test", LoopID: "loop2"},
		{EventID: "e3", EventType: "test", LoopID: "loop3"},
	}

	var executed int32
	err := scheduler.ParallelExecute(ctx, events, func(e *SchedulerEvent) error {
		atomic.AddInt32(&executed, 1)
		return nil
	})

	if err != nil {
		t.Fatalf("ParallelExecute failed: %v", err)
	}
	if executed != 3 {
		t.Errorf("Executed %d events, want 3", executed)
	}
}

func TestCriticalPathMetricHash(t *testing.T) {
	metric := NewCriticalPathMetric()
	metric.RecordStage(1, []int{2, 3})

	hash1 := metric.Hash()
	if hash1 == "" {
		t.Error("Hash should not be empty")
	}

	// Same state should produce same hash
	hash2 := metric.Hash()
	if hash1 != hash2 {
		t.Error("Same state should produce same hash")
	}
}
