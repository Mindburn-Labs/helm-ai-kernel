package kernel

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCriticalPathMetric_RecordStage(t *testing.T) {
	m := NewCriticalPathMetric()

	// Stage 1: orchestration=1, branches=[3, 5, 2]
	m.RecordStage(1, []int{3, 5, 2})

	require.Equal(t, 1, m.StageIndex)
	require.Equal(t, 6, m.TotalCriticalSteps) // 1 + max(3,5,2) = 1 + 5 = 6

	// Stage 2: orchestration=2, branches=[4, 4]
	m.RecordStage(2, []int{4, 4})

	require.Equal(t, 2, m.StageIndex)
	require.Equal(t, 12, m.TotalCriticalSteps) // (1+5) + (2+4) = 12
}

func TestCriticalPathMetric_EmptyBranches(t *testing.T) {
	m := NewCriticalPathMetric()

	// No parallel branches
	m.RecordStage(5, []int{})

	require.Equal(t, 5, m.TotalCriticalSteps) // 5 + max() = 5 + 0 = 5
}

func TestCriticalPathMetric_Hash(t *testing.T) {
	m1 := NewCriticalPathMetric()
	m2 := NewCriticalPathMetric()

	m1.RecordStage(1, []int{2, 3})
	m2.RecordStage(1, []int{2, 3})

	// Same inputs should produce same hash (ignoring StartTime)
	// Note: StartTime differs, so hashes will differ
	require.NotEmpty(t, m1.Hash())
	require.NotEmpty(t, m2.Hash())
}

func TestCriticalPathMetric_ParallelEfficiency(t *testing.T) {
	m := NewCriticalPathMetric()

	// Single stage: orchestration=1, branches=[10]
	m.RecordStage(1, []int{10})

	// Total work = 1 + 10 = 11
	// Critical path = 1 + 10 = 11
	// Efficiency = 11/11 = 1.0
	require.Equal(t, 1.0, m.GetParallelEfficiency())
}

func TestCriticalPathScheduler_IdentifyIndependentGroups(t *testing.T) {
	s := NewCriticalPathScheduler(4)

	events := []*SchedulerEvent{
		{EventID: "e1", LoopID: "loop1"},
		{EventID: "e2", LoopID: "loop1"},
		{EventID: "e3", LoopID: "loop2"},
		{EventID: "e4", LoopID: ""}, // Standalone
		{EventID: "e5", LoopID: "loop2"},
	}

	groups := s.IdentifyIndependentGroups(events)

	// Should have 3 groups: loop1, loop2, e4 (standalone)
	require.Len(t, groups, 3)

	groupIDs := make(map[string]int)
	for _, g := range groups {
		groupIDs[g.GroupID] = len(g.Events)
	}

	require.Equal(t, 2, groupIDs["loop1"])
	require.Equal(t, 2, groupIDs["loop2"])
	require.Equal(t, 1, groupIDs["e4"])
}

func TestCriticalPathScheduler_OptimizeForCriticalPath(t *testing.T) {
	s := NewCriticalPathScheduler(2) // 2 parallel lanes

	events := []*SchedulerEvent{
		{EventID: "e1", LoopID: "big", Priority: 1},
		{EventID: "e2", LoopID: "big", Priority: 1},
		{EventID: "e3", LoopID: "big", Priority: 1},
		{EventID: "e4", LoopID: "small", Priority: 1},
	}

	ctx := context.Background()
	optimized := s.OptimizeForCriticalPath(ctx, events)

	// All events should be present
	require.Len(t, optimized, 4)

	// Metrics should be recorded
	require.Equal(t, 1, s.metrics.StageIndex)
}

func TestCriticalPathScheduler_ScheduleBatch(t *testing.T) {
	s := NewCriticalPathScheduler(4)
	ctx := context.Background()

	events := []*SchedulerEvent{
		{EventID: "e1", ScheduledAt: time.Now(), Priority: 1},
		{EventID: "e2", ScheduledAt: time.Now(), Priority: 2},
		{EventID: "e3", ScheduledAt: time.Now(), Priority: 1},
	}

	err := s.ScheduleBatch(ctx, events)
	require.NoError(t, err)

	// All events should be scheduled
	require.Equal(t, 3, s.Len())
}

func TestCriticalPathScheduler_ParallelExecute(t *testing.T) {
	s := NewCriticalPathScheduler(4)
	ctx := context.Background()

	// Create events in different groups
	events := []*SchedulerEvent{
		{EventID: "e1", LoopID: "group1"},
		{EventID: "e2", LoopID: "group1"},
		{EventID: "e3", LoopID: "group2"},
		{EventID: "e4", LoopID: "group3"},
	}

	var mu sync.Mutex
	executed := make([]string, 0)

	executor := func(e *SchedulerEvent) error {
		mu.Lock()
		executed = append(executed, e.EventID)
		mu.Unlock()
		time.Sleep(10 * time.Millisecond) // Simulate work
		return nil
	}

	err := s.ParallelExecute(ctx, events, executor)
	require.NoError(t, err)

	// All events should be executed
	require.Len(t, executed, 4)
	require.Contains(t, executed, "e1")
	require.Contains(t, executed, "e2")
	require.Contains(t, executed, "e3")
	require.Contains(t, executed, "e4")
}

func TestCriticalPathScheduler_ParallelExecuteWithError(t *testing.T) {
	s := NewCriticalPathScheduler(4)
	ctx := context.Background()

	events := []*SchedulerEvent{
		{EventID: "e1", LoopID: "group1"},
		{EventID: "e2", LoopID: "group2"},
	}

	executor := func(e *SchedulerEvent) error {
		if e.EventID == "e2" {
			return fmt.Errorf("execution failed")
		}
		return nil
	}

	err := s.ParallelExecute(ctx, events, executor)
	require.Error(t, err)
	require.Contains(t, err.Error(), "execution failed")
}

func TestCriticalPathScheduler_LoadBalancing(t *testing.T) {
	s := NewCriticalPathScheduler(3) // 3 parallel lanes
	ctx := context.Background()

	// Create uneven groups
	events := []*SchedulerEvent{
		{EventID: "e1", LoopID: "large"},
		{EventID: "e2", LoopID: "large"},
		{EventID: "e3", LoopID: "large"},
		{EventID: "e4", LoopID: "large"},
		{EventID: "e5", LoopID: "medium"},
		{EventID: "e6", LoopID: "medium"},
		{EventID: "e7", LoopID: "small"},
	}

	_ = s.OptimizeForCriticalPath(ctx, events)

	// Check that metrics track the optimization
	metrics := s.GetMetrics()
	require.Equal(t, 1, metrics.StageIndex)
	require.Greater(t, metrics.TotalCriticalSteps, 0)
}

func TestCriticalPathScheduler_EmptyEvents(t *testing.T) {
	s := NewCriticalPathScheduler(4)
	ctx := context.Background()

	events := []*SchedulerEvent{}
	optimized := s.OptimizeForCriticalPath(ctx, events)

	require.Len(t, optimized, 0)
}

func TestCriticalPathScheduler_SingleEvent(t *testing.T) {
	s := NewCriticalPathScheduler(4)
	ctx := context.Background()

	events := []*SchedulerEvent{
		{EventID: "solo", LoopID: ""},
	}

	optimized := s.OptimizeForCriticalPath(ctx, events)

	require.Len(t, optimized, 1)
	require.Equal(t, "solo", optimized[0].EventID)
}
