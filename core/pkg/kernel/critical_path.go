// Package kernel provides critical path scheduling.
// Inspired by Kimi K2.5 PARL Critical Steps metric:
// T = Σₜ [ S_main(t) + max_i S_sub,i(t) ]
package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// CriticalPathMetric tracks the critical path through parallel execution.
// Per PARL: Critical Steps = orchestration overhead + max parallel branch.
type CriticalPathMetric struct {
	mu sync.RWMutex

	// Current stage index
	StageIndex int `json:"stage_index"`

	// Orchestration steps at each stage (S_main)
	OrchestrationSteps []int `json:"orchestration_steps"`

	// Max subagent steps at each stage (max_i S_sub,i)
	MaxSubagentSteps []int `json:"max_subagent_steps"`

	// Total critical path length
	TotalCriticalSteps int `json:"total_critical_steps"`

	// Timestamp when started
	StartTime time.Time `json:"start_time"`
}

// NewCriticalPathMetric creates a new critical path tracker.
func NewCriticalPathMetric() *CriticalPathMetric {
	return &CriticalPathMetric{
		StageIndex:         0,
		OrchestrationSteps: make([]int, 0),
		MaxSubagentSteps:   make([]int, 0),
		StartTime:          time.Now(),
	}
}

// RecordStage records the completion of a stage with parallel branches.
func (m *CriticalPathMetric) RecordStage(orchestrationSteps int, branchSteps []int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find max branch steps
	maxBranch := 0
	for _, steps := range branchSteps {
		if steps > maxBranch {
			maxBranch = steps
		}
	}

	m.OrchestrationSteps = append(m.OrchestrationSteps, orchestrationSteps)
	m.MaxSubagentSteps = append(m.MaxSubagentSteps, maxBranch)
	m.StageIndex++

	// Update total: T = Σₜ [ S_main(t) + max_i S_sub,i(t) ]
	m.TotalCriticalSteps = 0
	for i := 0; i < len(m.OrchestrationSteps); i++ {
		m.TotalCriticalSteps += m.OrchestrationSteps[i] + m.MaxSubagentSteps[i]
	}
}

// GetTotalCriticalSteps returns the current critical path length.
func (m *CriticalPathMetric) GetTotalCriticalSteps() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.TotalCriticalSteps
}

// GetParallelEfficiency returns the ratio of work done vs critical path.
func (m *CriticalPathMetric) GetParallelEfficiency() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.TotalCriticalSteps == 0 {
		return 1.0
	}

	totalWork := 0
	for i := 0; i < len(m.OrchestrationSteps); i++ {
		totalWork += m.OrchestrationSteps[i]
	}
	// Add all branch work (not just max)
	for _, branchMax := range m.MaxSubagentSteps {
		totalWork += branchMax
	}

	return float64(totalWork) / float64(m.TotalCriticalSteps)
}

// Hash returns a deterministic hash of the metric state.
func (m *CriticalPathMetric) Hash() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, _ := json.Marshal(m)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// IndependentGroup represents a group of events that can execute in parallel.
type IndependentGroup struct {
	GroupID      string            `json:"group_id"`
	Events       []*SchedulerEvent `json:"events"`
	Dependencies []string          `json:"dependencies"` // GroupIDs this depends on
}

// CriticalPathScheduler extends InMemoryScheduler with parallel optimization.
type CriticalPathScheduler struct {
	*InMemoryScheduler

	mu             sync.RWMutex
	parallelBudget int // Max parallel branches
	metrics        *CriticalPathMetric
	groups         map[string]*IndependentGroup
}

// NewCriticalPathScheduler creates a scheduler with critical path optimization.
func NewCriticalPathScheduler(parallelBudget int) *CriticalPathScheduler {
	return &CriticalPathScheduler{
		InMemoryScheduler: NewInMemoryScheduler(),
		parallelBudget:    parallelBudget,
		metrics:           NewCriticalPathMetric(),
		groups:            make(map[string]*IndependentGroup),
	}
}

// IdentifyIndependentGroups partitions events into parallelizable groups.
// Events with no shared dependencies can execute concurrently.
func (s *CriticalPathScheduler) IdentifyIndependentGroups(events []*SchedulerEvent) []*IndependentGroup {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Group by LoopID (events in same loop are dependent)
	loopGroups := make(map[string][]*SchedulerEvent)
	for _, e := range events {
		loopID := e.LoopID
		if loopID == "" {
			loopID = e.EventID // Standalone events are their own group
		}
		loopGroups[loopID] = append(loopGroups[loopID], e)
	}

	// Convert to IndependentGroup structures
	groups := make([]*IndependentGroup, 0, len(loopGroups))
	for loopID, evts := range loopGroups {
		group := &IndependentGroup{
			GroupID:      loopID,
			Events:       evts,
			Dependencies: []string{}, // Can be extended with dependency analysis
		}
		groups = append(groups, group)
		s.groups[loopID] = group
	}

	// Sort for determinism
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].GroupID < groups[j].GroupID
	})

	return groups
}

// OptimizeForCriticalPath reorders events to minimize critical path length.
//
//nolint:gocognit // complexity acceptable
func (s *CriticalPathScheduler) OptimizeForCriticalPath(ctx context.Context, events []*SchedulerEvent) []*SchedulerEvent {
	if len(events) == 0 {
		return events
	}

	groups := s.IdentifyIndependentGroups(events)

	// Calculate expected steps per group
	groupSteps := make(map[string]int)
	for _, g := range groups {
		groupSteps[g.GroupID] = len(g.Events)
	}

	// Balance load across parallel budget
	// Sort groups by size (largest first) for better load balancing
	sort.Slice(groups, func(i, j int) bool {
		return len(groups[i].Events) > len(groups[j].Events)
	})

	// Assign groups to parallel lanes
	lanes := make([][]*IndependentGroup, s.parallelBudget)
	laneLoads := make([]int, s.parallelBudget)

	for _, group := range groups {
		// Find lane with minimum load
		minLane := 0
		minLoad := laneLoads[0]
		for i := 1; i < len(lanes); i++ {
			if laneLoads[i] < minLoad {
				minLane = i
				minLoad = laneLoads[i]
			}
		}
		lanes[minLane] = append(lanes[minLane], group)
		laneLoads[minLane] += len(group.Events)
	}

	// Record critical path metric
	branchSteps := make([]int, len(lanes))
	for i, lane := range lanes {
		for _, g := range lane {
			branchSteps[i] += len(g.Events)
		}
	}
	s.metrics.RecordStage(1, branchSteps) // 1 orchestration step

	// Flatten back to ordered events (deterministic interleaving)
	result := make([]*SchedulerEvent, 0, len(events))
	maxLaneLen := 0
	for _, lane := range lanes {
		total := 0
		for _, g := range lane {
			total += len(g.Events)
		}
		if total > maxLaneLen {
			maxLaneLen = total
		}
	}

	// Interleave from lanes for deterministic ordering
	laneIndices := make([]int, len(lanes))
	laneGroupIndices := make([]int, len(lanes))

	for step := 0; step < maxLaneLen*len(lanes); step++ {
		laneIdx := step % len(lanes)
		if laneGroupIndices[laneIdx] >= len(lanes[laneIdx]) {
			continue
		}

		group := lanes[laneIdx][laneGroupIndices[laneIdx]]
		if laneIndices[laneIdx] < len(group.Events) {
			result = append(result, group.Events[laneIndices[laneIdx]])
			laneIndices[laneIdx]++
		}

		if laneIndices[laneIdx] >= len(group.Events) {
			laneIndices[laneIdx] = 0
			laneGroupIndices[laneIdx]++
		}
	}

	return result
}

// GetMetrics returns the critical path metrics.
func (s *CriticalPathScheduler) GetMetrics() *CriticalPathMetric {
	return s.metrics
}

// ScheduleBatch schedules multiple events with critical path optimization.
func (s *CriticalPathScheduler) ScheduleBatch(ctx context.Context, events []*SchedulerEvent) error {
	optimized := s.OptimizeForCriticalPath(ctx, events)

	for _, event := range optimized {
		if err := s.Schedule(ctx, event); err != nil {
			return err
		}
	}

	return nil
}

// ParallelExecute executes events in parallel lanes while maintaining determinism.
func (s *CriticalPathScheduler) ParallelExecute(ctx context.Context, events []*SchedulerEvent, executor func(*SchedulerEvent) error) error {
	groups := s.IdentifyIndependentGroups(events)

	// Execute independent groups in parallel
	var wg sync.WaitGroup
	errChan := make(chan error, len(groups))

	// Limit parallelism to budget
	sem := make(chan struct{}, s.parallelBudget)

	for _, group := range groups {
		wg.Add(1)
		go func(g *IndependentGroup) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			// Execute events within group sequentially (they may be dependent)
			for _, event := range g.Events {
				if err := executor(event); err != nil {
					errChan <- err
					return
				}
			}
		}(group)
	}

	wg.Wait()
	close(errChan)

	// Return first error if any
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	// Record parallel execution metrics
	branchSteps := make([]int, 0)
	for _, g := range groups {
		branchSteps = append(branchSteps, len(g.Events))
	}
	s.metrics.RecordStage(1, branchSteps)

	return nil
}
