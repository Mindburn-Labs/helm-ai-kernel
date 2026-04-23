package kernel

import (
	"fmt"
	"math"
)

// CoordinationMode defines how subtasks are coordinated.
type CoordinationMode string

const (
	// ModeWaterfall executes subtasks sequentially (single-agent).
	ModeWaterfall CoordinationMode = "waterfall"
	// ModeParallel executes independent subtasks concurrently.
	ModeParallel CoordinationMode = "parallel"
	// ModeHybrid uses centralized orchestration with selective parallelism.
	ModeHybrid CoordinationMode = "hybrid"
)

// TaskProperties represents the analyzed properties of a task or goal
// used to select the optimal coordination mode. Based on Google Research's
// scaling principles (Jan 2026): multi-agent coordination helps on
// parallelizable tasks but can degrade on sequential tasks.
type TaskProperties struct {
	// ToolDensity is the ratio of tool calls to reasoning steps.
	// High density (>0.5) favors parallel execution.
	ToolDensity float64 `json:"tool_density"`

	// Decomposability measures how easily the task can be split into
	// independent subtasks. Range: 0.0 (monolithic) to 1.0 (fully decomposable).
	Decomposability float64 `json:"decomposability"`

	// SequentialDepth is the longest chain of dependent steps
	// (critical path length). Deep chains penalize parallelism.
	SequentialDepth int `json:"sequential_depth"`

	// ParallelizableFraction (Amdahl's law) — fraction of work that
	// can execute concurrently. Range: 0.0 to 1.0.
	ParallelizableFraction float64 `json:"parallelizable_fraction"`

	// EstimatedSubtasks is the total number of subtasks after decomposition.
	EstimatedSubtasks int `json:"estimated_subtasks"`

	// ErrorAmplificationRisk is the estimated probability that
	// independent multi-agent execution will amplify errors.
	// Based on Google's finding that error compounds across agents.
	// Range: 0.0 (low risk) to 1.0 (high risk).
	ErrorAmplificationRisk float64 `json:"error_amplification_risk"`
}

// TaskClassifier analyzes tasks and selects optimal coordination modes.
type TaskClassifier struct {
	// Thresholds for mode selection (configurable)
	ParallelThreshold  float64 // Min parallelizable fraction for ModeParallel
	HybridThreshold    float64 // Min for ModeHybrid (between single and parallel)
	MaxSequentialDepth int     // Max depth before forcing single-agent
	MinSubtasks        int     // Min subtasks to justify multi-agent overhead
}

// DefaultTaskClassifier returns a classifier with empirically-derived thresholds
// based on Google Research's scaling laws.
func DefaultTaskClassifier() *TaskClassifier {
	return &TaskClassifier{
		ParallelThreshold:  0.7, // 70%+ parallelizable → full parallel
		HybridThreshold:    0.3, // 30-70% → hybrid coordination
		MaxSequentialDepth: 8,   // >8 sequential steps → single agent
		MinSubtasks:        3,   // Need at least 3 subtasks for multi-agent
	}
}

// ClassifyFromDAG analyzes a task DAG and returns its properties.
// tasks: list of task IDs. deps: map of taskID → list of dependency IDs.
func (tc *TaskClassifier) ClassifyFromDAG(tasks []string, deps map[string][]string) TaskProperties {
	n := len(tasks)
	if n == 0 {
		return TaskProperties{Decomposability: 0, SequentialDepth: 0}
	}

	// 1. Compute critical path (longest chain)
	depth := computeCriticalPath(tasks, deps)

	// 2. Count parallelizable tasks (no deps or deps already resolved)
	rootTasks := 0
	for _, t := range tasks {
		if len(deps[t]) == 0 {
			rootTasks++
		}
	}

	// 3. Calculate properties
	parallelFraction := float64(rootTasks) / float64(n)
	if n > 1 && depth > 0 {
		// Amdahl's correction: account for critical path ratio
		parallelFraction = 1.0 - (float64(depth) / float64(n))
		if parallelFraction < 0 {
			parallelFraction = 0
		}
	}

	decomposability := float64(rootTasks) / float64(n)

	// Error amplification risk: increases with agent count, decreases with centralization
	// Per Google: P(all_correct) = p^n for n independent agents with accuracy p
	agentErrorRate := 0.05 // 5% per-agent error rate (empirical baseline)
	errorRisk := 1.0 - math.Pow(1.0-agentErrorRate, float64(n))

	// Tool density estimation (heuristic: more tools in more tasks = higher density)
	toolDensity := 0.0
	if n > 0 {
		// Assume each task uses at least one tool call
		toolDensity = math.Min(1.0, float64(n)*0.15)
	}

	return TaskProperties{
		ToolDensity:            toolDensity,
		Decomposability:        decomposability,
		SequentialDepth:        depth,
		ParallelizableFraction: parallelFraction,
		EstimatedSubtasks:      n,
		ErrorAmplificationRisk: errorRisk,
	}
}

// SelectMode returns the optimal CoordinationMode based on task properties.
// Implements the decision logic from Google's scaling agent systems paper:
//
//   - High parallelizable fraction + low sequential depth → ModeParallel
//   - Low parallelizable fraction + deep sequential → single-agent (no swarm)
//   - Mixed → ModeHybrid with centralized orchestration
//
// Returns the mode and a human-readable rationale.
func (tc *TaskClassifier) SelectMode(props TaskProperties) (CoordinationMode, string) {
	// Rule 1: Too few subtasks → single agent (overhead not justified)
	if props.EstimatedSubtasks < tc.MinSubtasks {
		return ModeWaterfall, fmt.Sprintf(
			"single-agent: only %d subtasks (min %d for multi-agent)",
			props.EstimatedSubtasks, tc.MinSubtasks,
		)
	}

	// Rule 2: Deep sequential chains → single agent (parallelism hurts)
	if props.SequentialDepth > tc.MaxSequentialDepth {
		return ModeWaterfall, fmt.Sprintf(
			"single-agent: sequential depth %d exceeds max %d",
			props.SequentialDepth, tc.MaxSequentialDepth,
		)
	}

	// Rule 3: High error amplification risk → centralized (hybrid) coordination
	if props.ErrorAmplificationRisk > 0.3 {
		return ModeHybrid, fmt.Sprintf(
			"hybrid: error amplification risk %.1f%% requires centralized validation",
			props.ErrorAmplificationRisk*100,
		)
	}

	// Rule 4: Highly parallelizable → full parallel
	if props.ParallelizableFraction >= tc.ParallelThreshold {
		return ModeParallel, fmt.Sprintf(
			"parallel: %.0f%% parallelizable fraction exceeds threshold %.0f%%",
			props.ParallelizableFraction*100, tc.ParallelThreshold*100,
		)
	}

	// Rule 5: Moderate parallelism → hybrid
	if props.ParallelizableFraction >= tc.HybridThreshold {
		return ModeHybrid, fmt.Sprintf(
			"hybrid: %.0f%% parallelizable (between %.0f%% and %.0f%%)",
			props.ParallelizableFraction*100,
			tc.HybridThreshold*100, tc.ParallelThreshold*100,
		)
	}

	// Default: sequential (single agent)
	return ModeWaterfall, fmt.Sprintf(
		"single-agent: only %.0f%% parallelizable (below %.0f%% threshold)",
		props.ParallelizableFraction*100, tc.HybridThreshold*100,
	)
}

// computeCriticalPath returns the length of the longest dependency chain.
func computeCriticalPath(tasks []string, deps map[string][]string) int {
	memo := make(map[string]int)
	maxDepth := 0

	var dfs func(taskID string) int
	dfs = func(taskID string) int {
		if d, ok := memo[taskID]; ok {
			return d
		}
		best := 0
		for _, dep := range deps[taskID] {
			d := dfs(dep)
			if d > best {
				best = d
			}
		}
		memo[taskID] = best + 1
		if memo[taskID] > maxDepth {
			maxDepth = memo[taskID]
		}
		return memo[taskID]
	}

	for _, t := range tasks {
		dfs(t)
	}
	return maxDepth
}
