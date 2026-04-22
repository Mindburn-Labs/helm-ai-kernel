// Package conductor drives research missions end-to-end by loading pre-created
// TaskLease records, resolving their dependency order from the stored WorkGraph,
// and dispatching them to the appropriate Agent implementations.
package conductor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/agents"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
)

// WorkGraphKey returns the canonical blob-store key for a mission's WorkGraph.
// The planner agent stores its output here so the conductor can resolve
// dependency ordering without a separate metadata column.
func WorkGraphKey(missionID string) string {
	return fmt.Sprintf("research/%s/workgraph.json", missionID)
}

// TaskOutputKey returns the canonical blob-store key for a task's output artifact.
func TaskOutputKey(missionID, leaseID string) string {
	return fmt.Sprintf("research/%s/tasks/%s/output.json", missionID, leaseID)
}

// Config holds all injectable dependencies for the conductor Service.
// BudgetChecker and FreezeController are optional — pass nil to disable.
type Config struct {
	Missions store.MissionStore
	Tasks    store.TaskStore
	Feed     store.FeedStore
	Blobs    store.BlobStore
	Agents   map[researchruntime.WorkerRole]agents.Agent
	Budget   *BudgetChecker // optional — nil means no budget enforcement
	Retry    *RetryPolicy   // optional — nil uses DefaultRetryPolicy
}

// Service is the conductor.  It is safe to call Run concurrently for different
// mission IDs; shared state is limited to the injected store implementations.
type Service struct {
	cfg Config
}

// New creates a Service from the provided Config.
func New(cfg Config) *Service {
	if cfg.Retry == nil {
		cfg.Retry = DefaultRetryPolicy()
	}
	return &Service{cfg: cfg}
}

// Run drives a single mission to completion.
//
// Preconditions (enforced by the caller / launcher):
//   - Mission record exists in MissionStore with state "pending".
//   - TaskLease records for all graph nodes have been created in TaskStore.
//   - The WorkGraph JSON produced by the PlannerAgent has been persisted to
//     BlobStore at WorkGraphKey(missionID) so dependency order can be resolved.
//
// The method transitions the mission through "running" → "published" (success)
// or returns an error leaving it in "failed" state for the caller to handle.
func (s *Service) Run(ctx context.Context, missionID string) error {
	// ── 1. Transition to running ──────────────────────────────────────────────
	if err := s.cfg.Missions.UpdateState(ctx, missionID, "running"); err != nil {
		return fmt.Errorf("conductor: start mission: %w", err)
	}
	_ = s.cfg.Feed.Append(ctx, missionID, "conductor", "mission_started", "Mission execution begun")

	// ── 2. Load work graph for dependency ordering ────────────────────────────
	graphBytes, err := s.cfg.Blobs.Get(ctx, WorkGraphKey(missionID))
	if err != nil {
		_ = s.failMission(ctx, missionID, "load work graph", err)
		return fmt.Errorf("conductor: load work graph: %w", err)
	}
	var graph researchruntime.WorkGraph
	if err := json.Unmarshal(graphBytes, &graph); err != nil {
		_ = s.failMission(ctx, missionID, "parse work graph", err)
		return fmt.Errorf("conductor: parse work graph: %w", err)
	}

	// Build nodeID → WorkNode lookup for dependency resolution.
	nodeByID := make(map[string]researchruntime.WorkNode, len(graph.Nodes))
	for _, n := range graph.Nodes {
		nodeByID[n.ID] = n
	}

	// ── 3. Load task leases ───────────────────────────────────────────────────
	tasks, err := s.cfg.Tasks.ListByMission(ctx, missionID)
	if err != nil {
		_ = s.failMission(ctx, missionID, "load tasks", err)
		return fmt.Errorf("conductor: load tasks: %w", err)
	}

	// Build nodeID → TaskLease lookup so we can wire predecessor outputs to inputs.
	taskByNodeID := make(map[string]researchruntime.TaskLease, len(tasks))
	for _, t := range tasks {
		taskByNodeID[t.NodeID] = t
	}

	// ── 4. Topological execution ──────────────────────────────────────────────
	// completed maps nodeID → output bytes produced by that node's agent.
	completed := make(map[string][]byte, len(tasks))

	for len(completed) < len(tasks) {
		progress := false

		for _, task := range tasks {
			nodeID := task.NodeID
			if _, done := completed[nodeID]; done {
				continue
			}

			// Resolve the WorkNode so we can inspect DependsOn.
			node, known := nodeByID[nodeID]
			if !known {
				// Defensive: if the task has no matching graph node, treat it as
				// having no dependencies and proceed.
				node = researchruntime.WorkNode{ID: nodeID, Role: task.Role}
			}

			// Skip until all predecessors have completed.
			if !s.depsReady(node.DependsOn, completed) {
				continue
			}

			// Collect the merged predecessor output as this task's input.
			input := s.gatherInput(ctx, node.DependsOn, completed, taskByNodeID)

			// Execute with retry.
			output, execErr := s.executeWithRetry(ctx, missionID, task, input)
			if execErr != nil {
				_ = s.cfg.Tasks.UpdateState(ctx, task.LeaseID, "failed")
				_ = s.cfg.Feed.Append(ctx, missionID, string(task.Role), "task_failed", execErr.Error())
				_ = s.failMission(ctx, missionID, "task "+nodeID, execErr)
				return fmt.Errorf("conductor: task %s (%s) failed: %w", nodeID, task.Role, execErr)
			}

			// Persist output blob.
			if len(output) > 0 {
				outputKey := TaskOutputKey(missionID, task.LeaseID)
				if putErr := s.cfg.Blobs.Put(ctx, outputKey, output, "application/json"); putErr != nil {
					// Non-fatal: log but continue — the output is still in memory.
					_ = s.cfg.Feed.Append(ctx, missionID, "conductor", "blob_write_error", putErr.Error())
				}
			}

			if err := s.cfg.Tasks.UpdateState(ctx, task.LeaseID, "completed"); err != nil {
				_ = s.cfg.Feed.Append(ctx, missionID, "conductor", "state_update_error", err.Error())
			}
			_ = s.cfg.Feed.Append(ctx, missionID, string(task.Role), "task_completed", nodeID)

			completed[nodeID] = output
			progress = true
		}

		if !progress {
			_ = s.failMission(ctx, missionID, "dependency deadlock", nil)
			return fmt.Errorf("conductor: no progress — possible dependency deadlock in mission %s", missionID)
		}
	}

	// ── 5. Mark mission published ─────────────────────────────────────────────
	if err := s.cfg.Missions.UpdateState(ctx, missionID, "published"); err != nil {
		return fmt.Errorf("conductor: publish mission: %w", err)
	}
	_ = s.cfg.Feed.Append(ctx, missionID, "conductor", "mission_completed", "All tasks completed")
	return nil
}

// executeWithRetry runs a task's agent, retrying transient failures according to
// the configured RetryPolicy.  Budget is checked before each attempt.
func (s *Service) executeWithRetry(
	ctx context.Context,
	missionID string,
	task researchruntime.TaskLease,
	input []byte,
) ([]byte, error) {
	agent, ok := s.cfg.Agents[task.Role]
	if !ok {
		return nil, fmt.Errorf("no agent registered for role %s", task.Role)
	}

	var lastErr error
	for attempt := 0; s.cfg.Retry.ShouldRetry(attempt); attempt++ {
		if attempt > 0 {
			delay := s.cfg.Retry.Delay(attempt - 1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
			_ = s.cfg.Feed.Append(ctx, missionID, string(task.Role), "task_retry",
				fmt.Sprintf("attempt %d for %s", attempt+1, task.NodeID))
		}

		// Optional budget check before each attempt.
		if s.cfg.Budget != nil {
			if budgetErr := s.cfg.Budget.Allow(); budgetErr != nil {
				return nil, fmt.Errorf("budget: %w", budgetErr)
			}
		}

		if stateErr := s.cfg.Tasks.UpdateState(ctx, task.LeaseID, "running"); stateErr != nil {
			// Non-fatal: state tracking failure should not abort the task.
			_ = s.cfg.Feed.Append(ctx, missionID, "conductor", "state_update_error", stateErr.Error())
		}
		_ = s.cfg.Feed.Append(ctx, missionID, string(task.Role), "task_started", task.NodeID)

		output, err := agent.Execute(ctx, &task, input)
		if err == nil {
			return output, nil
		}

		lastErr = err
		_ = s.cfg.Feed.Append(ctx, missionID, string(task.Role), "task_attempt_failed",
			fmt.Sprintf("attempt %d: %s", attempt+1, err.Error()))
	}
	return nil, fmt.Errorf("all %d attempts failed: %w", s.cfg.Retry.MaxAttempts, lastErr)
}

// depsReady returns true when every nodeID in deps is present in the completed map.
func (s *Service) depsReady(deps []string, completed map[string][]byte) bool {
	for _, dep := range deps {
		if _, ok := completed[dep]; !ok {
			return false
		}
	}
	return true
}

// gatherInput assembles the merged predecessor output to pass as input to a task.
// If there is exactly one predecessor, its raw output is returned unchanged.
// If there are multiple predecessors, they are merged into a JSON object keyed
// by nodeID.  If there are no predecessors, nil is returned.
func (s *Service) gatherInput(
	ctx context.Context,
	deps []string,
	completed map[string][]byte,
	taskByNodeID map[string]researchruntime.TaskLease,
) []byte {
	switch len(deps) {
	case 0:
		return nil
	case 1:
		return completed[deps[0]]
	default:
		merged := make(map[string]json.RawMessage, len(deps))
		for _, dep := range deps {
			if data, ok := completed[dep]; ok {
				merged[dep] = json.RawMessage(data)
			}
		}
		out, _ := json.Marshal(merged)
		return out
	}
}

// failMission transitions the mission to the "failed" state and appends a feed event.
func (s *Service) failMission(ctx context.Context, missionID, step string, cause error) error {
	_ = s.cfg.Missions.UpdateState(ctx, missionID, "failed")
	detail := step
	if cause != nil {
		detail = fmt.Sprintf("%s: %s", step, cause.Error())
	}
	_ = s.cfg.Feed.Append(ctx, missionID, "conductor", "mission_failed", detail)
	return nil
}
