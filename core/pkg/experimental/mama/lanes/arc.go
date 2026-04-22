package lanes

import (
	"context"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/experimental/mama/agents"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/experimental/mama/command"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/experimental/mama/runtime"
)

// RunARCExploration executes the standardized agent loop over an ARC puzzle.
func RunARCExploration(ctx context.Context, mission *runtime.MissionState, registry *command.Registry, roster []agents.SubAgent) error {
	// Mode Transition Graph:
	// 1. Observe (Build WorldModel)
	// 2. Explore (Generate Beliefs)
	// 3. Plan (Evaluate Constraints)
	// 4. Probe (Test Hypotheses)
	// 5. Commit (Action Mutation)
	
	executor := findAgent(roster, agents.RoleExecutor)
	
	// Delegate the final mutation to the strict Executor bounding intent URNs.
	return executor.Act(ctx, mission, registry)
}

func findAgent(roster []agents.SubAgent, role agents.AgentRole) agents.SubAgent {
	for _, a := range roster {
		if a.Role() == role {
			return a
		}
	}
	return nil
}
