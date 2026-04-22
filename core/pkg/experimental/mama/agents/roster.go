package agents

import (
	"context"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/experimental/mama/command"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/experimental/mama/runtime"
)

// AgentRole strictly types the roles allowed inside the MAMA execution budget.
type AgentRole string

const (
	RoleExplore       AgentRole = "Explore"
	RoleWorldModel    AgentRole = "WorldModel"
	RolePlanner       AgentRole = "Planner"
	RoleExecutor      AgentRole = "Executor"
	RoleCritic        AgentRole = "Critic"
	RoleReplayAnalyst AgentRole = "ReplayAnalyst"
	RoleSkillSynth    AgentRole = "SkillSynth"
	RoleGovernor      AgentRole = "Governor"
)

// SubAgent defines the standard interface for an explicitly scoped MAMA actor.
type SubAgent interface {
	Role() AgentRole
	// Act executes the agent's logic but MUST NOT mutate state directly if it is not 
	// an Executor propagating through the correct connector URN.
	Act(ctx context.Context, mission *runtime.MissionState, registry *command.Registry) error
}
