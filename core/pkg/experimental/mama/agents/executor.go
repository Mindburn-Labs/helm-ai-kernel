package agents

import (
	"context"
	"errors"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/experimental/mama/command"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/experimental/mama/runtime"
)

// ExecutorAgent is the ONLY subagent permitted to mutate the environment.
// It acts solely on the explicit allowed URN to satisfy the No-Bypass invariant.
type ExecutorAgent struct {
	allowedURN string
}

func NewExecutorAgent() *ExecutorAgent {
	return &ExecutorAgent{
		// Enforcing the strict connector bounds per the Canonical Standard
		allowedURN: "helm.connector.arc.session.step.v1",
	}
}

func (e *ExecutorAgent) Role() AgentRole {
	return RoleExecutor
}

// Act dispatches the planner's finalized request to the underlying registry.
func (e *ExecutorAgent) Act(ctx context.Context, mission *runtime.MissionState, registry *command.Registry) error {
	if mission.ActionBudget <= 0 {
		return errors.New("action budget exhausted: Executor refused to act")
	}

	// The Executor MUST ensure the command operates over the allowed URN.
	// In the real pipeline, this drops Intent -> CPI -> PEP.
	err := registry.Dispatch(ctx, e.allowedURN, mission)
	if err != nil {
		return err
	}

	// Successfully manifested. Deduct global execution budget.
	mission.ActionBudget--
	return nil
}
