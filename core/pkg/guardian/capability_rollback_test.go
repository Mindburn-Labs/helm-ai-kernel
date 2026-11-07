package guardian

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capability"
)

type staticRollbackPlanStore struct {
	entry *capability.RollbackPlanEntry
}

func (s staticRollbackPlanStore) ResolvePlan(string) *capability.RollbackPlanEntry { return s.entry }
func (s staticRollbackPlanStore) Len() int                                         { return 1 }

func rollbackRequest(capabilityID string) *DecisionRequest {
	return &DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Resource:  "capability:" + capabilityID,
		Context:   map[string]interface{}{ContextKeyCapabilityID: capabilityID},
	}
}
