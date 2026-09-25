package workstation

import (
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// Test helpers kept from the retired adapter certification (HELM-756 removed
// `workstation certify`); the importer and decision tests still build on them.

func decisionRequest(effectClass, target string) contracts.WorkstationDecisionRequest {
	effectType, effectMode, action, toolID := EffectDefaults(effectClass)
	return contracts.WorkstationDecisionRequest{
		RequestID:   deterministicID("cert", effectClass, target),
		RunID:       "certification-run",
		ToolID:      toolID,
		Action:      action,
		EffectType:  effectType,
		EffectMode:  effectMode,
		Target:      target,
		OccurredAt:  time.Unix(0, 0).UTC(),
		WorkspaceID: defaultWorkspaceID,
	}
}

func receiptActionHasMetadata(receipt *contracts.AgentRunReceipt, actionID, key string) bool {
	for _, action := range receipt.ToolActions {
		if action.ActionID == actionID {
			_, ok := action.Metadata[key]
			return ok
		}
	}
	return false
}
