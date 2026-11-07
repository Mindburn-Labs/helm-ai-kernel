package governance

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func safeAgentSafetyContext() AgentSafetyContext {
	return AgentSafetyContext{
		EffectType:             contracts.EffectTypeUpdateDoc,
		EffectClass:            "E1",
		ToolName:               "doc_writer",
		ConnectorID:            "connector-docs",
		Action:                 "read",
		Taint:                  []string{},
		SourceTrust:            "trusted",
		SourceChannel:          "user",
		MemoryTier:             "none",
		MemoryReviewState:      "approved",
		MemoryTrustScore:       100,
		ProvenanceScore:        2,
		DelegationSessionValid: true,
		CredentialScope:        "task_bound",
		A2ASignatureValid:      true,
		ManifestDigestValid:    true,
		OutputContractValid:    true,
		ApprovedArgsValid:      true,
		SafeDepState:           "normal",
		BudgetRemaining:        100,
		FanoutCount:            1,
		RetryCount:             0,
		PrincipalID:            "agent-safe",
		ResourceID:             "doc-1",
	}
}
