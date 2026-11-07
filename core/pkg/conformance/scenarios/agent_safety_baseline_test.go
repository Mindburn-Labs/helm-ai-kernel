package scenarios

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance/agentsafety"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/governance"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policybundles"
)

func TestAgentSafetyBaselineCoversEveryGroup(t *testing.T) {
	wantPrefixes := []string{"AGH", "TME", "IPA", "ASC", "RCE", "MEM", "A2A", "CAS", "HITL", "ROG", "BENCH"}
	seen := map[string]bool{}
	for _, entry := range agentsafety.Registry() {
		prefix := strings.Split(entry.CaseID, "-")[0]
		seen[prefix] = true
	}
	for _, prefix := range wantPrefixes {
		if !seen[prefix] {
			t.Fatalf("missing case group %s", prefix)
		}
	}
}

func contextForRegistryRule(ruleID string) governance.AgentSafetyContext {
	ctx := safeRegistryContext()
	switch ruleID {
	case policybundles.AgentSafetyRuleMissingContext:
		return governance.AgentSafetyContext{}
	case policybundles.AgentSafetyRuleTaintedHighRisk:
		ctx.EffectClass = "E3"
		ctx.Taint = []string{"prompt_injection"}
	case policybundles.AgentSafetyRuleProtectedConfig:
		ctx.Action = "modify_policy"
	case policybundles.AgentSafetyRuleToolContract:
		ctx.ToolName = ""
	case policybundles.AgentSafetyRuleApprovedArgs:
		ctx.ApprovedArgsValid = false
	case policybundles.AgentSafetyRuleEgressBoundary:
		ctx.EffectType = contracts.EffectTypeDataEgress
		ctx.SourceTrust = "untrusted"
	case policybundles.AgentSafetyRuleSupplyChain:
		ctx.SourceChannel = "registry"
		ctx.ProvenanceScore = 1
	case policybundles.AgentSafetyRuleDelegationIdentity:
		ctx.DelegationSessionValid = false
	case policybundles.AgentSafetyRuleA2AVerification:
		ctx.A2ASignatureValid = false
	case policybundles.AgentSafetyRuleMemoryInfluenceOnly:
		ctx.MemoryTier = "LKS"
		ctx.Action = "select_tool"
	case policybundles.AgentSafetyRulePreviewSideEffect:
		ctx.InspectionOnly = true
		ctx.Action = "execute"
	case policybundles.AgentSafetyRuleSafeDepOverride:
		ctx.SafeDepState = "terminal_freeze"
	case policybundles.AgentSafetyRuleBudgetCircuitBreaker:
		ctx.BudgetRemaining = -1
	case policybundles.AgentSafetyRuleHighImpactApproval:
		ctx.EffectType = contracts.EffectTypeSoftwarePublish
		ctx.EffectClass = "E4"
	case policybundles.AgentSafetyRuleBenchmarkEvidence:
		ctx.SourceChannel = "benchmark"
	}
	return ctx
}

func safeRegistryContext() governance.AgentSafetyContext {
	return governance.AgentSafetyContext{
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
		PrincipalID:            "agent-safety-baseline",
		ResourceID:             "registry-case",
	}
}

func denialReason(reasonCode string) governance.DenialReason {
	switch contracts.ReasonCode(reasonCode) {
	case contracts.ReasonProvenance:
		return governance.DenialProvenance
	case contracts.ReasonVerification, contracts.ReasonDelegationInvalid:
		return governance.DenialVerification
	case contracts.ReasonBudgetExceeded:
		return governance.DenialBudget
	case contracts.ReasonDataEgressBlocked:
		return governance.DenialSandbox
	default:
		if reasonCode == "" {
			panic(fmt.Sprintf("empty reason code"))
		}
		return governance.DenialPolicy
	}
}
