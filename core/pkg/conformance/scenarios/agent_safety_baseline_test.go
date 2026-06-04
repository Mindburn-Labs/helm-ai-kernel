package scenarios

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance/agentsafety"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/governance"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policybundles"
)

func TestAgentSafetyBaselineRegistryScenarios(t *testing.T) {
	engine, err := governance.NewPolicyEngine()
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	bundle := policybundles.AgentSafetyBaselineBundle()
	rules := make(map[string]policybundles.PolicyRule, len(bundle.Rules))
	for _, rule := range bundle.Rules {
		rules[rule.RuleID] = rule
	}

	ledger := governance.NewDenialLedger().WithClock(func() time.Time {
		return time.Unix(1760000000, 0).UTC()
	})

	for _, entry := range agentsafety.Registry() {
		t.Run(entry.CaseID, func(t *testing.T) {
			rule, ok := rules[entry.PolicyRuleID]
			if !ok {
				t.Fatalf("missing baseline rule %s", entry.PolicyRuleID)
			}
			if rule.Action != entry.ExpectedPolicyAction {
				t.Fatalf("rule action = %s, want %s", rule.Action, entry.ExpectedPolicyAction)
			}

			decision, err := engine.EvaluateAgentSafetyBaseline(context.Background(), contextForRegistryRule(entry.PolicyRuleID))
			if err != nil {
				t.Fatalf("EvaluateAgentSafetyBaseline: %v", err)
			}

			switch entry.ExpectedPolicyAction {
			case "deny":
				if decision.Verdict != string(contracts.VerdictDeny) {
					t.Fatalf("decision verdict = %s, want DENY: %#v", decision.Verdict, decision)
				}
				if entry.ExpectedReasonCode == "" {
					t.Fatal("deny scenario must declare a reason code")
				}
				if !contracts.IsCanonicalReasonCode(entry.ExpectedReasonCode) {
					t.Fatalf("non-canonical reason code %s", entry.ExpectedReasonCode)
				}
				if decision.ReasonCode != entry.ExpectedReasonCode {
					t.Fatalf("decision reason = %s, want %s", decision.ReasonCode, entry.ExpectedReasonCode)
				}
				receipt := ledger.DenyWithContext(
					"agent-safety-baseline",
					"tenant-agent-safety",
					entry.CaseID,
					"run-"+strings.ToLower(entry.CaseID),
					denialReason(entry.ExpectedReasonCode),
					entry.ExpectedReasonCode,
					entry.PolicyRuleID,
					policybundles.AgentSafetyBaselineBundleID,
				)
				if !entry.ReceiptRequired {
					t.Fatal("deny scenarios must require a receipt")
				}
				if receipt.ReceiptID == "" || receipt.ContentHash == "" {
					t.Fatalf("denial receipt is incomplete: %#v", receipt)
				}
				if receipt.PolicyRef != entry.PolicyRuleID {
					t.Fatalf("policy ref = %s, want %s", receipt.PolicyRef, entry.PolicyRuleID)
				}
			case "require_approval":
				if decision.Verdict != string(contracts.VerdictEscalate) {
					t.Fatalf("decision verdict = %s, want ESCALATE: %#v", decision.Verdict, decision)
				}
				if entry.ExpectedReasonCode != string(contracts.ReasonApprovalRequired) {
					t.Fatalf("approval scenario reason = %s, want %s", entry.ExpectedReasonCode, contracts.ReasonApprovalRequired)
				}
				if decision.ReasonCode != entry.ExpectedReasonCode {
					t.Fatalf("decision reason = %s, want %s", decision.ReasonCode, entry.ExpectedReasonCode)
				}
				if entry.ReceiptRequired {
					t.Fatal("approval scenarios should not be modeled as denial receipts")
				}
				if rule.Parameters["min_approvers"] == "" {
					t.Fatal("approval rule must declare min_approvers")
				}
			case "log":
				if decision.Verdict != string(contracts.VerdictAllow) {
					t.Fatalf("decision verdict = %s, want ALLOW: %#v", decision.Verdict, decision)
				}
				if entry.ExpectedReasonCode != "" {
					t.Fatalf("log scenario should not declare deny/escalate reason, got %s", entry.ExpectedReasonCode)
				}
				if entry.ReceiptRequired {
					t.Fatal("log scenario should not require denial receipt")
				}
			default:
				t.Fatalf("unsupported expected policy action %s", entry.ExpectedPolicyAction)
			}
		})
	}

	if ledger.Length() == 0 {
		t.Fatal("expected receipt-required deny scenarios")
	}
}

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
