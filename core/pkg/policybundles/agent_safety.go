package policybundles

import (
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policycel"
	"github.com/google/cel-go/cel"
)

const (
	AgentSafetyBaselineBundleID = "builtin-agent-safety-baseline"
	AgentSafetyBaselineCategory = "agent_safety"

	AgentSafetyRuleTaintedHighRisk      = "asb-001-tainted-high-risk"
	AgentSafetyRuleProtectedConfig      = "asb-002-protected-config"
	AgentSafetyRuleToolContract         = "asb-003-tool-contract"
	AgentSafetyRuleEgressBoundary       = "asb-004-egress-boundary"
	AgentSafetyRuleHighImpactApproval   = "asb-005-high-impact-approval"
	AgentSafetyRuleDelegationIdentity   = "asb-006-delegation-identity"
	AgentSafetyRuleMemoryInfluenceOnly  = "asb-007-memory-influence-only"
	AgentSafetyRuleA2AVerification      = "asb-008-a2a-verification"
	AgentSafetyRuleSafeDepOverride      = "asb-009-safedep-override"
	AgentSafetyRulePreviewSideEffect    = "asb-010-preview-side-effect"
	AgentSafetyRuleSupplyChain          = "asb-011-supply-chain-provenance"
	AgentSafetyRuleMissingContext       = "asb-012-missing-context"
	AgentSafetyRuleApprovedArgs         = "asb-013-approved-args"
	AgentSafetyRuleBudgetCircuitBreaker = "asb-014-budget-circuit-breaker"
	AgentSafetyRuleBenchmarkEvidence    = "asb-015-benchmark-evidence"
)

// AgentSafetyDecisionField describes a variable that baseline CEL rules expect.
type AgentSafetyDecisionField struct {
	Name        string
	CELType     string
	Required    bool
	FailClosed  bool
	Description string
}

// AgentSafetyDecisionContextFields returns the compact decision context contract.
func AgentSafetyDecisionContextFields() []AgentSafetyDecisionField {
	fields := []AgentSafetyDecisionField{
		{Name: "effect_type", CELType: "string", Required: true, FailClosed: true, Description: "canonical effect type"},
		{Name: "effect_class", CELType: "string", Required: true, FailClosed: true, Description: "E1-E4 effect class"},
		{Name: "tool_name", CELType: "string", Required: true, FailClosed: true, Description: "resolved tool name"},
		{Name: "connector_id", CELType: "string", Required: true, FailClosed: true, Description: "resolved connector identity"},
		{Name: "action", CELType: "string", Required: true, FailClosed: true, Description: "requested action"},
		{Name: "taint", CELType: "list<string>", Required: true, FailClosed: true, Description: "threat-source taint labels"},
		{Name: "source_trust", CELType: "string", Required: true, FailClosed: true, Description: "trusted or untrusted source posture"},
		{Name: "source_channel", CELType: "string", Required: true, FailClosed: true, Description: "origin channel such as user, tool_output, registry, benchmark"},
		{Name: "memory_tier", CELType: "string", Required: true, FailClosed: true, Description: "LKS, CKS, or none"},
		{Name: "memory_review_state", CELType: "string", Required: true, FailClosed: true, Description: "memory review status"},
		{Name: "memory_trust_score", CELType: "int", Required: true, FailClosed: true, Description: "0-100 memory trust score"},
		{Name: "provenance_score", CELType: "int", Required: true, FailClosed: true, Description: "independent source count or normalized score"},
		{Name: "destination", CELType: "string", Required: true, FailClosed: true, Description: "network or data destination"},
		{Name: "payload_bytes", CELType: "int", Required: true, FailClosed: true, Description: "egress payload size"},
		{Name: "delegation_session_valid", CELType: "bool", Required: true, FailClosed: true, Description: "delegation session validity"},
		{Name: "credential_scope", CELType: "string", Required: true, FailClosed: true, Description: "credential scope posture"},
		{Name: "a2a_signature_valid", CELType: "bool", Required: true, FailClosed: true, Description: "inter-agent signature verification"},
		{Name: "manifest_digest_valid", CELType: "bool", Required: true, FailClosed: true, Description: "tool or artifact digest verification"},
		{Name: "output_contract_valid", CELType: "bool", Required: true, FailClosed: true, Description: "connector output contract verification"},
		{Name: "approved_args_valid", CELType: "bool", Required: true, FailClosed: true, Description: "execution args match approved args"},
		{Name: "safe_dep_state", CELType: "string", Required: true, FailClosed: true, Description: "SafeDep lifecycle state"},
		{Name: "inspection_only", CELType: "bool", Required: true, FailClosed: true, Description: "read-only preview or inspection mode"},
		{Name: "budget_remaining", CELType: "int", Required: true, FailClosed: true, Description: "remaining budget after planned effect"},
		{Name: "fanout_count", CELType: "int", Required: true, FailClosed: true, Description: "planned fan-out action count"},
		{Name: "retry_count", CELType: "int", Required: true, FailClosed: true, Description: "planned retry count"},
	}
	out := make([]AgentSafetyDecisionField, len(fields))
	copy(out, fields)
	return out
}

// AgentSafetyCELEnvOptions returns CEL variables used by the baseline bundle.
func AgentSafetyCELEnvOptions() []cel.EnvOption {
	opts := []cel.EnvOption{
		cel.Variable("effect_type", cel.StringType),
		cel.Variable("effect_class", cel.StringType),
		cel.Variable("tool_name", cel.StringType),
		cel.Variable("connector_id", cel.StringType),
		cel.Variable("action", cel.StringType),
		cel.Variable("source_trust", cel.StringType),
		cel.Variable("source_channel", cel.StringType),
		cel.Variable("memory_tier", cel.StringType),
		cel.Variable("memory_review_state", cel.StringType),
		cel.Variable("memory_trust_score", cel.IntType),
		cel.Variable("provenance_score", cel.IntType),
		cel.Variable("destination", cel.StringType),
		cel.Variable("payload_bytes", cel.IntType),
		cel.Variable("delegation_session_valid", cel.BoolType),
		cel.Variable("credential_scope", cel.StringType),
		cel.Variable("a2a_signature_valid", cel.BoolType),
		cel.Variable("manifest_digest_valid", cel.BoolType),
		cel.Variable("output_contract_valid", cel.BoolType),
		cel.Variable("approved_args_valid", cel.BoolType),
		cel.Variable("safe_dep_state", cel.StringType),
		cel.Variable("inspection_only", cel.BoolType),
		cel.Variable("budget_remaining", cel.IntType),
		cel.Variable("fanout_count", cel.IntType),
		cel.Variable("retry_count", cel.IntType),
	}
	opts = append(opts, policycel.TaintEnvOptions()...)
	return opts
}

// AgentSafetyBaselineBundle returns the built-in baseline agent-safety policy.
func AgentSafetyBaselineBundle() *PolicyBundle {
	return &PolicyBundle{
		BundleID:     AgentSafetyBaselineBundleID,
		Name:         "Agent Safety Baseline",
		Description:  "Default fail-closed controls for agent goal hijack, tool misuse, identity abuse, supply chain, execution, memory, A2A, cascade, HITL, rogue-agent, and benchmark conformance cases.",
		Jurisdiction: "global",
		Category:     AgentSafetyBaselineCategory,
		Version:      1,
		Status:       BundleStatusActive,
		Rules: []PolicyRule{
			agentSafetyRule(
				AgentSafetyRuleMissingContext,
				"Missing high-risk context fails closed",
				"Required baseline decision fields must be present before dispatch.",
				"effect_type == '' || effect_class == '' || action == '' || source_trust == ''",
				"deny",
				10,
				contracts.ReasonNoPolicy,
				[]string{"effect_type", "effect_class", "action", "source_trust"},
			),
			agentSafetyRule(
				AgentSafetyRuleTaintedHighRisk,
				"Tainted source cannot drive high-risk effects",
				"Prompt, tool-output, or untrusted instruction taint blocks E3/E4 dispatch.",
				"(effect_class == 'E3' || effect_class == 'E4') && (taint_contains(taint, 'prompt_injection') || taint_contains(taint, 'untrusted_instruction') || taint_contains(taint, 'tool_output_instruction'))",
				"deny",
				20,
				contracts.ReasonTaintedInputDeny,
				[]string{"effect_class", "taint"},
			),
			agentSafetyRule(
				AgentSafetyRuleProtectedConfig,
				"Protected policy and system settings require provenance",
				"Agents cannot modify prompts, policy, reward, or safety settings from ordinary instructions.",
				"action == 'modify_policy' || action == 'modify_system_prompt' || action == 'modify_reward' || action == 'modify_safety_settings'",
				"deny",
				30,
				contracts.ReasonPolicyViolation,
				[]string{"action"},
			),
			agentSafetyRule(
				AgentSafetyRuleToolContract,
				"Tool identity and contracts are mandatory",
				"Unknown tools, connector IDs, digests, and output contracts fail closed.",
				"tool_name == '' || connector_id == '' || manifest_digest_valid == false || output_contract_valid == false",
				"deny",
				40,
				contracts.ReasonVerification,
				[]string{"tool_name", "connector_id", "manifest_digest_valid", "output_contract_valid"},
			),
			agentSafetyRule(
				AgentSafetyRuleApprovedArgs,
				"Execution args must match approved args",
				"Tool calls cannot drift between preview, approval, and dispatch.",
				"approved_args_valid == false",
				"deny",
				50,
				contracts.ReasonPolicyViolation,
				[]string{"approved_args_valid"},
			),
			agentSafetyRule(
				AgentSafetyRuleEgressBoundary,
				"Untrusted egress is blocked",
				"External destinations and large payloads require explicit egress policy.",
				"(effect_type == 'DATA_EGRESS' || destination != '') && (source_trust == 'untrusted' || payload_bytes > 1048576)",
				"deny",
				60,
				contracts.ReasonDataEgressBlocked,
				[]string{"effect_type", "destination", "source_trust", "payload_bytes"},
			),
			agentSafetyRule(
				AgentSafetyRuleSupplyChain,
				"Supply-chain artifacts require provenance",
				"Registry artifacts without valid digests and independent provenance are rejected.",
				"source_channel == 'registry' && (manifest_digest_valid == false || provenance_score < 2)",
				"deny",
				70,
				contracts.ReasonProvenance,
				[]string{"source_channel", "manifest_digest_valid", "provenance_score"},
			),
			agentSafetyRule(
				AgentSafetyRuleDelegationIdentity,
				"Delegation and credential scope must be current",
				"Expired, invalid, or overbroad delegation cannot authorize action.",
				"delegation_session_valid == false || credential_scope == 'overbroad' || credential_scope == 'expired' || credential_scope == 'escalated'",
				"deny",
				80,
				contracts.ReasonDelegationInvalid,
				[]string{"delegation_session_valid", "credential_scope"},
			),
			agentSafetyRule(
				AgentSafetyRuleA2AVerification,
				"Inter-agent identity must verify",
				"A2A messages and agent cards must have valid identity proof before trust.",
				"a2a_signature_valid == false",
				"deny",
				90,
				contracts.ReasonDelegationInvalid,
				[]string{"a2a_signature_valid"},
			),
			agentSafetyRule(
				AgentSafetyRuleMemoryInfluenceOnly,
				"LKS memory is influence-only",
				"Unreviewed memory cannot authorize tools, policies, or high-risk effects.",
				"memory_tier == 'LKS' && (action == 'authorize' || action == 'select_tool' || effect_class == 'E3' || effect_class == 'E4' || memory_review_state != 'approved')",
				"deny",
				100,
				contracts.ReasonSessionRiskDeny,
				[]string{"memory_tier", "action", "effect_class", "memory_review_state"},
			),
			agentSafetyRule(
				AgentSafetyRulePreviewSideEffect,
				"Inspection mode is side-effect free",
				"Preview and read-only inspection cannot perform mutation or network side effects.",
				"inspection_only == true && (effect_class == 'E3' || effect_class == 'E4' || action == 'egress' || action == 'mutate' || action == 'execute')",
				"deny",
				110,
				contracts.ReasonPolicyViolation,
				[]string{"inspection_only", "effect_class", "action"},
			),
			agentSafetyRule(
				AgentSafetyRuleSafeDepOverride,
				"SafeDep state overrides ordinary allow",
				"Freeze, degraded narrowing, and deprecated readonly states stop or narrow dispatch.",
				"safe_dep_state == 'terminal_freeze' || safe_dep_state == 'degraded_narrow' || safe_dep_state == 'deprecated_readonly'",
				"deny",
				120,
				contracts.ReasonSystemFrozen,
				[]string{"safe_dep_state"},
			),
			agentSafetyRule(
				AgentSafetyRuleBudgetCircuitBreaker,
				"Budget and fan-out circuit breaker",
				"Cost storms, retry storms, and fleet fan-out are denied before cascade.",
				"budget_remaining < 0 || fanout_count > 10 || retry_count > 3",
				"deny",
				130,
				contracts.ReasonBudgetExceeded,
				[]string{"budget_remaining", "fanout_count", "retry_count"},
			),
			agentSafetyRule(
				AgentSafetyRuleHighImpactApproval,
				"High-impact effects require approval",
				"E4 effects and canonical irreversible actions require dual-control approval.",
				"effect_class == 'E4' || effect_type == 'CI_CREDENTIAL_ACCESS' || effect_type == 'SOFTWARE_PUBLISH' || effect_type == 'INFRA_DESTROY' || effect_type == 'EXECUTE_PAYMENT' || effect_type == 'REQUEST_PURCHASE'",
				"require_approval",
				140,
				contracts.ReasonApprovalRequired,
				[]string{"effect_type", "effect_class"},
				map[string]string{"min_approvers": "2", "dual_control": "true"},
			),
			agentSafetyRule(
				AgentSafetyRuleBenchmarkEvidence,
				"Benchmark imports are measured evidence",
				"Imported adversarial and benign benchmark cases must remain explicit evidence, not implicit allow policy.",
				"source_channel == 'benchmark'",
				"log",
				150,
				"",
				[]string{"source_channel"},
			),
		},
	}
}

func agentSafetyRule(id, name, description, condition, action string, priority int, reason contracts.ReasonCode, fields []string, extra ...map[string]string) PolicyRule {
	params := map[string]string{
		"context_fields": strings.Join(fields, ","),
	}
	if reason != "" {
		params["reason_code"] = string(reason)
	}
	if len(extra) > 0 {
		for k, v := range extra[0] {
			params[k] = v
		}
	}
	return PolicyRule{
		RuleID:      id,
		Name:        name,
		Description: description,
		Condition:   condition,
		Action:      action,
		Priority:    priority,
		Parameters:  params,
	}
}
