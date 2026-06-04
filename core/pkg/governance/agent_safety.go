package governance

import (
	"context"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policybundles"
)

// AgentSafetyContext is the runtime fact contract consumed by the built-in
// agent-safety baseline bundle.
type AgentSafetyContext struct {
	EffectType             string
	EffectClass            string
	ToolName               string
	ConnectorID            string
	Action                 string
	Taint                  []string
	SourceTrust            string
	SourceChannel          string
	MemoryTier             string
	MemoryReviewState      string
	MemoryTrustScore       int
	ProvenanceScore        int
	Destination            string
	PayloadBytes           int
	DelegationSessionValid bool
	CredentialScope        string
	A2ASignatureValid      bool
	ManifestDigestValid    bool
	OutputContractValid    bool
	ApprovedArgsValid      bool
	SafeDepState           string
	InspectionOnly         bool
	BudgetRemaining        int
	FanoutCount            int
	RetryCount             int
	PrincipalID            string
	ResourceID             string
}

// EvaluateAgentSafetyBaseline evaluates the built-in baseline as violation
// rules: matching deny rules DENY, approval rules ESCALATE, log rules ALLOW.
func (pe *PolicyEngine) EvaluateAgentSafetyBaseline(ctx context.Context, input AgentSafetyContext) (*contracts.DecisionRecord, error) {
	_ = ctx
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	decision := &contracts.DecisionRecord{
		ID:                fmt.Sprintf("agent-safety-dec-%d", time.Now().UnixNano()),
		Timestamp:         time.Now(),
		SubjectID:         input.PrincipalID,
		Action:            input.Action,
		Resource:          input.ResourceID,
		Verdict:           string(contracts.VerdictDeny),
		ReasonCode:        string(contracts.ReasonNoPolicy),
		Reason:            "agent safety baseline is not loaded",
		PolicyBackend:     "helm",
		PolicyContentHash: pe.agentSafetyBundleHash,
		PolicyVersion:     pe.agentSafetyBaselineID,
		InputContext:      input.toCELVars(),
	}
	if decision.SubjectID == "" {
		decision.SubjectID = "agent"
	}
	if pe.agentSafetyBaselineID == "" || len(pe.agentSafetyRules) == 0 {
		return decision, nil
	}

	var loggedRule string
	for _, rule := range pe.agentSafetyRules {
		prg := pe.agentSafetyPrograms[rule.RuleID]
		if prg == nil {
			return agentSafetyEvalErrorDecision(decision, rule, "missing compiled rule"), nil
		}
		out, _, err := prg.Eval(input.toCELVars())
		if err != nil {
			return agentSafetyEvalErrorDecision(decision, rule, err.Error()), nil
		}
		matched, ok := out.Value().(bool)
		if !ok {
			return agentSafetyEvalErrorDecision(decision, rule, "rule did not return bool"), nil
		}
		if !matched {
			continue
		}

		reason := rule.Parameters["reason_code"]
		switch rule.Action {
		case "deny":
			decision.Verdict = string(contracts.VerdictDeny)
			decision.ReasonCode = reason
			decision.Reason = fmt.Sprintf("Denied by agent safety rule %s", rule.RuleID)
			decision.PolicyVersion = pe.agentSafetyBaselineID
			return decision, nil
		case "require_approval":
			decision.Verdict = string(contracts.VerdictEscalate)
			decision.ReasonCode = reason
			decision.Reason = fmt.Sprintf("Approval required by agent safety rule %s", rule.RuleID)
			decision.PolicyVersion = pe.agentSafetyBaselineID
			return decision, nil
		case "log":
			loggedRule = rule.RuleID
		default:
			return agentSafetyEvalErrorDecision(decision, rule, "unsupported rule action"), nil
		}
	}

	decision.Verdict = string(contracts.VerdictAllow)
	decision.ReasonCode = ""
	decision.PolicyVersion = pe.agentSafetyBaselineID
	if loggedRule != "" {
		decision.Reason = fmt.Sprintf("Allowed with agent safety evidence rule %s", loggedRule)
	} else {
		decision.Reason = fmt.Sprintf("Allowed by %s", policybundles.AgentSafetyBaselineBundleID)
	}
	return decision, nil
}

func agentSafetyEvalErrorDecision(base *contracts.DecisionRecord, rule policybundles.PolicyRule, detail string) *contracts.DecisionRecord {
	decision := *base
	decision.Verdict = string(contracts.VerdictDeny)
	decision.ReasonCode = string(contracts.ReasonPRGEvalError)
	decision.Reason = fmt.Sprintf("Agent safety rule %s evaluation failed: %s", rule.RuleID, detail)
	return &decision
}

func (c AgentSafetyContext) toCELVars() map[string]any {
	taint := c.Taint
	if taint == nil {
		taint = []string{}
	}
	return map[string]any{
		"effect_type":              c.EffectType,
		"effect_class":             c.EffectClass,
		"tool_name":                c.ToolName,
		"connector_id":             c.ConnectorID,
		"action":                   c.Action,
		"taint":                    taint,
		"source_trust":             c.SourceTrust,
		"source_channel":           c.SourceChannel,
		"memory_tier":              c.MemoryTier,
		"memory_review_state":      c.MemoryReviewState,
		"memory_trust_score":       c.MemoryTrustScore,
		"provenance_score":         c.ProvenanceScore,
		"destination":              c.Destination,
		"payload_bytes":            c.PayloadBytes,
		"delegation_session_valid": c.DelegationSessionValid,
		"credential_scope":         c.CredentialScope,
		"a2a_signature_valid":      c.A2ASignatureValid,
		"manifest_digest_valid":    c.ManifestDigestValid,
		"output_contract_valid":    c.OutputContractValid,
		"approved_args_valid":      c.ApprovedArgsValid,
		"safe_dep_state":           c.SafeDepState,
		"inspection_only":          c.InspectionOnly,
		"budget_remaining":         c.BudgetRemaining,
		"fanout_count":             c.FanoutCount,
		"retry_count":              c.RetryCount,
	}
}
