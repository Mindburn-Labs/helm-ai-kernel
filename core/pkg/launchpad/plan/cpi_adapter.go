package plan

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/cpi"
)

type CPIVerdict string

const (
	CPIVerdictAllow    CPIVerdict = "ALLOW"
	CPIVerdictDeny     CPIVerdict = "DENY"
	CPIVerdictEscalate CPIVerdict = "ESCALATE"
)

type ActionKind string

const (
	ActionPlan             ActionKind = "plan"
	ActionProvision        ActionKind = "provision"
	ActionInstall          ActionKind = "install"
	ActionSandboxPreflight ActionKind = "sandbox_preflight"
	ActionMCPBind          ActionKind = "mcp_bind"
	ActionStart            ActionKind = "start"
	ActionHealthcheck      ActionKind = "healthcheck"
	ActionRepair           ActionKind = "repair"
	ActionTeardown         ActionKind = "teardown"
)

type ActionIR struct {
	ID          string         `json:"id"`
	Kind        ActionKind     `json:"kind"`
	AppID       string         `json:"app_id"`
	SubstrateID string         `json:"substrate_id"`
	Effect      string         `json:"effect"`
	Inputs      map[string]any `json:"inputs"`
}

type CPIOutput struct {
	Verdict    CPIVerdict      `json:"verdict"`
	ReasonCode string          `json:"reason_code,omitempty"`
	ResultHash string          `json:"result_hash"`
	CheckedAt  time.Time       `json:"checked_at"`
	Actions    []ActionIR      `json:"actions"`
	RawResult  json.RawMessage `json:"raw_result,omitempty"`
}

func CompileActionIR(plan LaunchPlan) []ActionIR {
	common := map[string]any{
		"launch_id":   plan.LaunchID,
		"plan_hash":   plan.PlanHash,
		"policy_hash": plan.PolicyHash,
	}
	return []ActionIR{
		{ID: plan.LaunchID + ":plan", Kind: ActionPlan, AppID: plan.AppID, SubstrateID: plan.SubstrateID, Effect: "launchpad.plan", Inputs: common},
		{ID: plan.LaunchID + ":provision", Kind: ActionProvision, AppID: plan.AppID, SubstrateID: plan.SubstrateID, Effect: "launchpad.provision", Inputs: common},
		{ID: plan.LaunchID + ":install", Kind: ActionInstall, AppID: plan.AppID, SubstrateID: plan.SubstrateID, Effect: "launchpad.install", Inputs: common},
		{ID: plan.LaunchID + ":sandbox_preflight", Kind: ActionSandboxPreflight, AppID: plan.AppID, SubstrateID: plan.SubstrateID, Effect: "launchpad.sandbox_preflight", Inputs: common},
		{ID: plan.LaunchID + ":mcp_bind", Kind: ActionMCPBind, AppID: plan.AppID, SubstrateID: plan.SubstrateID, Effect: "launchpad.mcp_bind", Inputs: common},
		{ID: plan.LaunchID + ":start", Kind: ActionStart, AppID: plan.AppID, SubstrateID: plan.SubstrateID, Effect: "launchpad.start", Inputs: common},
		{ID: plan.LaunchID + ":healthcheck", Kind: ActionHealthcheck, AppID: plan.AppID, SubstrateID: plan.SubstrateID, Effect: "launchpad.healthcheck", Inputs: common},
	}
}

func CompileTeardownIR(plan LaunchPlan) []ActionIR {
	return []ActionIR{{
		ID:          plan.LaunchID + ":teardown",
		Kind:        ActionTeardown,
		AppID:       plan.AppID,
		SubstrateID: plan.SubstrateID,
		Effect:      "launchpad.teardown",
		Inputs: map[string]any{
			"launch_id": plan.LaunchID,
			"plan_hash": plan.PlanHash,
		},
	}}
}

func EvaluateActions(plan LaunchPlan, actions []ActionIR) (CPIOutput, error) {
	p0Verdict := plan.KernelVerdict
	if p0Verdict == "" {
		p0Verdict = string(CPIVerdictEscalate)
	}
	layers := []cpi.PolicyLayer{
		{
			Name:     "P0",
			Priority: 0,
			Rules: []cpi.PolicyRule{{
				ID:      "launchpad-no-side-effect-without-conformance",
				Action:  "launchpad.*",
				Verdict: p0Verdict,
				Reason:  "Launchpad side effects require policy, sandbox, receipt, and EvidencePack conformance",
			}},
			Metadata: map[string]string{"source": "launchpad"},
		},
		{
			Name:     "P1",
			Priority: 1,
			Rules: []cpi.PolicyRule{{
				ID:      "launchpad-requested-actions",
				Action:  "launchpad.*",
				Verdict: string(plan.KernelVerdict),
				Reason:  "Launchpad compiled action request",
			}},
			Metadata: map[string]string{"launch_id": plan.LaunchID, "plan_hash": plan.PlanHash},
		},
	}
	facts, err := json.Marshal(layers)
	if err != nil {
		return CPIOutput{}, err
	}
	raw, err := cpi.Validate(nil, nil, nil, facts)
	if err != nil {
		return CPIOutput{}, err
	}
	var result cpi.ValidationResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return CPIOutput{}, err
	}
	verdict := CPIVerdict(plan.KernelVerdict)
	if verdict == "" {
		verdict = CPIVerdictEscalate
	}
	reason := ""
	if result.Verdict == cpi.VerdictConflict {
		verdict = CPIVerdictEscalate
		reason = "ERR_LAUNCHPAD_POLICY_CONFLICT"
	}
	if verdict == CPIVerdictEscalate && reason == "" {
		reason = "ERR_LAUNCHPAD_CPI_ESCALATE"
	}
	if plan.KernelVerdict == string(CPIVerdictDeny) {
		verdict = CPIVerdictDeny
		reason = "ERR_LAUNCHPAD_POLICY_DENY"
	}
	if result.Hash == "" {
		return CPIOutput{}, fmt.Errorf("cpi result hash missing")
	}
	return CPIOutput{
		Verdict:    verdict,
		ReasonCode: reason,
		ResultHash: result.Hash,
		CheckedAt:  time.Now().UTC(),
		Actions:    actions,
		RawResult:  raw,
	}, nil
}
