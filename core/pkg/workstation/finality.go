package workstation

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

// Denial finality and counterfactuals are derived here, from the reason code
// that fired. Nothing in this file is reachable from a caller-supplied value:
// an evaluator returns a reason code, and the tables below decide what may be
// said about it. That is the whole point — a denial that teaches has to teach
// the same lesson every time, and a hand-assigned field drifts from the rule
// it claims to describe.

// disclosure says what a denial is allowed to reveal about the policy that
// produced it. The zero value discloses nothing, so a code that is added to
// denialCatalog without a considered disclosure class leaks nothing by default.
type disclosure uint8

const (
	// discloseNothing: the reason code is the whole answer.
	discloseNothing disclosure = iota
	// discloseScalarBound: a numeric ceiling the agent can retry under.
	discloseScalarBound
	// discloseCapabilityName: the permission the action would have needed.
	discloseCapabilityName
)

type denialClass struct {
	finality   contracts.DenialFinality
	disclosure disclosure
}

// denialCatalog maps every workstation deny reason code to what a consumer may
// learn from it.
//
// Membership denials (egress allowlist, workspace roots) deliberately disclose
// nothing beyond their finality. The set is a map of internal infrastructure;
// answering "not that one, try these" would turn each denial into a free probe
// of the estate. The agent learns "this target is closed" and stops probing.
var denialCatalog = map[string]denialClass{
	// The context was refused, not the action. Nothing about the action changed.
	"TAINTED_CONTEXT_REQUIRES_DENY": {contracts.DenialInstanceContext, discloseNothing},

	// Refused by membership in a confidential set: the target is closed,
	// other targets may work, the set is never described. No counterfactual, ever.
	"EGRESS_DESTINATION_NOT_ALLOWED":       {contracts.DenialInstanceMembership, discloseNothing},
	"DRAFT_TARGET_OUTSIDE_WORKSPACE_SCOPE": {contracts.DenialInstanceMembership, discloseNothing},

	// Not membership: the refused thing is a policy-named category of action
	// (writing a given memory class) from a fixed public vocabulary, so the
	// class lesson applies — stop attempting that category.
	"MEMORY_CLASS_DISALLOWED": {contracts.DenialClassForbidden, discloseNothing},

	// A bound was exceeded and the agent can retry under it.
	"MEMORY_TTL_EXCEEDS_POLICY": {contracts.DenialInstanceParameter, discloseScalarBound},

	// A required field was absent. The reason code already names it, so there
	// is nothing a counterfactual would add.
	"RECURRING_LOOP_MISSING_SCHEDULE":    {contracts.DenialInstanceParameter, discloseNothing},
	"RECURRING_LOOP_MISSING_MAX_RUNTIME": {contracts.DenialInstanceParameter, discloseNothing},
	"RECURRING_LOOP_MISSING_TOOL_SCOPE":  {contracts.DenialInstanceParameter, discloseNothing},
	"RECURRING_LOOP_MISSING_EXPIRATION":  {contracts.DenialInstanceParameter, discloseNothing},

	// Nobody granted this. The workstation layer has no approver to escalate
	// to, so these are terminal here; the kernel PDP routes the same finality
	// onto its escalation channel, where a signer exists to address.
	"OPERATE_PERMISSION_NOT_GRANTED": {contracts.DenialUngranted, discloseCapabilityName},
	"OPERATE_PERMISSIONS_EMPTY":      {contracts.DenialUngranted, discloseNothing},
	"EGRESS_ALLOWLIST_EMPTY":         {contracts.DenialUngranted, discloseNothing},
}

// DenialFinality returns the finality for a workstation deny reason code.
// Unknown codes return "" — a denial HELM cannot classify says nothing about
// itself rather than guessing.
func DenialFinality(reasonCode string) contracts.DenialFinality {
	return denialCatalog[reasonCode].finality
}

// DenialCounterfactualFor returns the nearest allowed envelope for a denial, or
// nil when the denial's disclosure class forbids one. Every path that does not
// explicitly build a counterfactual returns nil, so an unclassified code
// discloses nothing.
//
// Exported because a conformance consumer has to be able to observe what a
// denial discloses without reconstructing the import pipeline.
func DenialCounterfactualFor(profile contracts.WorkstationPolicyProfile, event ToolEvent, reasonCode string) *contracts.DenialCounterfactual {
	switch denialCatalog[reasonCode].disclosure {
	case discloseScalarBound:
		// Only MEMORY_TTL_EXCEEDS_POLICY carries a scalar today. A future
		// scalar code gets nil until someone writes its bound here, which is
		// the safe direction to be wrong in.
		if reasonCode != "MEMORY_TTL_EXCEEDS_POLICY" || event.MemoryEffect == nil {
			return nil
		}
		// Only report a request the event actually made. When the event
		// declared no TTL the effective value came from the profile default,
		// and reporting that as "requested" would both misstate what the
		// agent asked for and disclose a second policy scalar nobody agreed
		// to publish.
		requested := event.MemoryEffect.TTLDays
		if requested == 0 || profile.Memory.MaxTTLDays == 0 {
			return nil
		}
		return &contracts.DenialCounterfactual{
			Field:     "ttl_days",
			Requested: requested,
			Max:       profile.Memory.MaxTTLDays,
		}
	case discloseCapabilityName:
		// workstationPermissionForEffect falls back to the raw effect_type
		// for anything it does not recognise, and effect_type is producer
		// supplied. Disclose only names from the fixed vocabulary, or a
		// crafted event would land an arbitrary attacker-chosen string in a
		// signed receipt field the contract describes as an enum.
		required := workstationPermissionForEffect(event.EffectType, event.Type, event.Action)
		if !isKnownPermission(required) {
			return nil
		}
		return &contracts.DenialCounterfactual{
			Field:      "operate.permissions",
			Capability: required,
		}
	}
	return nil
}

// knownPermissions is the closed vocabulary a counterfactual may name.
var knownPermissions = map[string]struct{}{
	contracts.WorkstationPermissionNetworkEgress:   {},
	contracts.WorkstationPermissionMCPMutate:       {},
	contracts.WorkstationPermissionMemoryWrite:     {},
	contracts.WorkstationPermissionLoopRegister:    {},
	contracts.WorkstationPermissionShellOperate:    {},
	contracts.WorkstationPermissionDeployPublish:   {},
	contracts.WorkstationPermissionSecretRead:      {},
	contracts.WorkstationPermissionPaymentInitiate: {},
}

func isKnownPermission(name string) bool {
	_, ok := knownPermissions[name]
	return ok
}

// AnnotateDenial fills the learning fields on a denied effect, subject to the
// profile opting in. Both switches default off, and a disabled field is absent
// rather than empty, so receipts from profiles that never opted in stay
// byte-identical.
//
// reasonCode must be the code the evaluator produced, never one declared by
// the agent's own event log — see normalizeEvents.
func AnnotateDenial(denied *contracts.AgentDeniedEffect, profile contracts.WorkstationPolicyProfile, event ToolEvent, reasonCode string) {
	learning := profile.Learning
	if learning == nil {
		return
	}
	if learning.EmitFinality {
		denied.Finality = DenialFinality(reasonCode)
	}
	if learning.EmitCounterfactual {
		denied.Counterfactual = DenialCounterfactualFor(profile, event, reasonCode)
	}
}
