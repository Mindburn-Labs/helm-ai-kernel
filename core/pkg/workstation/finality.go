package workstation

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

// Denial finality and counterfactuals are derived here, from the reason code
// that fired. A complete denied effect is built from that same evaluation, so
// its counterfactual cannot be attached to another event that happens to share
// its identifiers. The tables below decide what may be said about that result.

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

// denialFinality returns the finality for an evaluated workstation deny reason
// code. Unknown codes return "" — a denial HELM cannot classify says nothing
// about itself rather than guessing.
func denialFinality(reasonCode string) contracts.DenialFinality {
	return denialCatalog[reasonCode].finality
}

// DenialFinality classifies a workstation denial code for compatibility with
// downstream consumers. It is read-only: receipt learning fields must still
// be produced through EvaluateDeniedEffect, which evaluates and constructs a
// complete denied effect together.
func DenialFinality(reasonCode string) contracts.DenialFinality {
	return denialFinality(reasonCode)
}

// denialCounterfactualFor returns the nearest allowed envelope for an
// evaluated denial, or nil when the denial's disclosure class forbids one.
// Every path that does not explicitly build a counterfactual returns nil, so
// an unclassified code discloses nothing.
func denialCounterfactualFor(profile contracts.WorkstationPolicyProfile, event ToolEvent, reasonCode string) *contracts.DenialCounterfactual {
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
		counterfactual := &contracts.DenialCounterfactual{
			Field:     "ttl_days",
			Requested: requested,
			Max:       profile.Memory.MaxTTLDays,
		}
		if err := counterfactual.Validate(); err != nil {
			return nil
		}
		return counterfactual
	case discloseCapabilityName:
		// workstationPermissionForEffect falls back to the raw effect_type
		// for anything it does not recognise, and effect_type is producer
		// supplied. Disclose only names from the fixed vocabulary, or a
		// crafted event would land an arbitrary attacker-chosen string in a
		// signed receipt field the contract describes as an enum.
		required := workstationPermissionForEffect(event.EffectType, event.Type, event.Action)
		if !contracts.IsWorkstationPermission(required) {
			return nil
		}
		return &contracts.DenialCounterfactual{
			Field:      "operate.permissions",
			Capability: required,
		}
	}
	return nil
}

// EvaluateDeniedEffect evaluates event and, when it is denied, returns the
// complete receipt effect derived from that one evaluation. The construction is
// deliberately atomic: counterfactual fields must not be added to a separate,
// caller-supplied receipt effect.
func EvaluateDeniedEffect(profile contracts.WorkstationPolicyProfile, event ToolEvent) (contracts.AgentDeniedEffect, bool) {
	verdict, reasonCode, reason := EvaluateEvent(profile, event)
	if verdict != contracts.WorkstationVerdictDeny {
		return contracts.AgentDeniedEffect{}, false
	}
	return evaluatedDeniedEffect(profile, event, reasonCode, reason), true
}

func evaluatedDeniedEffect(profile contracts.WorkstationPolicyProfile, event ToolEvent, reasonCode, reason string) contracts.AgentDeniedEffect {
	denied := contracts.AgentDeniedEffect{
		EffectID:   event.EventID,
		EffectType: event.EffectType,
		ToolID:     event.ToolID,
		Action:     event.Action,
		ReasonCode: reasonCode,
		Reason:     firstNonEmpty(event.Reason, reason),
		OccurredAt: event.OccurredAt,
	}
	if learning := profile.Learning; learning != nil {
		if learning.EmitFinality {
			denied.Finality = denialFinality(reasonCode)
		}
		if learning.EmitCounterfactual {
			denied.Counterfactual = denialCounterfactualFor(profile, event, reasonCode)
		}
	}
	return denied
}
