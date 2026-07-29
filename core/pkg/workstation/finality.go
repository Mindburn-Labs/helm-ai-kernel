package workstation

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

// Denial finality and counterfactuals are derived here, from the reason code
// that fired. The public annotation entry point re-evaluates the event before
// it writes either field, and the tables below decide what may be said about
// that result. That is the whole point — a denial that teaches has to teach
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

// denialFinality returns the finality for an evaluated workstation deny reason
// code. Unknown codes return "" — a denial HELM cannot classify says nothing
// about itself rather than guessing.
func denialFinality(reasonCode string) contracts.DenialFinality {
	return denialCatalog[reasonCode].finality
}

// DenialFinality classifies a workstation denial code for compatibility with
// downstream consumers. It is read-only: receipt learning fields must still
// be produced through AnnotateDenial, which independently evaluates the event.
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

// AnnotateDenial fills the learning fields on a denied effect, subject to the
// profile opting in. Both switches default off, and a disabled field is absent
// rather than empty, so receipts from profiles that never opted in stay
// byte-identical.
//
// AnnotateDenial independently evaluates event and requires the receipt identity
// and recorded code to agree with that evaluation. A caller-declared reason code
// therefore cannot steer the learning fields on another receipt — see normalizeEvents.
func AnnotateDenial(denied *contracts.AgentDeniedEffect, profile contracts.WorkstationPolicyProfile, event ToolEvent) {
	if denied == nil {
		return
	}
	// A receipt can be reused across policy evaluations. Clear prior disclosure
	// before any opt-out or mismatch return so stale learning cannot survive.
	denied.Finality = ""
	denied.Counterfactual = nil
	learning := profile.Learning
	if learning == nil {
		return
	}
	verdict, reasonCode, _ := EvaluateEvent(profile, event)
	if verdict != contracts.WorkstationVerdictDeny ||
		denied.EffectID != event.EventID ||
		denied.EffectType != event.EffectType ||
		denied.ToolID != event.ToolID ||
		denied.Action != event.Action ||
		!denied.OccurredAt.Equal(event.OccurredAt) ||
		denied.ReasonCode != reasonCode {
		return
	}
	if learning.EmitFinality {
		denied.Finality = denialFinality(reasonCode)
	}
	if learning.EmitCounterfactual {
		denied.Counterfactual = denialCounterfactualFor(profile, event, reasonCode)
	}
}
