package provision

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// Precheck applies the rules of a plan that read the organization's applied
// plan (applied is nil when it has none), for the requester that proposed it.
// It is pure. Propose runs it so that an approver is never asked for a plan that
// cannot apply, and Apply runs it again on the row it has locked, which is the
// authoritative check. A refusal's reason is INSUFFICIENT_PRIVILEGE for a
// narrowing plan from a principal that is not the organization's provisioner,
// and PRECONDITION_FAILED otherwise.
//
//   - A narrowing plan (helm.authority.narrow.v1) needs no approval, so it is
//     accepted only from the organization's provisioner, the principal that
//     requested the plan applied now, and it lists only nodes and principals
//     that plan has.
//   - A plan applies to the digest it names: base_plan_digest is the applied
//     plan's, or empty when there is none. A plan whose digest is the applied one
//     changes nothing and passes, whatever its base.
//   - A plan disables only principals the applied plan lists, never its own
//     requester, and a narrowing plan never a human: a disabled principal is
//     never re-enabled, so one plan cannot lock out another organization's
//     principals or a person.
func Precheck(c *Compiled, applied *Applied, requester string) *adapters.Refusal {
	plan := c.Plan
	narrow := plan.Schema == effectargs.AuthorityNarrow
	if narrow {
		switch {
		case applied == nil:
			return adapters.Refuse(contracts.ReasonPreconditionFailed,
				"%s has no applied plan: a narrowing plan narrows the plan applied now", plan.OrgRef)
		case requester != applied.Provisioner:
			return adapters.Refuse(contracts.ReasonInsufficientPrivilege,
				"a narrowing plan needs no approval and is accepted only from the organization's provisioner")
		}
	}
	if applied != nil && applied.Digest == plan.Digest {
		return nil
	}
	base := ""
	if applied != nil {
		base = applied.Digest
	}
	if plan.BaseDigest != base {
		return adapters.Refuse(contracts.ReasonPreconditionFailed,
			"base_plan_digest %q is not the digest of the plan applied now (%q)", plan.BaseDigest, base)
	}
	for _, id := range plan.Disable {
		if id == requester {
			return adapters.Refuse(contracts.ReasonPreconditionFailed, "a plan does not disable its own requester %q", id)
		}
		var listed AppliedPrincipal
		ok := false
		if applied != nil {
			listed, ok = applied.principal(id)
		}
		if !ok {
			return adapters.Refuse(contracts.ReasonPreconditionFailed,
				"%q is not a principal the applied plan lists, so this plan cannot disable it", id)
		}
		if narrow && listed.Kind == "human" {
			return adapters.Refuse(contracts.ReasonPreconditionFailed,
				"a narrowing plan does not disable a human (%q): that needs an approval", id)
		}
	}
	if narrow {
		for _, m := range plan.Mandates {
			if _, ok := applied.node(m.Node); !ok {
				return adapters.Refuse(contracts.ReasonPreconditionFailed,
					"node %q is not in the applied plan: a narrowing plan adds none", m.Node)
			}
		}
		for _, p := range plan.Principals {
			if _, ok := applied.principal(p.ID); !ok {
				return adapters.Refuse(contracts.ReasonPreconditionFailed,
					"principal %q is not one the applied plan lists: a narrowing plan registers none", p.ID)
			}
		}
	}
	return nil
}
