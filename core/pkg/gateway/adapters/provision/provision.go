// Package provision is the effect adapter of the gateway's own authority
// effects (contract 5, docs/architecture/gateway-provisioning-api.md):
// helm.authority.provision.v1, which applies an organization's whole authority
// plan behind a distinct human's approval, and helm.authority.narrow.v1, which
// applies a plan that only narrows the one applied and needs none.
//
// Unlike a provider adapter it acts on the gateway's own database. Dispatch
// applies the plan in one transaction bound to the token's tenant under forced
// row security, through authorityrows.Tx, and writes the organization's row in
// authority_provisions in that transaction; Observe reads that row back and
// compares its digest with the plan's. It holds no credential and reads no
// provider.
//
// Admission treats these two effect types differently from every other: they
// need no proposer mandate, and Propose calls Check and Precheck (both pure) so
// that an approver is never asked for a plan that cannot apply.
//
// The package imports no legacy kernel runtime (guardian, proxy, mcp,
// executor), like the rest of the gateway (Zone C).
package provision

// quantum_posture: a plan is identified by its SHA-256 digest; nothing here
// signs or verifies, and no post-quantum claim is made.

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

// Where this adapter's read-back comes from.
const (
	observationSource = "gateway.authority.readback"
	trustClass        = "gateway_ledger"
)

// schemaOf is the published argument schema of one of this adapter's effect
// types. The gateway's own authority effects are never grantable: no mandate
// names them.
func schemaOf(effectType string) []byte {
	body, _ := effectargs.ArgumentSchema(effectType)
	return body
}

// targetForm is the form of both effects' target.
const targetForm = "org:{org_id}"

var declarations = []adapters.Declaration{
	{
		EffectType: effectargs.AuthorityProvision,
		RiskClass:  adapters.RiskIrreversible,
		Idempotent: adapters.IdempotentConditional,
		Observable: adapters.ObservableYes,
		Reversible: adapters.ReversibleNo,
		Mediation:  adapters.MediationEnforced,
		Notes: "Applies an organization's whole authority plan in one transaction, by compare-and-set on the digest " +
			"of the plan applied now; the plan applied again changes nothing. Needs a distinct human's approval with step-up. " +
			"Observe reads the applied digest back.",
		TargetForm:     targetForm,
		Description:    "Applies one organization's whole authority plan: its effect types, principals, mandates and limits.",
		ArgumentSchema: schemaOf(effectargs.AuthorityProvision),
	},
	{
		EffectType: effectargs.AuthorityNarrow,
		RiskClass:  adapters.RiskMedium,
		Idempotent: adapters.IdempotentConditional,
		Observable: adapters.ObservableYes,
		Reversible: adapters.ReversibleNo,
		Mediation:  adapters.MediationEnforced,
		Notes: "Applies a plan that only narrows the one applied, and needs no approval; it is accepted only from the " +
			"organization's provisioner. Only a provision plan, which needs approval, widens again. Observe reads the applied digest back.",
		TargetForm:     targetForm,
		Description:    "Applies a plan that only narrows the organization's applied plan.",
		ArgumentSchema: schemaOf(effectargs.AuthorityNarrow),
	},
}

// Adapter applies authority plans to the gateway's own rows.
type Adapter struct {
	rows *authorityrows.Store
	now  func() time.Time
}

// New returns the adapter over db, whose gateway schema is migrated.
func New(db *sql.DB) (*Adapter, error) {
	rows, err := authorityrows.New(db)
	if err != nil {
		return nil, err
	}
	return &Adapter{rows: rows, now: time.Now}, nil
}

// Store is the authority rows store the adapter writes through, which the
// provisioning reads share.
func (a *Adapter) Store() *authorityrows.Store { return a.rows }

// DeclaredRisk is the risk class of one of this adapter's effect types.
func DeclaredRisk(effectType string) (adapters.RiskClass, bool) {
	for _, d := range declarations {
		if d.EffectType == effectType {
			return d.RiskClass, true
		}
	}
	return "", false
}

// Declarations implements adapters.Adapter.
func (a *Adapter) Declarations() []adapters.Declaration {
	return append([]adapters.Declaration(nil), declarations...)
}

func declaration(effectType string) (adapters.Declaration, bool) {
	for _, d := range declarations {
		if d.EffectType == effectType {
			return d, true
		}
	}
	return adapters.Declaration{}, false
}

// Prepare implements adapters.Adapter. It parses and compiles the plan, which
// reads nothing: the rules that read the applied plan run in Precheck.
func (a *Adapter) Prepare(_ context.Context, _ adapters.TokenSource, effect adapters.Effect) (*adapters.Preparation, error) {
	decl, ok := declaration(effect.EffectType)
	if !ok {
		return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "effect type %q is not an authority plan effect", effect.EffectType)
	}
	c, err := Check(effect.EffectType, effect.Arguments)
	if err != nil {
		return nil, err
	}
	if effect.Target != c.Plan.OrgRef {
		return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "target must be the plan's org_ref %q", c.Plan.OrgRef)
	}
	return &adapters.Preparation{Declaration: decl, Target: effect.Target}, nil
}

// Dispatch implements adapters.Adapter: it applies the plan. A refusal of the
// plan is NOT_SENT with its reason: nothing was applied. A failure of the
// database is INDEFINITE, whichever statement failed: the attempt is UNKNOWN,
// and Observe finds the plan applied or not by its digest.
func (a *Adapter) Dispatch(ctx context.Context, _ adapters.TokenSource, effect adapters.Effect, permitArgumentDigest []byte) adapters.DispatchResult {
	if r := adapters.CheckPermitDigest(effect.Arguments, permitArgumentDigest); r != nil {
		return notSent(r)
	}
	inv := effect.Invocation
	if inv == nil || inv.TenantID == "" || inv.AttemptID == "" || inv.RequesterPrincipalID == "" {
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "the dispatch carries no invocation"))
	}
	c, err := Check(effect.EffectType, effect.Arguments)
	if err != nil {
		r, ok := refusalOf(err)
		if !ok {
			r = adapters.Refuse(contracts.ReasonSchemaViolation, "%v", err)
		}
		return notSent(r)
	}
	if effect.Target != c.Plan.OrgRef {
		return notSent(adapters.Refuse(contracts.ReasonSchemaViolation, "target must be the plan's org_ref %q", c.Plan.OrgRef))
	}
	err = a.rows.InTenant(ctx, inv.TenantID, func(tx *authorityrows.Tx) error {
		approver := ""
		if c.Plan.Schema == effectargs.AuthorityProvision {
			var found sql.NullString
			err := tx.SQL().QueryRowContext(ctx, `SELECT approver_principal_id FROM authority_approvals
				WHERE tenant_id = $1 AND attempt_id = $2 AND decision = 'APPROVED'`, inv.TenantID, inv.AttemptID).Scan(&found)
			if errors.Is(err, sql.ErrNoRows) {
				return adapters.Refuse(contracts.ReasonPreconditionFailed, "the attempt has no recorded approval")
			}
			if err != nil {
				return err
			}
			approver = found.String
		}
		return a.apply(ctx, tx, applyInput{compiled: c, requester: inv.RequesterPrincipalID, approver: approver, attemptID: inv.AttemptID})
	})
	switch {
	case err == nil:
		return adapters.DispatchResult{Status: adapters.DispatchSent}
	default:
		if r, ok := toRefusal(err); ok {
			return notSent(r)
		}
		return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Detail: "the database failed while the plan was applied"}
	}
}

func notSent(r *adapters.Refusal) adapters.DispatchResult {
	return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: r.Reason, Detail: r.Detail}
}

// Observe implements adapters.Adapter: the plan is applied when the
// organization's applied digest is the plan's. The read-back finds a plan by its
// digest in the current provisioning, so a plan applied and then superseded
// before it ran reads as not applied (a FAILED by absence, which the gateway
// takes as final only after the dispatch fence).
func (a *Adapter) Observe(ctx context.Context, _ adapters.TokenSource, effect adapters.Effect) adapters.ObserveResult {
	unknown := func(format string, args ...any) adapters.ObserveResult {
		r := adapters.Refuse(contracts.ReasonPreconditionFailed, format, args...)
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: r.Reason, Detail: r.Detail}
	}
	plan, err := effectargs.ParsePlan(effect.EffectType, effect.Arguments)
	if err != nil {
		return unknown("the arguments are not a plan: %v", err)
	}
	if effect.Invocation == nil || effect.Invocation.TenantID == "" {
		return unknown("the read-back carries no invocation")
	}
	var applied *Applied
	err = a.rows.InTenant(ctx, effect.Invocation.TenantID, func(tx *authorityrows.Tx) error {
		var err error
		applied, err = LoadApplied(ctx, tx.SQL(), tx.TenantID(), plan.OrgRef, false)
		return err
	})
	if err != nil {
		return unknown("the provisioning could not be read")
	}
	obs := &adapters.Observation{Source: observationSource, TrustClass: trustClass, ObservedAt: a.now().UTC()}
	if applied == nil {
		obs.EvidenceDigest = (&Applied{OrgRef: plan.OrgRef}).evidence()
		return adapters.ObserveResult{Outcome: adapters.OutcomeFailed, Reason: contracts.ReasonReadbackMismatch,
			Detail: "the organization has no applied plan", Observation: obs, Absent: true}
	}
	obs.EvidenceDigest = applied.evidence()
	if applied.Digest != plan.Digest {
		return adapters.ObserveResult{Outcome: adapters.OutcomeFailed, Reason: contracts.ReasonReadbackMismatch,
			Detail: "the organization's applied plan is not this plan", Observation: obs, Absent: true}
	}
	return adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded, Observation: obs}
}
