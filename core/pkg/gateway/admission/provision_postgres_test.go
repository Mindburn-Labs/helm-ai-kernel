package admission

// The gateway's own authority effects (contract 5, docs/architecture/
// gateway-provisioning-api.md) through admission, against real PostgreSQL 16
// (listed in scripts/ci/postgres-proofs.txt): who may propose a plan, what
// Propose refuses before an approver is asked, the narrowing plan's path from
// Propose through Dispatch to its read-back, and what a stop covers. The
// adapter's own transaction proofs are in adapters/provision.
//
// quantum_posture: computes SHA-256 digests to compare with stored ones;
// signs nothing.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

const (
	planOrg     = "org:acme"
	planTeam    = "team:acme"
	provisioner = "svc:helm-org"
)

// organization is the provisioner, the organization's service principal,
// carried by the Control Plane runner.
var organization = Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: provisioner, ActorID: actor}

type planFixture struct {
	*fixture
	svc     *Service
	adapter *provision.Adapter
}

// newPlanFixture is the admission fixture with the provision adapter
// configured, a provisioner and another service principal in both tenants.
func newPlanFixture(t *testing.T) *planFixture {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()
	for _, tenant := range []string{tenantA, tenantB} {
		must(t, f.rows.CreatePrincipal(ctx, tenant, provisioner, authorityrows.PrincipalService))
		must(t, f.rows.CreatePrincipal(ctx, tenant, "svc:other", authorityrows.PrincipalService))
	}
	adapter, err := provision.New(f.runtime)
	must(t, err)
	svc, err := New(f.runtime, Config{Adapters: []adapters.Adapter{adapter}})
	must(t, err)
	return &planFixture{fixture: f, svc: svc, adapter: adapter}
}

// plan renders a plan for planOrg with a team below it and a daily budget on
// each; edit adjusts the document before it is encoded.
func (f *planFixture) plan(schema, base, version string, edit func(map[string]any)) []byte {
	f.t.Helper()
	doc := map[string]any{
		"schema": schema, "org_ref": planOrg, "version_ref": version, "stage": "constrained-live", "base_plan_digest": base,
		"valid_from": f.now.Add(-time.Minute).UTC().Format(time.RFC3339), "valid_until": f.now.Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"effect_types": []any{map[string]any{"effect_type": effectargs.GitHubRepositoryGet, "risk_class": "low"}},
		"principals":   []any{map[string]any{"id": planOrg, "kind": "service"}, map[string]any{"id": planTeam, "kind": "service"}},
		"mandates": []any{
			map[string]any{"node": planOrg, "holder": planOrg, "parent": nil,
				"terms": map[string]any{"effect_types": []string{effectargs.GitHubRepositoryGet}, "targets": nil}},
			map[string]any{"node": planTeam, "holder": planTeam, "parent": planOrg,
				"terms": map[string]any{"effect_types": []string{effectargs.GitHubRepositoryGet}, "targets": []string{repo}}},
		},
		"limits": []any{
			map[string]any{"node": planOrg, "unit": "usd_micros", "measure": "sum", "window": "day", "span": 1, "value": 100},
			map[string]any{"node": planTeam, "unit": "usd_micros", "measure": "sum", "window": "day", "span": 1, "value": 80},
		},
	}
	if edit != nil {
		edit(doc)
	}
	raw, err := json.Marshal(doc)
	must(f.t, err)
	return raw
}

func planDigest(t *testing.T, schema string, raw []byte) string {
	t.Helper()
	plan, err := effectargs.ParsePlan(schema, raw)
	must(t, err)
	return plan.Digest
}

func planProposal(key, schema string, raw []byte) ProposeInput {
	return ProposeInput{IdempotencyKey: key, EffectType: schema, Target: planOrg, Arguments: raw}
}

// applyBase applies a provision plan for tenant through the adapter, after
// recording the attempt and the distinct human's approval that the gateway
// commits before it invokes one. Approve of a widening plan needs a step-up
// assertion, which its own proofs cover, so the approval row is written here.
func (f *planFixture) applyBase(tenant string, raw []byte) {
	f.t.Helper()
	ctx := context.Background()
	attemptID := uuid.NewString()
	digest := sha256.Sum256(raw)
	f.ownerTx(tenant, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO authority_effect_attempts
			(tenant_id, attempt_id, workspace_id, idempotency_key, request_digest, requester_principal_id,
			 effect_type, target, target_digest, argument_digest, state)
			VALUES ($1, $2::uuid, $3, $2::text, $4, $5, $6, $7, $4, $4, 'DISPATCHING')`,
			tenant, attemptID, workspace, digest[:], provisioner, effectargs.AuthorityProvision, planOrg); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO authority_approvals (tenant_id, attempt_id, approver_principal_id, decision, approval_digest)
			VALUES ($1, $2, 'human-b', 'APPROVED', $3)`, tenant, attemptID, digest[:])
		return err
	})
	result := f.adapter.Dispatch(ctx, nil, adapters.Effect{EffectType: effectargs.AuthorityProvision, Target: planOrg, Arguments: raw,
		Invocation: &adapters.Invocation{TenantID: tenant, AttemptID: attemptID, RequesterPrincipalID: provisioner}}, digest[:])
	if result.Status != adapters.DispatchSent {
		f.t.Fatalf("the base plan did not apply: %+v", result)
	}
}

func (f *planFixture) provisioning(tenant string) *provision.Provisioning {
	f.t.Helper()
	p, err := provision.GetProvisioning(context.Background(), f.adapter.Store(), tenant, planOrg)
	must(f.t, err)
	return p
}

// attempts counts the tenant's authority-plan attempts. The owner role bypasses
// row security, so the query names the tenant itself.
func (f *planFixture) attempts(tenant string) int {
	return f.count(tenant, `SELECT count(*) FROM authority_effect_attempts WHERE tenant_id = $1 AND effect_type LIKE 'helm.authority.%'`, tenant)
}

// limits sets the two budgets of a plan document: the organization's and the
// team's below it (a child's limit may not exceed its ancestor's).
func limits(org, team int64) func(map[string]any) {
	return func(d map[string]any) {
		d["limits"].([]any)[0].(map[string]any)["value"] = org
		d["limits"].([]any)[1].(map[string]any)["value"] = team
	}
}

// limitRow reads the value and the version of a node's usd_micros limit.
func (f *planFixture) limitRow(tenant string, p *provision.Provisioning, node string) (value, version int64) {
	f.t.Helper()
	for _, n := range p.Nodes {
		if n.Node != node {
			continue
		}
		id, err := uuid.Parse(n.MandateID)
		must(f.t, err)
		f.ownerTx(tenant, func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT limit_value, version FROM authority_limits WHERE tenant_id = $1 AND mandate_id = $2 AND unit = 'usd_micros'`,
				tenant, id).Scan(&value, &version)
		})
		return value, version
	}
	f.t.Fatalf("the applied plan has no node %s", node)
	return 0, 0
}

func (f *planFixture) limitValue(tenant string, p *provision.Provisioning, node string) int64 {
	f.t.Helper()
	value, _ := f.limitRow(tenant, p, node)
	return value
}

// A plan is proposed by a registered service principal, never by a person or
// an agent, and needs no proposer mandate: a provision plan is ESCALATED for a
// distinct human, whose approval needs a step-up assertion until that
// assertion exists.
func TestPostgresProvisionPlanIsEscalatedForADistinctHuman(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	raw := f.plan(effectargs.AuthorityProvision, "", "v1", nil)

	a, existing, err := f.svc.Propose(ctx, organization, planProposal("prov-1", effectargs.AuthorityProvision, raw))
	must(t, err)
	wantState(t, "a provision plan", a, "ESCALATED", contracts.ReasonApprovalRequired)
	if existing || a.MandateID != "" || a.RiskClass != "irreversible" || a.Permit != nil || len(a.Exposures) != 0 || len(a.ApprovalDigest) != 32 ||
		a.EffectType != effectargs.AuthorityProvision || a.Target != planOrg {
		t.Fatalf("a provision plan = %+v", a)
	}
	// The approver reads the exact plan bytes the approval digest binds.
	content, err := f.svc.GetContent(ctx, approverB, a.ID)
	must(t, err)
	if string(content) != string(raw) {
		t.Fatal("the escalated content is not the plan as proposed")
	}
	// A replay returns the stored attempt.
	again, existing, err := f.svc.Propose(ctx, organization, planProposal("prov-1", effectargs.AuthorityProvision, raw))
	must(t, err)
	if !existing || again.ID != a.ID {
		t.Fatalf("a replayed plan = %+v existing=%v", again, existing)
	}

	// Fails closed: a distinct human cannot approve a widening plan without
	// step-up, and the requester cannot approve its own.
	_, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(a, ""))
	wantRefusal(t, "a widening plan approved without step-up", err, CodePermissionDenied, contracts.ReasonStepUpRequired)
	_, _, err = f.svc.Approve(ctx, organization, decideToken("helm.gateway.decide"), approval(a, ""))
	wantRefusal(t, "the requester's own approval", err, CodePermissionDenied, contracts.ReasonApproverNotDistinct)
	got, err := f.svc.Get(ctx, human, a.ID)
	must(t, err)
	if got.State != "ESCALATED" || got.Approval != nil {
		t.Fatalf("a refused approval changed the attempt: %+v", got)
	}
	if _, err := provision.GetProvisioning(ctx, f.adapter.Store(), tenantA, planOrg); err == nil {
		t.Fatal("an unapproved plan was applied")
	}
	// A rejection needs no step-up.
	rejected, _, err := f.svc.Reject(ctx, approverB, decideToken("helm.gateway.decide"), DecideInput{AttemptID: a.ID, ApprovalDigest: a.ApprovalDigest, Reason: "not this plan"})
	must(t, err)
	wantState(t, "a rejected plan", rejected, "REJECTED", contracts.ReasonApprovalRejected)
}

func TestPostgresPlanRequesterMustBeARegisteredServicePrincipal(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	raw := f.plan(effectargs.AuthorityProvision, "", "v1", nil)
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE authority_principals SET status = 'disabled' WHERE tenant_id = $1 AND principal_id = 'svc:other'`, tenantA)
		return err
	})
	for name, test := range map[string]struct {
		caller Caller
		state  string
		reason contracts.ReasonCode
	}{
		"a human through the workload": {Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-a", ActorID: actor}, "DENIED", contracts.ReasonInsufficientPrivilege},
		"an agent":                     {Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a", ActorID: actor}, "DENIED", contracts.ReasonInsufficientPrivilege},
		"an unregistered principal":    {Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "svc:ghost", ActorID: actor}, "DENIED", contracts.ReasonPrincipalInactive},
		"a disabled service principal": {Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "svc:other", ActorID: actor}, "DENIED", contracts.ReasonPrincipalInactive},
	} {
		a, _, err := f.svc.Propose(ctx, test.caller, planProposal("who-"+test.caller.PrincipalID, effectargs.AuthorityProvision, raw))
		must(t, err)
		if a.State != test.state || a.ReasonCode != string(test.reason) || a.Permit != nil {
			t.Errorf("%s: attempt is %s %q, want %s %q", name, a.State, a.ReasonCode, test.state, test.reason)
		}
	}
	// A person proposing directly, without the workload, is refused outright.
	_, _, err := f.svc.Propose(ctx, Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-a"},
		planProposal("direct", effectargs.AuthorityProvision, raw))
	wantRefusal(t, "a human proposing directly", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
}

// Propose refuses what cannot apply before any approver is asked: the refusal
// leaves no attempt.
func TestPostgresPlanProposalsAreRefusedBeforeAnApproverIsAsked(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	base := f.plan(effectargs.AuthorityProvision, "", "v1", nil)
	f.applyBase(tenantA, base)
	applied := planDigest(t, effectargs.AuthorityProvision, base)
	if f.provisioning(tenantA).Digest != applied {
		t.Fatal("the applied digest is not the plan's")
	}
	before := f.attempts(tenantA)

	narrow := func(edit func(map[string]any)) []byte { return f.plan(effectargs.AuthorityNarrow, applied, "v2", edit) }
	other := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "svc:other", ActorID: actor}
	for name, test := range map[string]struct {
		caller Caller
		in     ProposeInput
		code   Code
		reason contracts.ReasonCode
	}{
		"a narrowing plan from another service principal": {other,
			planProposal("n1", effectargs.AuthorityNarrow, narrow(nil)), CodePermissionDenied, contracts.ReasonInsufficientPrivilege},
		"a provision plan on a stale base": {organization,
			planProposal("p1", effectargs.AuthorityProvision, f.plan(effectargs.AuthorityProvision, "0000000000000000000000000000000000000000000000000000000000000000", "v2", nil)),
			CodeFailedPrecondition, contracts.ReasonPreconditionFailed},
		"a provision plan that forgets the applied base": {organization,
			planProposal("p2", effectargs.AuthorityProvision, f.plan(effectargs.AuthorityProvision, "", "v2", nil)),
			CodeFailedPrecondition, contracts.ReasonPreconditionFailed},
		"a narrowing plan that adds a node": {organization,
			planProposal("n2", effectargs.AuthorityNarrow, narrow(func(d map[string]any) {
				d["principals"] = append(d["principals"].([]any), map[string]any{"id": "team:new", "kind": "service"})
				d["mandates"] = append(d["mandates"].([]any), map[string]any{"node": "team:new", "holder": "team:new", "parent": planOrg,
					"terms": map[string]any{"effect_types": []string{effectargs.GitHubRepositoryGet}, "targets": []string{repo}}})
			})), CodeFailedPrecondition, contracts.ReasonPreconditionFailed},
		"a plan that disables its own requester": {organization,
			planProposal("p3", effectargs.AuthorityProvision, f.plan(effectargs.AuthorityProvision, applied, "v2", func(d map[string]any) {
				d["disable_principals"] = []any{provisioner}
			})), CodeFailedPrecondition, contracts.ReasonPreconditionFailed},
		"a plan that names another effect type in a mandate": {organization,
			planProposal("p4", effectargs.AuthorityProvision, f.plan(effectargs.AuthorityProvision, applied, "v2", func(d map[string]any) {
				d["mandates"].([]any)[0].(map[string]any)["terms"] = map[string]any{"effect_types": []string{"helm.authority.provision.v1"}, "targets": nil}
			})), CodeInvalidArgument, contracts.ReasonSchemaViolation},
		"a plan with an unknown field": {organization,
			planProposal("p5", effectargs.AuthorityProvision, f.plan(effectargs.AuthorityProvision, applied, "v2", func(d map[string]any) { d["surprise"] = true })),
			CodeInvalidArgument, contracts.ReasonSchemaViolation},
		"a plan whose schema is not its effect type": {organization,
			planProposal("p6", effectargs.AuthorityProvision, f.plan(effectargs.AuthorityNarrow, applied, "v2", nil)),
			CodeInvalidArgument, contracts.ReasonSchemaViolation},
		"a plan for another organization": {organization,
			ProposeInput{IdempotencyKey: "p7", EffectType: effectargs.AuthorityProvision, Target: "org:other", Arguments: f.plan(effectargs.AuthorityProvision, applied, "v2", nil)},
			CodeInvalidArgument, contracts.ReasonSchemaViolation},
	} {
		_, _, err := f.svc.Propose(ctx, test.caller, test.in)
		if err == nil {
			t.Errorf("%s: proposed", name)
			continue
		}
		var refusal *Error
		if !errors.As(err, &refusal) || refusal.Code != test.code || refusal.Reason != test.reason {
			t.Errorf("%s: err = %v, want code %d reason %q", name, err, test.code, test.reason)
		}
	}
	if n := f.attempts(tenantA); n != before {
		t.Fatalf("refused plans left %d attempts", n-before)
	}
	// A narrowing plan for a tenant with nothing applied has nothing to narrow.
	_, _, err := f.svc.Propose(ctx, Caller{TenantID: tenantB, WorkspaceID: workspace, PrincipalID: provisioner, ActorID: actor},
		planProposal("n3", effectargs.AuthorityNarrow, narrow(nil)))
	wantRefusal(t, "a narrowing plan with nothing applied", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
	if f.attempts(tenantB) != 0 {
		t.Fatal("a refused narrowing plan left an attempt")
	}
}

// helm.authority.narrow.v1 needs no approval: it is admitted at once, from the
// provisioner alone, and applied by Dispatch and read back by digest.
func TestPostgresNarrowPlanIsAdmittedDispatchedAndObserved(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	base := f.plan(effectargs.AuthorityProvision, "", "v1", nil)
	f.applyBase(tenantA, base)
	first := f.provisioning(tenantA)
	limitBefore, versionBefore := f.limitRow(tenantA, first, planOrg)
	if first.Revision != 1 || first.Provisioner != provisioner || limitBefore != 100 {
		t.Fatalf("base = %+v", first)
	}

	lowered := f.plan(effectargs.AuthorityNarrow, first.Digest, "v2", limits(40, 30))
	a, existing, err := f.svc.Propose(ctx, organization, planProposal("narrow-1", effectargs.AuthorityNarrow, lowered))
	must(t, err)
	wantState(t, "a narrowing plan", a, "ADMITTED", "")
	if existing || a.RiskClass != "medium" || a.MandateID != "" || a.Permit == nil || a.Approval != nil || len(a.ApprovalDigest) != 0 {
		t.Fatalf("a narrowing plan = %+v", a)
	}

	// Only the workload the plan was proposed through dispatches it.
	_, _, err = f.svc.Dispatch(ctx, Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "svc:other"}, a.ID)
	wantRefusal(t, "another workload's dispatch", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)

	dispatched, existing, err := f.svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "a narrowing plan after dispatch", dispatched, "OBSERVED", "SUCCEEDED", "")
	if existing || dispatched.LatestObservation == nil || dispatched.LatestObservation.Source != "gateway.authority.readback" ||
		dispatched.LatestObservation.TrustClass != "gateway_ledger" || dispatched.LatestObservation.ResultRef != "" {
		t.Fatalf("the read-back = %+v", dispatched.LatestObservation)
	}
	second := f.provisioning(tenantA)
	if second.Digest != planDigest(t, effectargs.AuthorityNarrow, lowered) || second.Revision != 2 || second.AttemptID != a.ID ||
		second.Provisioner != provisioner || f.limitValue(tenantA, second, planOrg) != 40 || f.limitValue(tenantA, second, planTeam) != 30 {
		t.Fatalf("after the narrowing = %+v", second)
	}
	// Narrowed in place: every node keeps its mandate.
	for i, n := range second.Nodes {
		if n.MandateID != first.Nodes[i].MandateID || n.HolderID != first.Nodes[i].HolderID {
			t.Errorf("node %s changed its mandate: %+v -> %+v", n.Node, first.Nodes[i], n)
		}
	}
	// A lowered limit bumps the limit's own version, which a permit issued
	// before it carries, so the claim of an earlier permit sees the change.
	if _, versionAfter := f.limitRow(tenantA, second, planOrg); versionAfter <= versionBefore {
		t.Errorf("the org limit's version did not move: %d -> %d", versionBefore, versionAfter)
	}

	// Nothing is dispatched or observed twice.
	again, existing, err := f.svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	if !existing || again.Version != dispatched.Version {
		t.Fatalf("a second dispatch = %+v existing=%v", again, existing)
	}
	observed, existing, err := f.svc.Observe(ctx, workload, a.ID)
	must(t, err)
	if !existing || observed.State != "OBSERVED" || f.provisioning(tenantA).Revision != 2 {
		t.Fatalf("Observe = %+v existing=%v", observed, existing)
	}
	// A replayed proposal returns the stored attempt.
	replay, existing, err := f.svc.Propose(ctx, organization, planProposal("narrow-1", effectargs.AuthorityNarrow, lowered))
	must(t, err)
	if !existing || replay.ID != a.ID || replay.State != "OBSERVED" {
		t.Fatalf("a replayed narrowing plan = %+v existing=%v", replay, existing)
	}
}

// A narrowing plan whose change would widen is admitted (Propose cannot read
// the mandates) and refused by the adapter, whole: nothing applies.
func TestPostgresNarrowPlanThatWidensChangesNothing(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	f.applyBase(tenantA, f.plan(effectargs.AuthorityProvision, "", "v1", nil))
	first := f.provisioning(tenantA)

	raised := f.plan(effectargs.AuthorityNarrow, first.Digest, "v2", limits(200, 150))
	a, _, err := f.svc.Propose(ctx, organization, planProposal("widen-1", effectargs.AuthorityNarrow, raised))
	must(t, err)
	wantState(t, "a narrowing plan that widens", a, "ADMITTED", "")
	dispatched, _, err := f.svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	if dispatched.State != "OBSERVED" || dispatched.Outcome != "FAILED" ||
		(dispatched.ReasonCode != string(contracts.ReasonPreconditionFailed) && dispatched.ReasonCode != string(contracts.ReasonDelegationScopeViolation)) {
		t.Fatalf("a narrowing plan that widens = %s(%s) %q", dispatched.State, dispatched.Outcome, dispatched.ReasonCode)
	}
	after := f.provisioning(tenantA)
	if after.Digest != first.Digest || after.Revision != 1 || f.limitValue(tenantA, after, planOrg) != 100 || f.limitValue(tenantA, after, planTeam) != 80 {
		t.Fatalf("a refused narrowing plan changed the provisioning: %+v", after)
	}
}

// Two plans proposed on the same base: the first to dispatch applies, and the
// second does not, whole.
func TestPostgresPlanOnAMovedBaseIsNotApplied(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	f.applyBase(tenantA, f.plan(effectargs.AuthorityProvision, "", "v1", nil))
	base := f.provisioning(tenantA).Digest
	one := f.plan(effectargs.AuthorityNarrow, base, "v2", limits(70, 60))
	two := f.plan(effectargs.AuthorityNarrow, base, "v3", limits(60, 50))
	a := f.propose2(organization, planProposal("moved-1", effectargs.AuthorityNarrow, one))
	b := f.propose2(organization, planProposal("moved-2", effectargs.AuthorityNarrow, two))
	wantState(t, "the first plan", a, "ADMITTED", "")
	wantState(t, "the second plan", b, "ADMITTED", "")

	first, _, err := f.svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "the first plan", first, "OBSERVED", "SUCCEEDED", "")
	second, _, err := f.svc.Dispatch(ctx, workload, b.ID)
	must(t, err)
	if second.Outcome == "SUCCEEDED" {
		t.Fatalf("the second plan on a moved base applied: %+v", second)
	}
	after := f.provisioning(tenantA)
	if after.Digest != planDigest(t, effectargs.AuthorityNarrow, one) || after.Revision != 2 || f.limitValue(tenantA, after, planOrg) != 70 {
		t.Fatalf("the provisioning after a moved base = %+v", after)
	}
}

func (f *planFixture) propose2(caller Caller, in ProposeInput) Attempt {
	f.t.Helper()
	a, _, err := f.svc.Propose(context.Background(), caller, in)
	must(f.t, err)
	return a
}

// A tenant-wide stop denies a provision plan but does not block narrowing,
// which is what an operator needs during an incident; a stop on the requester
// does block it. (A plan effect has no effect-type row, so none can be stopped
// by effect type.)
func TestPostgresStopsAndAuthorityPlans(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	f.applyBase(tenantA, f.plan(effectargs.AuthorityProvision, "", "v1", nil))
	base := f.provisioning(tenantA).Digest
	narrow := func(key string, value int64) ProposeInput {
		return planProposal(key, effectargs.AuthorityNarrow, f.plan(effectargs.AuthorityNarrow, base, key, limits(value, value-10)))
	}
	provisionIn := func(key string) ProposeInput {
		return planProposal(key, effectargs.AuthorityProvision, f.plan(effectargs.AuthorityProvision, base, key, nil))
	}

	stop, err := f.rows.Stop(ctx, tenantA, authorityrows.StopSpec{Scope: authorityrows.Scope{Kind: authorityrows.ScopeTenant, Key: tenantA},
		Reason: "incident", IssuedBy: "human-c"})
	must(t, err)
	wantState(t, "a provision plan under a tenant stop", f.propose2(organization, provisionIn("under-stop")), "DENIED", contracts.ReasonEmergencyStopFenced)
	wantState(t, "a narrowing plan under a tenant stop", f.propose2(organization, narrow("under-stop-n", 50)), "ADMITTED", "")
	f.exec(tenantA, `UPDATE authority_stops SET expires_at = now() + interval '1 millisecond' WHERE stop_id = $1`, stop.ID)
	time.Sleep(10 * time.Millisecond)

	_, err = f.rows.Stop(ctx, tenantA, authorityrows.StopSpec{Scope: authorityrows.Scope{Kind: authorityrows.ScopePrincipal, Key: provisioner},
		Reason: "requester stopped", IssuedBy: "human-c"})
	must(t, err)
	wantState(t, "a narrowing plan from a stopped requester", f.propose2(organization, narrow("stopped-n", 45)), "DENIED", contracts.ReasonEmergencyStopFenced)
}
