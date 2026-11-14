package admission

// The plan stage as a ceiling (helm-tracker#334, modes L1) against real
// PostgreSQL 16 (listed in scripts/ci/postgres-proofs.txt). A plan's stage
// bounds what its mandates may grant, judged from the effect-type declarations
// the gateway holds: draft grants no write but an internal one, approval-
// required puts every granted write behind an approval, and a narrowing plan
// never raises the stage. Each rule holds at Propose, so no approver is asked,
// and again when the authority adapter applies the plan on its locked row.
// The first two tests are the mission check's probes: on main a draft plan
// granting a write escalated and applied, and svc:helm-org raised the stage
// from draft to certified-live with a narrowing plan and no approval.
//
// quantum_posture: computes SHA-256 digests to compare with stored ones;
// signs nothing.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	githubadapter "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

const (
	reasonStageCeiling = contracts.ReasonCode("STAGE_CEILING_EXCEEDED")
	reasonStageRaise   = contracts.ReasonCode("STAGE_RAISE_REQUIRES_PROVISION")
)

// newStageFixture is the plan fixture whose service also performs the GitHub
// effects, as helm-gateway serve does: github.repository.get is declared a read
// and github.branch.create_from_changes a write.
func newStageFixture(t *testing.T, extra ...adapters.Adapter) *planFixture {
	t.Helper()
	f := newPlanFixture(t)
	svc, err := New(f.runtime, Config{ReceiptSigner: testReceiptSigner,
		Adapters: append([]adapters.Adapter{f.adapter, githubadapter.New()}, extra...)})
	must(t, err)
	f.svc = svc
	return f
}

// grantPlan is a plan at stage for planOrg whose two mandates grant effect
// (registered at risk class medium); edit adjusts each mandate's terms.
func (f *planFixture) grantPlan(schema, base, version, stage, effect string, terms func(map[string]any)) []byte {
	f.t.Helper()
	return f.plan(schema, base, version, func(d map[string]any) {
		d["stage"] = stage
		d["effect_types"] = []any{map[string]any{"effect_type": effect, "risk_class": "medium"}}
		for i, m := range d["mandates"].([]any) {
			t := map[string]any{"effect_types": []string{effect}, "targets": nil}
			if i > 0 {
				t["targets"] = []string{repo}
			}
			if terms != nil {
				terms(t)
			}
			m.(map[string]any)["terms"] = t
		}
	})
}

// dispatchPlan applies a plan through the adapter as the gateway invokes it
// after the dispatch claim, with the attempt and (for a provision plan) the
// distinct human's approval recorded, and returns the adapter's answer.
func (f *planFixture) dispatchPlan(tenant, schema string, raw []byte) adapters.DispatchResult {
	f.t.Helper()
	attemptID := uuid.NewString()
	digest := sha256.Sum256(raw)
	f.ownerTx(tenant, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO authority_effect_attempts
			(tenant_id, attempt_id, workspace_id, idempotency_key, request_digest, requester_principal_id,
			 effect_type, target, target_digest, argument_digest, state)
			VALUES ($1, $2::uuid, $3, $2::text, $4, $5, $6, $7, $4, $4, 'DISPATCHING')`,
			tenant, attemptID, workspace, digest[:], provisioner, schema, planOrg); err != nil {
			return err
		}
		if schema != effectargs.AuthorityProvision {
			return nil
		}
		_, err := tx.Exec(`INSERT INTO authority_approvals (tenant_id, attempt_id, approver_principal_id, decision, approval_digest)
			VALUES ($1, $2, 'human-b', 'APPROVED', $3)`, tenant, attemptID, digest[:])
		return err
	})
	return f.adapter.Dispatch(context.Background(), nil, adapters.Effect{EffectType: schema, Target: planOrg, Arguments: raw,
		Invocation: &adapters.Invocation{TenantID: tenant, AttemptID: attemptID, RequesterPrincipalID: provisioner}}, digest[:])
}

func wantNotSent(t *testing.T, what string, r adapters.DispatchResult, reason contracts.ReasonCode) {
	t.Helper()
	if r.Status != adapters.DispatchNotSent || r.Reason != reason {
		t.Fatalf("%s: dispatch = %+v, want NOT_SENT %s", what, r, reason)
	}
}

// Mission probe 1: a draft plan granting a write. On main it escalated, was
// approved and applied, and the write it granted was admitted and sent.
func TestPostgresDraftPlanGrantingAWriteIsRefused(t *testing.T) {
	f := newStageFixture(t)
	ctx := context.Background()
	write := f.grantPlan(effectargs.AuthorityProvision, "", "v1", "draft", effectargs.GitHubBranchCreateFromChanges, nil)

	_, _, err := f.svc.Propose(ctx, organization, planProposal("draft-write", effectargs.AuthorityProvision, write))
	wantRefusal(t, "a draft plan granting a write, at Propose", err, CodeFailedPrecondition, reasonStageCeiling)
	if n := f.attempts(tenantA); n != 0 {
		t.Fatalf("a refused plan left %d attempts for an approver", n)
	}
	// Apply holds the same rule on the row it locks: an attempt admitted by a
	// gateway that did not check it applies nothing.
	wantNotSent(t, "a draft plan granting a write, at Apply", f.dispatchPlan(tenantA, effectargs.AuthorityProvision, write), reasonStageCeiling)
	if n := f.count(tenantA, `SELECT count(*) FROM authority_provisions WHERE tenant_id = $1`, tenantA); n != 0 {
		t.Fatalf("a refused draft plan was applied (%d provisionings)", n)
	}

	// Known good: the same grants at a live stage, and a draft plan of reads.
	for _, stage := range []string{"constrained-live", "certified-live"} {
		raw := f.grantPlan(effectargs.AuthorityProvision, "", "v-"+stage, stage, effectargs.GitHubBranchCreateFromChanges, nil)
		a, _, err := f.svc.Propose(ctx, organization, planProposal("live-"+stage, effectargs.AuthorityProvision, raw))
		must(t, err)
		wantState(t, stage+" grants by mandate terms", a, "ESCALATED", contracts.ReasonApprovalRequired)
	}
	reads := f.grantPlan(effectargs.AuthorityProvision, "", "v-reads", "draft", effectargs.GitHubRepositoryGet, nil)
	a, _, err := f.svc.Propose(ctx, organization, planProposal("draft-reads", effectargs.AuthorityProvision, reads))
	must(t, err)
	wantState(t, "a draft plan of reads", a, "ESCALATED", contracts.ReasonApprovalRequired)
}

// approval-required puts every granted write behind an approval: listed in
// approval_required, on a mandate with no approval threshold.
func TestPostgresApprovalRequiredPlanPutsEveryWriteBehindApproval(t *testing.T) {
	f := newStageFixture(t)
	ctx := context.Background()
	stage := "approval-required"
	cases := []struct {
		name  string
		terms func(map[string]any)
		ok    bool
	}{
		{"a write without approval", nil, false},
		{"a write behind a threshold only", func(t map[string]any) { t["approval_threshold"] = 0 }, false},
		{"a write behind approval and a threshold", func(t map[string]any) {
			t["approval_required"] = []string{effectargs.GitHubBranchCreateFromChanges}
			t["approval_threshold"] = 10
		}, false},
		{"every write behind approval", func(t map[string]any) {
			t["approval_required"] = []string{effectargs.GitHubBranchCreateFromChanges}
		}, true},
	}
	for i, c := range cases {
		raw := f.grantPlan(effectargs.AuthorityProvision, "", "v"+string(rune('a'+i)), stage, effectargs.GitHubBranchCreateFromChanges, c.terms)
		a, _, err := f.svc.Propose(ctx, organization, planProposal("ar-"+string(rune('a'+i)), effectargs.AuthorityProvision, raw))
		if !c.ok {
			wantRefusal(t, c.name, err, CodeFailedPrecondition, reasonStageCeiling)
			wantNotSent(t, c.name+", at Apply", f.dispatchPlan(tenantB, effectargs.AuthorityProvision, raw), reasonStageCeiling)
			continue
		}
		must(t, err)
		wantState(t, c.name, a, "ESCALATED", contracts.ReasonApprovalRequired)
	}
	// A read needs no approval at approval-required.
	reads := f.grantPlan(effectargs.AuthorityProvision, "", "v-reads", stage, effectargs.GitHubRepositoryGet, nil)
	a, _, err := f.svc.Propose(ctx, organization, planProposal("ar-reads", effectargs.AuthorityProvision, reads))
	must(t, err)
	wantState(t, "approval-required reads", a, "ESCALATED", contracts.ReasonApprovalRequired)
}

// Mission probe 2: svc:helm-org, the organization's provisioner, raises the
// stage from draft to certified-live with a narrowing plan. On main it was
// ADMITTED with no approval and applied at revision 2. A rung is raised only by
// a provision plan, which escalates to a distinct human.
func TestPostgresNarrowPlanCannotRaiseTheStage(t *testing.T) {
	f := newStageFixture(t)
	ctx := context.Background()
	base := f.grantPlan(effectargs.AuthorityProvision, "", "v1", "draft", effectargs.GitHubRepositoryGet, nil)
	f.applyBase(tenantA, base)
	first := f.provisioning(tenantA)
	if first.Stage != "draft" {
		t.Fatalf("base stage = %q", first.Stage)
	}

	raised := f.grantPlan(effectargs.AuthorityNarrow, first.Digest, "v2", "certified-live", effectargs.GitHubRepositoryGet, nil)
	before := f.attempts(tenantA)
	_, _, err := f.svc.Propose(ctx, organization, planProposal("narrow-raise", effectargs.AuthorityNarrow, raised))
	wantRefusal(t, "a narrowing plan raising the stage, at Propose", err, CodeFailedPrecondition, reasonStageRaise)
	if n := f.attempts(tenantA) - before; n != 0 {
		t.Fatalf("the refused narrowing left %d attempts", n)
	}
	wantNotSent(t, "a narrowing plan raising the stage, at Apply", f.dispatchPlan(tenantA, effectargs.AuthorityNarrow, raised), reasonStageRaise)
	if after := f.provisioning(tenantA); after.Stage != "draft" || after.Revision != 1 {
		t.Fatalf("the refused raise changed the provisioning: %+v", after)
	}

	// Known good: a provision plan raises the rung, behind a distinct human.
	provisionRaise := f.grantPlan(effectargs.AuthorityProvision, first.Digest, "v3", "constrained-live", effectargs.GitHubRepositoryGet, nil)
	a, _, err := f.svc.Propose(ctx, organization, planProposal("provision-raise", effectargs.AuthorityProvision, provisionRaise))
	must(t, err)
	wantState(t, "a provision plan raising the stage", a, "ESCALATED", contracts.ReasonApprovalRequired)
}

// Lowering the stage is a narrowing like any other: admitted without approval,
// once the mandates fit the lower stage.
func TestPostgresNarrowPlanLowersTheStage(t *testing.T) {
	f := newStageFixture(t)
	ctx := context.Background()
	base := f.grantPlan(effectargs.AuthorityProvision, "", "v1", "certified-live", effectargs.GitHubRepositoryGet, nil)
	f.applyBase(tenantA, base)
	first := f.provisioning(tenantA)
	lowered := f.grantPlan(effectargs.AuthorityNarrow, first.Digest, "v2", "draft", effectargs.GitHubRepositoryGet, nil)
	a, _, err := f.svc.Propose(ctx, organization, planProposal("narrow-lower", effectargs.AuthorityNarrow, lowered))
	must(t, err)
	wantState(t, "a narrowing plan lowering the stage", a, "ADMITTED", "")
	dispatched, _, err := f.svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "the lowering", dispatched, "OBSERVED", "SUCCEEDED", "")
	if after := f.provisioning(tenantA); after.Stage != "draft" || after.Revision != 2 {
		t.Fatalf("after the lowering = %+v", after)
	}
}

// An effect type no adapter of this gateway declares cannot be shown to be a
// read, so the ceiling counts it as a write.
func TestPostgresDraftPlanGrantingAnUndeclaredEffectIsRefused(t *testing.T) {
	f := newStageFixture(t)
	raw := f.grantPlan(effectargs.AuthorityProvision, "", "v1", "draft", "ops.undeclared", nil)
	_, _, err := f.svc.Propose(context.Background(), organization, planProposal("draft-undeclared", effectargs.AuthorityProvision, raw))
	wantRefusal(t, "a draft plan granting an undeclared effect", err, CodeFailedPrecondition, reasonStageCeiling)
}

// workAdapter declares one write of the composing Control Plane's own rows,
// marked Internal as the CP marks its helm.work.* declarations, and the same
// kind of write unmarked.
type workAdapter struct{ *scripted }

func (workAdapter) Declarations() []adapters.Declaration {
	return []adapters.Declaration{
		{EffectType: "work.record", Reversible: adapters.ReversibleNo, Internal: true},
		{EffectType: "work.publish", Reversible: adapters.ReversibleNo},
	}
}

// A draft plan may grant an internal write and nothing else that writes: the
// declaration, not the effect type's name, says which is which.
func TestPostgresDraftPlanMayGrantAnInternalWrite(t *testing.T) {
	f := newStageFixture(t, workAdapter{})
	ctx := context.Background()
	internal := f.grantPlan(effectargs.AuthorityProvision, "", "v1", "draft", "work.record", nil)
	a, _, err := f.svc.Propose(ctx, organization, planProposal("draft-internal", effectargs.AuthorityProvision, internal))
	must(t, err)
	wantState(t, "a draft plan granting an internal write", a, "ESCALATED", contracts.ReasonApprovalRequired)
	if r := f.dispatchPlan(tenantA, effectargs.AuthorityProvision, internal); r.Status != adapters.DispatchSent {
		t.Fatalf("the internal draft plan did not apply: %+v", r)
	}
	if p := f.provisioning(tenantA); p.Stage != "draft" {
		t.Fatalf("applied stage = %q", p.Stage)
	}
	external := f.grantPlan(effectargs.AuthorityProvision, f.provisioning(tenantA).Digest, "v2", "draft", "work.publish", nil)
	_, _, err = f.svc.Propose(ctx, organization, planProposal("draft-external", effectargs.AuthorityProvision, external))
	wantRefusal(t, "a draft plan granting a write not marked internal", err, CodeFailedPrecondition, reasonStageCeiling)
}
