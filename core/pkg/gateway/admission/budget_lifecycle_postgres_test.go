package admission

// A non-resetting team budget does not cancel work already sent. The native
// provision effect raises its cap only through a distinct human's step-up.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	testkit "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/testkit/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	githubadapter "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

func lifecyclePlan(f *planFixture, base, version string, cap int64) []byte {
	return f.plan(effectargs.AuthorityProvision, base, version, func(d map[string]any) {
		effects := []string{effectargs.ModelInference, effectargs.GitHubBranchCreateFromChanges}
		targets := []string{modelRoute, repo}
		d["effect_types"] = []any{
			map[string]any{"effect_type": effectargs.ModelInference, "risk_class": "low"},
			map[string]any{"effect_type": effectargs.GitHubBranchCreateFromChanges, "risk_class": "medium"},
		}
		d["principals"] = append(d["principals"].([]any), map[string]any{"id": "agent-a", "kind": "agent", "ensure_only": true})
		mandates := d["mandates"].([]any)
		mandates[0].(map[string]any)["terms"] = map[string]any{"effect_types": effects, "targets": nil}
		mandates[1].(map[string]any)["terms"] = map[string]any{"effect_types": effects, "targets": targets}
		d["mandates"] = append(mandates, map[string]any{"node": "seat:budget", "holder": "agent-a", "parent": planTeam,
			"terms": map[string]any{"effect_types": effects, "targets": targets}})
		var limits []any
		for _, node := range []string{planOrg, planTeam, "seat:budget"} {
			limits = append(limits, map[string]any{"node": node, "unit": UnitUSDMicros, "measure": "sum", "window": "none", "span": 1, "value": cap})
		}
		d["limits"] = limits
	})
}

func lifecycleWrite(key string, quote int64, baseSHA string) ProposeInput {
	args := bytes.Replace(branchArgs("helm/"+key), []byte("0123456789abcdef0123456789abcdef01234567"), []byte(baseSHA), 1)
	in := proposal(key, effectargs.GitHubBranchCreateFromChanges, repo, args)
	in.Quote = []Amount{{Unit: UnitUSDMicros, Amount: quote}, {Unit: "count", Amount: 1}}
	return in
}

type lifecycleGitHubCredentials struct{ token string }

func (c lifecycleGitHubCredentials) Token(context.Context, string, adapters.Effect) (string, error) {
	return c.token, nil
}

// Hold the first automatic readback of the sent branch so the reconciliation
// job can prove that an already DISPATCHED attempt settles at full budget.
type lifecycleDelayedReadback struct {
	adapters.Adapter
	entered, release chan struct{}
	delayed          atomic.Bool
}

func (a *lifecycleDelayedReadback) Observe(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect) adapters.ObserveResult {
	if bytes.Contains(effect.Arguments, []byte(`"head":"helm/dispatched"`)) && a.delayed.CompareAndSwap(false, true) {
		close(a.entered)
		<-a.release
	}
	return a.Adapter.Observe(ctx, creds, effect)
}

func lifecycleTeamCounter(f *planFixture) (cap, used, reserved int64) {
	f.t.Helper()
	limitID := lifecycleTeamLimitID(f)
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT l.limit_value, COALESCE(c.used,0), COALESCE(c.reserved,0)
			FROM authority_limits l LEFT JOIN authority_counters c ON c.tenant_id=l.tenant_id AND c.limit_id=l.limit_id
			WHERE l.tenant_id=$1 AND l.limit_id=$2`, tenantA, limitID).Scan(&cap, &used, &reserved)
	})
	return cap, used, reserved
}

func lifecycleTeamLimitID(f *planFixture) string {
	f.t.Helper()
	p := f.provisioning(tenantA)
	var mandateID string
	for _, n := range p.Nodes {
		if n.Node == planTeam {
			mandateID = n.MandateID
		}
	}
	if mandateID == "" {
		f.t.Fatal("the team mandate was not applied")
	}
	var limitID string
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT limit_id::text FROM authority_limits
			WHERE tenant_id=$1 AND mandate_id=$2 AND unit='usd_micros' AND window_kind='none'`, tenantA, mandateID).Scan(&limitID)
	})
	return limitID
}

func lifecycleExposure(f *planFixture, limitID string) (confirmed, held int64) {
	f.t.Helper()
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT COALESCE(sum(amount) FILTER (WHERE kind='confirmed'),0),
			COALESCE(sum(amount) FILTER (WHERE kind='held'),0)
			FROM authority_exposures WHERE tenant_id=$1 AND limit_id=$2`, tenantA, limitID).Scan(&confirmed, &held)
	})
	return confirmed, held
}

func TestPostgresBudgetExhaustionReconcilesAndStepUpRaiseReadmits(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	first := lifecyclePlan(f, "", "budget-v1", 100)
	f.applyBase(tenantA, first)
	fake := testkit.NewFakeGitHubFor(t, "Mindburn-Labs", "example")
	readback := &lifecycleDelayedReadback{Adapter: githubadapter.New(githubadapter.WithBaseURL(fake.URL())),
		entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-readback.release:
		default:
			close(readback.release)
		}
	}()
	svc, err := New(f.runtime, Config{Adapters: []adapters.Adapter{f.adapter, readback},
		Credentials: lifecycleGitHubCredentials{token: fake.Token()}})
	must(t, err)
	f.svc = svc
	baseSHA := fake.BaseSHA()
	fake.SetApplyThenDrop(true, false)
	u, _, err := svc.Propose(ctx, worker, lifecycleWrite("unknown", 40, baseSHA))
	must(t, err)
	wantState(t, "unknown write admission", u, "ADMITTED", "")
	u, _, err = svc.Dispatch(ctx, workload, u.ID)
	must(t, err)
	wantState(t, "lost-response write", u, "UNKNOWN", contracts.ReasonProviderError)
	if fake.AppliedRef("heads/helm/unknown") != 1 {
		t.Fatal("the unknown write did not reach fake GitHub exactly once")
	}
	fake.SetApplyThenDrop(false, false)
	d, _, err := svc.Propose(ctx, worker, lifecycleWrite("dispatched", 60, baseSHA))
	must(t, err)
	wantState(t, "second write admission", d, "ADMITTED", "")
	type dispatchResult struct {
		attempt Attempt
		err     error
	}
	dispatchDone := make(chan dispatchResult, 1)
	go func() {
		attempt, _, err := svc.Dispatch(ctx, workload, d.ID)
		dispatchDone <- dispatchResult{attempt, err}
	}()
	select {
	case <-readback.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the sent GitHub branch did not enter automatic readback")
	}
	d, err = svc.Get(ctx, worker, d.ID)
	must(t, err)
	wantState(t, "sent write", d, "DISPATCHED", "")
	if fake.AppliedRef("heads/helm/dispatched") != 1 {
		t.Fatal("the dispatched write did not reach fake GitHub exactly once")
	}
	if cap, used, reserved := lifecycleTeamCounter(f); cap != 100 || used != 0 || reserved != 100 {
		t.Fatalf("exhausted team: cap=%d used=%d reserved=%d", cap, used, reserved)
	}
	f.ledgerBalances()

	model := modelProposal("same-model-args", modelRoute, 1)
	write := lifecycleWrite("same-write-args", 1, baseSHA)
	for name, in := range map[string]ProposeInput{"model": model, "write": write} {
		a, _, err := svc.Propose(ctx, worker, in)
		must(t, err)
		if a.State != "DENIED" || a.ReasonCode != string(contracts.ReasonBudgetExceeded) || len(a.Exposures) != 0 || a.Permit != nil {
			t.Fatalf("%s at full budget = %+v", name, a)
		}
	}
	if cap, used, reserved := lifecycleTeamCounter(f); cap != 100 || used != 0 || reserved != 100 {
		t.Fatalf("denials changed full budget: cap=%d used=%d reserved=%d", cap, used, reserved)
	}

	// Neither pending attempt is cancelled. Observation and the reconciliation
	// job still read GitHub while new work is denied.
	unknownReads := fake.RefReads("helm/unknown")
	dispatchedReads := fake.RefReads("helm/dispatched")
	u, _, err = svc.Observe(ctx, workload, u.ID)
	must(t, err)
	wantOutcome(t, "UNKNOWN observation", u, "RECONCILED", "SUCCEEDED", "")
	resolved, _, err := svc.Reconcile(ctx, tenantA, workspace, d.ID, false)
	must(t, err)
	if !resolved {
		t.Fatal("the DISPATCHED reconciliation did not resolve")
	}
	d, err = svc.Get(ctx, worker, d.ID)
	must(t, err)
	wantOutcome(t, "DISPATCHED reconciliation", d, "OBSERVED", "SUCCEEDED", "")
	close(readback.release)
	select {
	case result := <-dispatchDone:
		must(t, result.err)
		wantOutcome(t, "late automatic readback", result.attempt, "OBSERVED", "SUCCEEDED", "")
	case <-time.After(10 * time.Second):
		t.Fatal("the delayed automatic readback did not finish")
	}
	if fake.RefReads("helm/unknown") <= unknownReads || fake.RefReads("helm/dispatched") <= dispatchedReads ||
		fake.AppliedRef("heads/helm/unknown") != 1 || fake.AppliedRef("heads/helm/dispatched") != 1 {
		t.Fatal("reconciliation did not read both provider refs without writing them again")
	}
	if cap, used, reserved := lifecycleTeamCounter(f); cap != 100 || used != 100 || reserved != 0 {
		t.Fatalf("settled full budget: cap=%d used=%d reserved=%d", cap, used, reserved)
	}
	f.ledgerBalances()
	oldTeamLimit := lifecycleTeamLimitID(f)
	for _, a := range []Attempt{u, d} {
		if a.State == "CANCELLED" || a.Exposures[0].Kind != "confirmed" {
			t.Fatalf("exhaustion cancelled or released prior work: %+v", a)
		}
	}

	// A distinct human's verified step-up approves a higher provision. The
	// same effect arguments and quote, under fresh idempotency keys, now fit.
	raised := lifecyclePlan(f, f.provisioning(tenantA).Digest, "budget-v2", 200)
	plan, _, err := svc.Propose(ctx, organization, planProposal("raise-budget", effectargs.AuthorityProvision, raised))
	must(t, err)
	wantState(t, "limit-raising provision", plan, "ESCALATED", contracts.ReasonApprovalRequired)
	_, _, err = svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(plan, "raise to 200"))
	wantRefusal(t, "raise without step-up", err, CodePermissionDenied, contracts.ReasonStepUpRequired)
	proof := stepUpProof()
	approved, _, err := svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), withProof(approval(plan, "raise to 200"), proof))
	must(t, err)
	wantState(t, "step-up approved provision", approved, "ADMITTED", "")
	f.wantProofRecord(plan.ID, proof)
	applied, _, err := svc.Dispatch(ctx, workload, plan.ID)
	must(t, err)
	wantOutcome(t, "higher provision applied", applied, "OBSERVED", "SUCCEEDED", "")
	if cap, used, reserved := lifecycleTeamCounter(f); cap != 200 || used != 100 || reserved != 0 {
		t.Fatalf("raise lost or duplicated spent budget: cap=%d used=%d reserved=%d", cap, used, reserved)
	}
	for name, in := range map[string]ProposeInput{"model": model, "write": write} {
		in.IdempotencyKey += "-after-raise"
		a, _, err := svc.Propose(ctx, worker, in)
		must(t, err)
		if a.State != "ADMITTED" || len(a.Exposures) == 0 || a.Exposures[0].Kind != "held" {
			t.Fatalf("%s remained blocked after raise: %+v", name, a)
		}
	}
	if cap, used, reserved := lifecycleTeamCounter(f); cap != 200 || used != 100 || reserved != 2 {
		t.Fatalf("after readmission: cap=%d used=%d reserved=%d", cap, used, reserved)
	}
	// A replacement limit copies prior used into its enforcement counter;
	// historical exposures stay on the original limit. Assert the copy and
	// the new holds separately, so the same settlement is never counted twice.
	newTeamLimit := lifecycleTeamLimitID(f)
	oldConfirmed, oldHeld := lifecycleExposure(f, oldTeamLimit)
	newConfirmed, newHeld := lifecycleExposure(f, newTeamLimit)
	if oldTeamLimit == newTeamLimit || oldConfirmed != 100 || oldHeld != 0 || newConfirmed != 0 || newHeld != 2 {
		t.Fatalf("carry-over and new exposures: old=%s %d+%d, new=%s %d+%d",
			oldTeamLimit, oldConfirmed, oldHeld, newTeamLimit, newConfirmed, newHeld)
	}
}

func TestPostgresOverwideBudgetPlanIsRefusedBeforeDelegation(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	base := lifecyclePlan(f, "", "wide-budget", 10_000_000)
	f.applyBase(tenantA, base)
	replacement := lifecyclePlan(f, f.provisioning(tenantA).Digest, "wide-budget-v2", 10_000_000)
	var doc map[string]any
	if err := json.Unmarshal(replacement, &doc); err != nil {
		t.Fatal(err)
	}
	limits := doc["limits"].([]any)
	limits[2].(map[string]any)["value"] = float64(10_000_001)
	wide, err := json.Marshal(doc)
	must(t, err)
	before := f.attempts(tenantA)
	_, _, err = f.svc.Propose(ctx, organization, planProposal("wide-budget-v2", effectargs.AuthorityProvision, wide))
	var refusal *Error
	if !errors.As(err, &refusal) || refusal.Reason != contracts.ReasonDelegationScopeViolation {
		t.Fatalf("overwide child plan: %v, want DELEGATION_SCOPE_VIOLATION", err)
	}
	if after := f.attempts(tenantA); after != before {
		t.Fatalf("overwide delegation created %d attempts", after-before)
	}
	if cap, used, reserved := lifecycleTeamCounter(f); cap != 10_000_000 || used != 0 || reserved != 0 {
		t.Fatalf("overwide delegation changed the applied team cap: %d, used=%d reserved=%d", cap, used, reserved)
	}
	if got := f.count(tenantA, `SELECT count(*) FROM authority_limits WHERE limit_value > $1`, int64(10_000_000)); got != 0 {
		t.Fatalf("overwide delegation installed %d excess limits", got)
	}
	overspend, _, err := f.svc.Propose(ctx, worker, modelProposal("after-overwide-refusal", modelRoute, 10_000_001))
	must(t, err)
	if overspend.State != "DENIED" || overspend.ReasonCode != string(contracts.ReasonBudgetExceeded) || len(overspend.Exposures) != 0 {
		t.Fatalf("model call spent beyond the unchanged team cap: %+v", overspend)
	}
	if cap, used, reserved := lifecycleTeamCounter(f); cap != 10_000_000 || used != 0 || reserved != 0 {
		t.Fatalf("overspend refusal held budget: cap=%d used=%d reserved=%d", cap, used, reserved)
	}
}
