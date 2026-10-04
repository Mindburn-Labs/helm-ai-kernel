package provision_test

// These tests use actual provision/admission/claim/settlement transactions and
// a restricted PostgreSQL role. No provider call or customer money is used.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

const budgetRoute = "anthropic/claude-sonnet-5-5"

func budgetPlan(f *provisionFixture, schema, version string, cap int64) []byte {
	f.t.Helper()
	return budgetPlanAt(f, schema, f.applied().Digest, version, cap, "none")
}

func budgetPlanAt(f *provisionFixture, schema, base, version string, cap int64, window string) []byte {
	f.t.Helper()
	var doc map[string]any
	provisionMust(f.t, json.Unmarshal(f.plan(schema, base, version, cap), &doc))
	doc["effect_types"] = []any{map[string]any{"effect_type": effectargs.ModelInference, "risk_class": "low"}}
	for _, raw := range doc["mandates"].([]any) {
		terms := raw.(map[string]any)["terms"].(map[string]any)
		terms["effect_types"] = []string{effectargs.ModelInference}
		terms["targets"] = []string{budgetRoute}
	}
	var modelLimits []any
	for _, raw := range doc["limits"].([]any) {
		l := raw.(map[string]any)
		if l["unit"] != "usd_micros" {
			continue
		}
		l["window"], l["span"] = window, 1
		modelLimits = append(modelLimits, l)
	}
	doc["limits"] = modelLimits
	raw, err := json.Marshal(doc)
	provisionMust(f.t, err)
	return raw
}

func budgetFixture(t *testing.T) (*provisionFixture, *admission.Service) {
	t.Helper()
	f := newProvisionFixtureWithPlan(t, func(f *provisionFixture) []byte {
		return budgetPlanAt(f, effectargs.AuthorityProvision, "", "budget-v1", 200, "none")
	})
	s, err := admission.New(f.db, admission.Config{})
	provisionMust(t, err)
	return f, s
}

func budgetBinding(f *provisionFixture) provision.BudgetBinding {
	f.t.Helper()
	a, err := provision.GetProvisioning(f.ctx, f.rows, provisionTenant, provisionOrg)
	provisionMust(f.t, err)
	for i, n := range a.Nodes {
		if n.Node != provisionOrg {
			continue
		}
		for _, l := range a.Status[i].Limits {
			if l.Spec.Unit == "usd_micros" {
				return provision.BudgetBinding{OrgRef: a.OrgRef, VersionRef: a.VersionRef, PlanDigest: a.Digest,
					Revision: a.Revision, Node: n.Node, MandateID: n.MandateID, LimitID: l.ID.String(), LimitVersion: l.Version}
			}
		}
	}
	f.t.Fatal("provisioning readback did not expose the budget binding")
	return provision.BudgetBinding{}
}

func budgetRead(f *provisionFixture) *provision.BudgetSnapshot {
	f.t.Helper()
	x, err := provision.GetProvisionBudget(f.ctx, f.rows, provisionTenant, "workspace-provision", provisioner, budgetBinding(f))
	provisionMust(f.t, err)
	return x
}

func budgetProposal(key string, hold int64) admission.ProposeInput {
	d := sha256.Sum256([]byte(key))
	args := fmt.Sprintf(`{"schema":"model.inference.v1","api":"anthropic-messages","route":%q,"request_sha256":%q,"input_bytes":20,"max_output_tokens":16,"stream":true}`, budgetRoute, hex.EncodeToString(d[:]))
	return admission.ProposeInput{IdempotencyKey: key, CaseID: "work-budget-proof", EffectType: effectargs.ModelInference, Target: budgetRoute,
		Arguments: []byte(args), Quote: []admission.Amount{{Unit: "usd_micros", Amount: hold}}}
}

func budgetCaller() admission.Caller {
	return admission.Caller{TenantID: provisionTenant, WorkspaceID: "workspace-provision", PrincipalID: provisionChild, ActorID: "spiffe://helm.test/cp"}
}

func budgetAdmit(f *provisionFixture, s *admission.Service, key string, hold int64) admission.Attempt {
	f.t.Helper()
	a, _, err := s.Propose(f.ctx, budgetCaller(), budgetProposal(key, hold))
	provisionMust(f.t, err)
	if a.State != "ADMITTED" {
		f.t.Fatalf("admit: %+v", a)
	}
	return a
}

func budgetClaim(f *provisionFixture, s *admission.Service, key string, hold int64) *admission.ModelCallClaim {
	f.t.Helper()
	a := budgetAdmit(f, s, key, hold)
	c, state, err := s.ClaimModelCall(f.ctx, budgetCaller(), a.ID, time.Minute)
	provisionMust(f.t, err)
	if c == nil {
		f.t.Fatalf("claim refused: %+v", state)
	}
	return c
}

func budgetSettle(f *provisionFixture, s *admission.Service, c *admission.ModelCallClaim, result admission.ModelCallResult, confirmed int64) {
	f.t.Helper()
	out := admission.ModelCallOutcome{Result: result, ConfirmedMicros: confirmed}
	if result == admission.ModelCallNotSent {
		out.Reason = contracts.ReasonProviderCredentialRejected
	}
	_, err := s.SettleModelCall(f.ctx, c, out)
	provisionMust(f.t, err)
}

func wantBudget(t *testing.T, x *provision.BudgetSnapshot, spent, aside int64) {
	t.Helper()
	if !x.CoverageComplete || x.Amounts == nil || x.Amounts.SpentFinal != spent || x.Amounts.SetAside != aside || len(x.EvidenceDigest) != sha256.Size {
		t.Fatalf("budget = %+v amounts=%+v; want spent%d aside%d", x, x.Amounts, spent, aside)
	}
}

func TestPostgresProvisionBudgetCountsNativeAttemptsOnceAcrossReplacement(t *testing.T) {
	f, s := budgetFixture(t)
	x := budgetRead(f)
	wantBudget(t, x, 0, 0)
	if x.Activity != "no_runs_yet" {
		t.Fatalf("empty activity = %q", x.Activity)
	}
	budgetSettle(f, s, budgetClaim(f, s, "confirmed", 20), admission.ModelCallConfirmed, 8)
	budgetAdmit(f, s, "unclaimed", 10)
	budgetSettle(f, s, budgetClaim(f, s, "estimated", 30), admission.ModelCallEstimated, 0)
	budgetClaim(f, s, "zero-quote", 0)
	wantBudget(t, budgetRead(f), 8, 40)
	old := budgetBinding(f)
	f.wantSent(f.dispatch(f.effect(budgetPlan(f, effectargs.AuthorityProvision, "budget-v2", 300))))
	x = budgetRead(f)
	wantBudget(t, x, 8, 40)
	if x.Binding.LimitID == old.LimitID {
		t.Fatal("replacement did not create a new limit")
	}
	if _, err := provision.GetProvisionBudget(f.ctx, f.rows, provisionTenant, "workspace-provision", provisioner, old); !errors.Is(err, provision.ErrBudgetBinding) {
		t.Fatalf("stale binding: %v", err)
	}
}

func TestPostgresProvisionBudgetZeroQuoteAndOverageRemainVisible(t *testing.T) {
	f, s := budgetFixture(t)
	budgetAdmit(f, s, "only-zero", 0)
	x := budgetRead(f)
	wantBudget(t, x, 0, 0)
	if x.Activity != "reported" {
		t.Fatal("zero quote was erased")
	}
	budgetSettle(f, s, budgetClaim(f, s, "overage", 10), admission.ModelCallConfirmed, 15)
	x = budgetRead(f)
	wantBudget(t, x, 10, 0)
	if !x.OverageDetected || x.EnforcementAvailable {
		t.Fatal("provider overage claimed an enforced bound")
	}
}

func TestPostgresProvisionBudgetUnknownAndReleasedAreNotFinalSpend(t *testing.T) {
	f, s := budgetFixture(t)
	budgetSettle(f, s, budgetClaim(f, s, "cut", 20), admission.ModelCallCut, 0)
	budgetSettle(f, s, budgetClaim(f, s, "not-sent", 10), admission.ModelCallNotSent, 0)
	wantBudget(t, budgetRead(f), 0, 20)
}

func TestPostgresProvisionBudgetWindowChangeCannotEraseSpend(t *testing.T) {
	for _, window := range []string{"day", "month"} {
		t.Run(window, func(t *testing.T) {
			f := newProvisionFixtureWithPlan(t, func(f *provisionFixture) []byte {
				return budgetPlanAt(f, effectargs.AuthorityProvision, "", "window-v1", 200, window)
			})
			s, err := admission.New(f.db, admission.Config{})
			provisionMust(t, err)
			budgetSettle(f, s, budgetClaim(f, s, "old-spend", 20), admission.ModelCallConfirmed, 8)
			budgetClaim(f, s, "old-hold", 10)
			f.wantSent(f.dispatch(f.effect(budgetPlan(f, effectargs.AuthorityProvision, "lifetime-v2", 200))))
			x := budgetRead(f)
			if x.CoverageComplete || x.Amounts != nil || x.EnforcementAvailable || x.Activity != "not_reported" || x.Reason != "unsupported_budget_history" {
				t.Fatalf("window change erased historical spend/hold: %+v", x)
			}
		})
	}
}

func TestPostgresProvisionBudgetRequiresCurrentServiceAndWorkspace(t *testing.T) {
	f, s := budgetFixture(t)
	b := budgetBinding(f)
	for _, principal := range []string{provisionOwner, "missing"} {
		if _, err := provision.GetProvisionBudget(f.ctx, f.rows, provisionTenant, "workspace-provision", principal, b); !errors.Is(err, provision.ErrBudgetReader) {
			t.Fatalf("reader %s: %v", principal, err)
		}
	}
	x, err := provision.GetProvisionBudget(f.ctx, f.rows, provisionTenant, "foreign", provisioner, b)
	provisionMust(t, err)
	if x.CoverageComplete || x.Amounts != nil {
		t.Fatal("foreign workspace received budget")
	}
	foreign := budgetCaller()
	foreign.WorkspaceID = "foreign"
	a, _, err := s.Propose(f.ctx, foreign, budgetProposal("other-workspace", 10))
	provisionMust(t, err)
	if a.State != "ADMITTED" {
		t.Fatalf("foreign fixture: %+v", a)
	}
	x = budgetRead(f)
	if x.CoverageComplete || x.Amounts != nil || x.Activity == "no_runs_yet" {
		t.Fatal("cross-workspace cohort was silently filtered")
	}
	provisionMust(t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error { _, err := tx.DisablePrincipal(f.ctx, provisioner); return err }))
	if _, err := provision.GetProvisionBudget(f.ctx, f.rows, provisionTenant, "workspace-provision", provisioner, b); !errors.Is(err, provision.ErrBudgetReader) {
		t.Fatalf("disabled service: %v", err)
	}
}

func TestPostgresProvisionBudgetLegacyOrMissingExposureIsNotZero(t *testing.T) {
	t.Run("legacy", func(t *testing.T) {
		f, _ := budgetFixture(t)
		provisionMust(t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
			_, err := tx.SQL().ExecContext(f.ctx, `UPDATE authority_provisions SET budget_lineage_complete=false WHERE tenant_id=$1`, provisionTenant)
			return err
		}))
		f.wantSent(f.dispatch(f.effect(budgetPlan(f, effectargs.AuthorityProvision, "budget-v2", 200))))
		x := budgetRead(f)
		if x.CoverageComplete || x.Amounts != nil {
			t.Fatal("later apply healed missing history")
		}
	})
	t.Run("corrupt quote", func(t *testing.T) {
		f, s := budgetFixture(t)
		a := budgetAdmit(f, s, "zero", 0)
		provisionMust(t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
			_, err := tx.SQL().ExecContext(f.ctx, `UPDATE authority_effect_attempts SET quote='[{"unit":"usd_micros","amount":20}]' WHERE tenant_id=$1 AND attempt_id=$2`, provisionTenant, a.ID)
			return err
		}))
		x := budgetRead(f)
		if x.CoverageComplete || x.Amounts != nil {
			t.Fatal("missing held exposure reported as zero")
		}
	})
}

func TestPostgresProvisionBudgetSnapshotIsReadOnlyAndRepeatable(t *testing.T) {
	f, s := budgetFixture(t)
	budgetAdmit(f, s, "held", 10)
	provisionMust(t, f.rows.ReadInTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		var first, second int64
		provisionMust(t, tx.SQL().QueryRowContext(f.ctx, `SELECT count(*) FROM authority_effect_attempts`).Scan(&first))
		budgetAdmit(f, s, "concurrent", 0)
		provisionMust(t, tx.SQL().QueryRowContext(f.ctx, `SELECT count(*) FROM authority_effect_attempts`).Scan(&second))
		if first != second {
			t.Fatal("read model mixed transaction snapshots")
		}
		return nil
	}))
	err := f.rows.ReadInTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		_, err := tx.SQL().ExecContext(f.ctx, `UPDATE authority_tenants SET version=version+1 WHERE tenant_id=$1`, provisionTenant)
		return err
	})
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("read-only write was not refused: %v", err)
	}
}
