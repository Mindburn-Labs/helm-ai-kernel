package admission

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

// T82: late provider usage corrects the original window's estimate exactly
// once. The other call's reservation and count exposures must remain intact.
func TestPostgresModelCallLateUsageConfirmsEstimateOnce(t *testing.T) {
	for _, initial := range []ModelCallResult{ModelCallEstimated, ModelCallCut} {
		for _, actual := range []int64{0, 700, 4_200} {
			t.Run(fmt.Sprintf("initial%d/actual%d", initial, actual), func(t *testing.T) {
				f := newFixture(t)
				ctx := context.Background()
				mandate, limit := f.modelFixture(10_000)
				countLimit, err := f.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &mandate.ID, Unit: "calls", Measure: "count", Window: "day", Value: 20, Span: 1})
				must(t, err)
				claim, _ := f.claimModel("late-usage", 3_000)
				_, _ = f.claimModel("still-held", 500)
				f.ledgerBalances()
				body := []byte(`{"id":"completed-without-usage"}`)
				first := ModelCallOutcome{Result: initial, Reason: contracts.ReasonProviderError}
				if initial == ModelCallEstimated {
					first.Replay = &ModelCallReplay{StatusCode: 200, Body: body, BodySHA256: sha(body), TTL: time.Hour}
				}
				estimated, err := f.svc.SettleModelCall(ctx, claim, first)
				must(t, err)
				if estimated.ModelCall.State != SettlementEstimated {
					t.Fatalf("not estimated: %+v", estimated.ModelCall)
				}
				if used, reserved := f.counter(limit.ID.String()); used != 3_000 || reserved != 500 {
					t.Fatalf("estimate used/reserved %d/%d", used, reserved)
				}
				f.ledgerBalances()
				lateBody := []byte(`{"id":"never-delivered-late-body"}`)
				outcome := ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: actual, Usage: []byte(`{"provider_report":"late"}`),
					Replay: &ModelCallReplay{StatusCode: 200, Body: lateBody, BodySHA256: sha(lateBody), TTL: time.Hour}}
				settled, err := f.svc.SettleModelCall(ctx, claim, outcome)
				must(t, err)
				wantOutcome(t, "late confirmation", settled, "SETTLED", "SUCCEEDED", "")
				basis := "OBSERVED"
				if initial == ModelCallCut {
					basis = "RECONCILED"
				}
				mc := settled.ModelCall
				if settled.OutcomeBasis != basis || mc.State != SettlementConfirmed || mc.ConfirmedMicros == nil || *mc.ConfirmedMicros != actual || mc.BillableMicros != min(actual, 3_000) || mc.HeldMicros != 3_000 {
					t.Fatalf("late settlement: %+v %+v", settled, mc)
				}
				if used, reserved := f.counter(limit.ID.String()); used != actual || reserved != 500 {
					t.Fatalf("late usage/reserved %d/%d, want %d/500", used, reserved, actual)
				}
				if used, reserved := f.counter(countLimit.ID.String()); used != 1 || reserved != 1 {
					t.Fatalf("count exposure changed: %d/%d", used, reserved)
				}
				f.ledgerBalances()
				postings := f.count(tenantA, `SELECT count(*) FROM authority_postings`)
				observations := f.count(tenantA, `SELECT count(*) FROM authority_observations`)
				for _, repeated := range []ModelCallOutcome{outcome, {Result: ModelCallConfirmed, ConfirmedMicros: 9_999}, {Result: ModelCallCut}} {
					again, err := f.svc.SettleModelCall(ctx, claim, repeated)
					must(t, err)
					if again.Version != settled.Version || *again.ModelCall.ConfirmedMicros != actual {
						t.Fatalf("final settlement changed on replay: %+v", again)
					}
				}
				if f.count(tenantA, `SELECT count(*) FROM authority_postings`) != postings || f.count(tenantA, `SELECT count(*) FROM authority_observations`) != observations {
					t.Fatal("a duplicate late report appended accounting or observations")
				}
				replay, err := f.svc.ModelCallReplay(ctx, worker, claim.AttemptID)
				must(t, err)
				if initial == ModelCallEstimated && (replay == nil || string(replay.Body) != string(body)) {
					t.Fatal("late usage replaced the already delivered response")
				}
				if initial == ModelCallCut && replay != nil {
					t.Fatal("accounting confirmation fabricated a lost response")
				}
				f.ledgerBalances()
			})
		}
	}
}

func TestPostgresModelCallLateUsageScopeAndFinalStates(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, limit := f.modelFixture(10_000)
	claim, _ := f.claimModel("late-scope", 3_000)
	estimated, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallEstimated})
	must(t, err)
	for _, change := range []func(*ModelCallClaim){
		func(c *ModelCallClaim) { c.TenantID = tenantB },
		func(c *ModelCallClaim) { c.WorkspaceID = "foreign-workspace" },
		func(c *ModelCallClaim) { c.ClaimID = "foreign-claim" },
	} {
		foreign := *claim
		change(&foreign)
		if _, err := f.svc.SettleModelCall(ctx, &foreign, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 10}); err == nil {
			t.Fatal("foreign late confirmation was accepted")
		}
	}
	unchanged, err := f.svc.Get(ctx, worker, claim.AttemptID)
	must(t, err)
	if unchanged.Version != estimated.Version || unchanged.ModelCall.State != SettlementEstimated {
		t.Fatal("a foreign claim changed the estimate")
	}
	for _, state := range []string{SettlementReleased, SettlementUnresolvedFinal} {
		other, _ := f.claimModel("final-"+state, 500)
		if state == SettlementReleased {
			_, err = f.svc.SettleModelCall(ctx, other, ModelCallOutcome{Result: ModelCallNotSent, Reason: contracts.ReasonProviderCredentialRejected})
			must(t, err)
		} else {
			_, err = f.svc.SettleModelCall(ctx, other, ModelCallOutcome{Result: ModelCallCut})
			must(t, err)
			// This reserved schema state has no current writer. A future writer
			// must not accidentally gain the late-estimate correction path.
			f.exec(tenantA, `UPDATE authority_model_calls SET state = $2 WHERE attempt_id = $1`, other.AttemptID, state)
		}
		before, err := f.svc.Get(ctx, worker, other.AttemptID)
		must(t, err)
		usedBefore, heldBefore := f.counter(limit.ID.String())
		after, err := f.svc.SettleModelCall(ctx, other, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 10})
		must(t, err)
		usedAfter, heldAfter := f.counter(limit.ID.String())
		if after.ModelCall.State != state || after.Version != before.Version || usedAfter != usedBefore || heldAfter != heldBefore {
			t.Fatalf("late report mutated final state %s", state)
		}
	}
	f.ledgerBalances()
}

func TestPostgresModelCallLateUsageConcurrentDelivery(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, limit := f.modelFixture(10_000)
	claim, _ := f.claimModel("late-concurrent", 3_000)
	_, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallCut})
	must(t, err)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			_, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 700})
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		must(t, err)
	}
	if used, reserved := f.counter(limit.ID.String()); used != 700 || reserved != 0 {
		t.Fatalf("concurrent late reports used/reserved %d/%d", used, reserved)
	}
	if got := f.count(tenantA, `SELECT count(*) FROM authority_observations`); got != 1 {
		t.Fatalf("confirmed observations %d, want 1", got)
	}
	if got := f.count(tenantA, `SELECT count(*) FROM authority_postings WHERE cause = 'reverse:model-confirmed' AND kind = 'estimated'`); got != 1 {
		t.Fatalf("estimate reversals %d, want 1", got)
	}
	f.ledgerBalances()
}
