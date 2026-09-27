package admission

// HELM-751 s3b against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): Stop, Lift, and sum limits that fail
// closed without their unit.

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

// operator is human-c at the Console, through the Control Plane runner.
var operator = Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-c", ActorID: actor}

func stopToken() Token { return decideToken("helm.gateway.stop") }

func tenantStop(key string) StopInput {
	return StopInput{IdempotencyKey: key, ScopeKind: "tenant", Reason: "incident"}
}

func TestPostgresStopBlocksProposeApproveAndDispatch(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	fake := &scripted{}
	svc := f.withAdapter(fake)
	escalated := f.escalated("pr1")
	admitted := f.propose(human, note("before"))

	token := stopToken()
	stop, existing, err := svc.Stop(ctx, operator, token, tenantStop("stop-1"))
	must(t, err)
	if existing || stop.ScopeKind != "tenant" || stop.ScopeKey != "" || stop.IssuedBy != "human-c" || stop.LiftedAt != nil {
		t.Fatalf("stop = %+v existing=%v", stop, existing)
	}
	// Propose, Approve and Dispatch all meet it.
	wantState(t, "a proposal under the stop", f.propose(human, note("after")), "DENIED", contracts.ReasonEmergencyStopFenced)
	approved, _, err := svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(escalated, ""))
	must(t, err)
	wantState(t, "an approval under the stop", approved, "DENIED", contracts.ReasonEmergencyStopFenced)
	dispatched, _, err := svc.Dispatch(ctx, workload, admitted.ID)
	must(t, err)
	wantState(t, "a dispatch under the stop", dispatched, "CANCELLED", contracts.ReasonEmergencyStopFenced)
	if fake.dispatched.Load() != 0 {
		t.Fatal("a stopped attempt reached the adapter")
	}

	// Idempotent by key: the same request returns the stop without using up
	// the token; another request under the key conflicts.
	again, existing, err := svc.Stop(ctx, operator, token, tenantStop("stop-1"))
	must(t, err)
	if !existing || again.ID != stop.ID {
		t.Fatalf("a replayed stop = %+v existing=%v", again, existing)
	}
	changed := tenantStop("stop-1")
	changed.Reason = "another"
	_, _, err = svc.Stop(ctx, operator, stopToken(), changed)
	wantRefusal(t, "another request under the key", err, CodeAlreadyExists, contracts.ReasonIdempotencyConflict)
	// The token is single-use for a new stop.
	_, _, err = svc.Stop(ctx, operator, token, tenantStop("stop-2"))
	wantRefusal(t, "a reused stop token", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	// Only an active human operator stops.
	_, _, err = svc.Stop(ctx, workload, stopToken(), tenantStop("stop-3"))
	wantRefusal(t, "a workload's stop", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	// Scopes are checked.
	_, _, err = svc.Stop(ctx, operator, stopToken(), StopInput{IdempotencyKey: "stop-4", ScopeKind: "principal", ScopeKey: "ghost", Reason: "x"})
	wantRefusal(t, "an unknown principal", err, CodeNotFound, "")
	_, _, err = svc.Stop(ctx, operator, stopToken(), StopInput{IdempotencyKey: "stop-5", ScopeKind: "tenant", ScopeKey: tenantB, Reason: "x"})
	wantRefusal(t, "another tenant's scope", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	// A stop on one effect type leaves the others alone.
	f.exec(tenantA, `UPDATE authority_stops SET expires_at = now() + interval '1 millisecond' WHERE stop_id = $1`, stop.ID)
	time.Sleep(10 * time.Millisecond)
	_, _, err = svc.Stop(ctx, operator, stopToken(), StopInput{IdempotencyKey: "stop-6", ScopeKind: "effect_type",
		ScopeKey: effectargs.GitHubPullRequestCreateDraft, Reason: "reviews paused"})
	must(t, err)
	wantState(t, "a note under a draft-PR stop", f.propose(human, note("unrelated")), "ADMITTED", "")
}

func TestPostgresStopMidFlightDoesNotRetractADispatchedCall(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	entered, answer := make(chan struct{}), make(chan struct{})
	fake := &scripted{}
	fake.set(func(adapters.Effect) adapters.DispatchResult {
		close(entered)
		<-answer
		return adapters.DispatchResult{Status: adapters.DispatchSent}
	}, nil)
	svc := f.withAdapter(fake)
	a := f.propose(human, note("in-flight"))
	done := make(chan error, 1)
	go func() {
		_, _, err := svc.Dispatch(ctx, workload, a.ID)
		done <- err
	}()
	<-entered
	stop, _, err := svc.Stop(ctx, operator, stopToken(), tenantStop("mid-flight"))
	must(t, err)
	close(answer)
	must(t, <-done)
	got, err := svc.Get(ctx, human, a.ID)
	must(t, err)
	// The call already sent is not retracted: it is read back and recorded.
	if got.State != "OBSERVED" || got.Outcome != "SUCCEEDED" || got.LatestObservation == nil {
		t.Fatalf("the dispatched call under a later stop = %+v", got)
	}
	// The stop holds for everything after it.
	if stop.ID == "" {
		t.Fatal("no stop")
	}
	wantState(t, "a proposal after the stop", f.propose(human, note("after")), "DENIED", contracts.ReasonEmergencyStopFenced)
}

func TestPostgresLiftNeedsADistinctStepUpApprover(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.rows.CreateEffectType(ctx, tenantA, effectargs.AuthorityLift, authorityrows.RiskLow))
	liftMandate := f.rootMandate(tenantA, "human-c", authorityrows.Terms{
		EffectTypes: []string{effectargs.AuthorityLift}, ValidFrom: f.now.Add(-time.Hour), ValidUntil: f.now.Add(24 * time.Hour),
	})
	svc := f.withAdapter(&scripted{})
	stop, _, err := svc.Stop(ctx, operator, stopToken(), tenantStop("stop-1"))
	must(t, err)

	token := stopToken()
	in := LiftInput{IdempotencyKey: "lift-1", StopID: stop.ID, MandateID: liftMandate.ID.String()}
	lift, existing, err := svc.Lift(ctx, operator, token, in)
	must(t, err)
	// Even under the tenant stop, and with a low-risk row: ESCALATED.
	wantState(t, "the lift", lift, "ESCALATED", contracts.ReasonApprovalRequired)
	if existing || lift.EffectType != effectargs.AuthorityLift || lift.Target != "stop:"+stop.ID || lift.RequesterPrincipalID != "human-c" {
		t.Fatalf("lift = %+v", lift)
	}
	again, existing, err := svc.Lift(ctx, operator, token, in)
	must(t, err)
	if !existing || again.ID != lift.ID {
		t.Fatalf("a replayed lift = %+v existing=%v", again, existing)
	}
	_, _, err = svc.Lift(ctx, operator, token, LiftInput{IdempotencyKey: "lift-2", StopID: stop.ID})
	wantRefusal(t, "a reused lift token", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	_, _, err = svc.Lift(ctx, operator, stopToken(), LiftInput{IdempotencyKey: "lift-3", StopID: "01a0e2e5-0000-7000-8000-000000000000"})
	wantRefusal(t, "an unknown stop", err, CodeNotFound, "")

	// The requester cannot approve it; a distinct human needs step-up, which
	// fails closed until the passkey slice.
	selfApprover := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-c", ActorID: actor}
	_, _, err = svc.Approve(ctx, selfApprover, decideToken("helm.gateway.decide"), approval(lift, ""))
	wantRefusal(t, "self-approval of a lift", err, CodePermissionDenied, contracts.ReasonApproverNotDistinct)
	_, _, err = svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(lift, ""))
	wantRefusal(t, "a lift approved without step-up", err, CodePermissionDenied, contracts.ReasonStepUpRequired)
	got, err := svc.Get(ctx, human, lift.ID)
	must(t, err)
	if got.State != "ESCALATED" {
		t.Fatalf("the lift left ESCALATED: %s", got.State)
	}
	// The stop still holds.
	wantState(t, "a proposal while the lift waits", f.propose(human, note("still-stopped")), "DENIED", contracts.ReasonEmergencyStopFenced)
}

func TestPostgresSumLimitFailsClosedWithoutItsUnit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.notesLimit(5)
	_, _, err := f.svc.Propose(ctx, human, note("unquoted"))
	wantRefusal(t, "a quote without the summed unit", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	if n := f.count(tenantA, `SELECT count(*) FROM authority_effect_attempts WHERE idempotency_key = 'unquoted'`); n != 0 {
		t.Fatal("a refused quote left an attempt")
	}
	zero := note("zero")
	zero.Quote = []Amount{{Unit: "notes", Amount: 0}}
	wantState(t, "a zero amount of the unit", f.propose(human, zero), "ADMITTED", "")
	wantState(t, "the unit quoted", f.propose(human, quotaNote("quoted")), "ADMITTED", "")
}
