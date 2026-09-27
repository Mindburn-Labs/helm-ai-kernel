package admission

// HELM-751 s3b against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): Stop, Lift, and sum limits that fail
// closed without their unit.

import (
	"context"
	"strings"
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

// H1 of the s3b review: a principal stop on a workload stops what it carries.
func TestPostgresPrincipalStopCoversTheWorkloadAndTheDispatcher(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	fake := &scripted{}
	svc := f.withAdapter(fake)
	admitted := f.propose(human, note("before"))
	_, _, err := svc.Stop(ctx, operator, stopToken(), StopInput{IdempotencyKey: "stop-runner", ScopeKind: "principal", ScopeKey: actor, Reason: "runaway"})
	must(t, err)
	// The runner can no longer propose for a human...
	wantState(t, "a proposal carried by the stopped runner", f.propose(human, note("after")), "DENIED", contracts.ReasonEmergencyStopFenced)
	// ...nor dispatch what it proposed before the stop.
	got, _, err := svc.Dispatch(ctx, workload, admitted.ID)
	must(t, err)
	wantState(t, "a dispatch by the stopped runner", got, "CANCELLED", contracts.ReasonEmergencyStopFenced)
	// An agent's own attempt, dispatched with the stopped runner as its act:
	// the dispatcher's actor is checked too.
	f.rootMandate(tenantA, "agent-a", skeletonTerms(f.now))
	agent := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a"}
	own := f.propose(agent, note("agent-own"))
	wantState(t, "the agent's direct proposal", own, "ADMITTED", "")
	carried := agent
	carried.ActorID = actor
	got, _, err = svc.Dispatch(ctx, carried, own.ID)
	must(t, err)
	wantState(t, "a dispatch whose act is the stopped runner", got, "CANCELLED", contracts.ReasonEmergencyStopFenced)
	if fake.dispatched.Load() != 0 {
		t.Fatal("a stopped workload reached the adapter")
	}
}

func TestPostgresAStoppedApproverCannotApprove(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.escalated("pr1")
	_, _, err := f.svc.Stop(ctx, operator, stopToken(), StopInput{IdempotencyKey: "stop-b", ScopeKind: "principal", ScopeKey: "human-b", Reason: "compromised"})
	must(t, err)
	_, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(a, ""))
	wantRefusal(t, "a stopped approver", err, CodePermissionDenied, contracts.ReasonEmergencyStopFenced)
	got, err := f.svc.Get(ctx, human, a.ID)
	must(t, err)
	if got.State != "ESCALATED" || got.Approval != nil {
		t.Fatalf("a stopped approver changed the attempt: %+v", got)
	}
	// Another human approves it.
	approved, _, err := f.svc.Approve(ctx, operator, decideToken("helm.gateway.decide"), approval(a, ""))
	must(t, err)
	wantState(t, "an unstopped approver", approved, "ADMITTED", "")
}

// M2 and M3 of the s3b review: a lift is blocked by every stop but its own,
// is created only through Lift, and spends no limit.
func TestPostgresLiftIsBlockedByEveryStopButItsOwn(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.rows.CreateEffectType(ctx, tenantA, effectargs.AuthorityLift, authorityrows.RiskLow))
	liftMandate := f.rootMandate(tenantA, "human-c", authorityrows.Terms{
		EffectTypes: []string{effectargs.AuthorityLift}, ValidFrom: f.now.Add(-time.Hour), ValidUntil: f.now.Add(24 * time.Hour),
	})
	// A sum limit on the lift's mandate: a Lift carries no quote, and
	// authority changes spend no resource.
	_, err := f.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &liftMandate.ID, Unit: "notes", Measure: "sum", Window: "day", Value: 1, Span: 1})
	must(t, err)
	stop, _, err := f.svc.Stop(ctx, operator, stopToken(), tenantStop("tenant-stop"))
	must(t, err)
	lift, _, err := f.svc.Lift(ctx, operator, stopToken(), LiftInput{IdempotencyKey: "lift-1", StopID: stop.ID})
	must(t, err)
	wantState(t, "a lift under its own stop and a sum limit", lift, "ESCALATED", contracts.ReasonApprovalRequired)
	// A stop on the operator is not the one being lifted: it applies.
	byB := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-b", ActorID: actor}
	_, _, err = f.svc.Stop(ctx, byB, stopToken(), StopInput{IdempotencyKey: "stop-c", ScopeKind: "principal", ScopeKey: "human-c", Reason: "x"})
	must(t, err)
	fenced, _, err := f.svc.Lift(ctx, operator, stopToken(), LiftInput{IdempotencyKey: "lift-2", StopID: stop.ID})
	must(t, err)
	wantState(t, "a lift by a stopped operator", fenced, "DENIED", contracts.ReasonEmergencyStopFenced)
	// Propose cannot create a lift.
	in := proposal("lift-by-propose", effectargs.AuthorityLift, "stop:"+stop.ID,
		[]byte(`{"schema":"helm.authority.lift.v1","stop_id":"`+stop.ID+`"}`))
	in.CommitmentID = ""
	_, _, err = f.svc.Propose(ctx, operator, in)
	wantRefusal(t, "a lift through Propose", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
}

// L2 of the s3b review: concurrent Stops under one key make one stop.
func TestPostgresConcurrentStopsUnderOneKeyReplay(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	shared := stopToken()
	type answer struct {
		stop     Stop
		existing bool
		err      error
	}
	answers := make(chan answer, 8)
	for i := 0; i < 8; i++ {
		token := stopToken()
		if i%2 == 0 {
			token = shared // the same request, sent twice with its token
		}
		go func() {
			stop, existing, err := f.svc.Stop(ctx, operator, token, tenantStop("one-key"))
			answers <- answer{stop, existing, err}
		}()
	}
	fresh, id := 0, ""
	for i := 0; i < 8; i++ {
		a := <-answers
		must(t, a.err)
		if id == "" {
			id = a.stop.ID
		}
		if a.stop.ID != id {
			t.Fatalf("two stops for one key: %s and %s", id, a.stop.ID)
		}
		if !a.existing {
			fresh++
		}
	}
	if fresh != 1 {
		t.Fatalf("%d fresh stops for one key", fresh)
	}
	if n := f.count(tenantA, `SELECT count(*) FROM authority_stops WHERE idempotency_key = 'one-key'`); n != 1 {
		t.Fatalf("%d stop rows", n)
	}
}

// M1 of the s3b review: the last reconciliation try hands the attempt to a
// human whatever made its read-back fail.
func TestPostgresFinalReconcileHandsOffWhateverTheReadBackError(t *testing.T) {
	f := newFixture(t)
	withAdapter := f.withAdapter(&scripted{})
	for name, run := range map[string]func(id string) (bool, time.Time, error){
		"no adapter for the effect type": func(id string) (bool, time.Time, error) {
			return f.svc.Reconcile(context.Background(), tenantA, workspace, id, true)
		},
		"a cancelled context": func(id string) (bool, time.Time, error) {
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			return withAdapter.Reconcile(cancelled, tenantA, workspace, id, true)
		},
	} {
		a := f.propose(human, note("handoff-"+strings.ReplaceAll(name, " ", "-")))
		f.claimOnly(withAdapter, a.ID)
		f.passFence(a.ID)
		// Before the last try, the error is returned for a retry.
		if _, _, err := f.svc.Reconcile(context.Background(), tenantA, workspace, a.ID, false); err == nil {
			t.Fatalf("%s: a failed read-back before the last try returned no error", name)
		}
		resolved, _, err := run(a.ID)
		must(t, err)
		got, err := f.svc.Get(context.Background(), human, a.ID)
		must(t, err)
		if !resolved || got.State != "ESCALATED_TO_HUMAN" {
			t.Fatalf("%s: the last try left %s (resolved=%v)", name, got.State, resolved)
		}
	}
}
