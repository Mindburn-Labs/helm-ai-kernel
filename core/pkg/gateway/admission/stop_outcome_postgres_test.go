package admission

// Principal Stop outcomes against a real PostgreSQL ledger. The provider is
// a scripted adapter; these are native boundary proofs, not live acceptance.

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

func principalStop(key, principal string) StopInput {
	return StopInput{IdempotencyKey: key, ScopeKind: "principal", ScopeKey: principal, Reason: "team freeze"}
}

func wantAttemptIDs(t *testing.T, what string, got []string, ids ...string) {
	t.Helper()
	slices.Sort(ids)
	if !slices.Equal(got, ids) {
		t.Fatalf("%s = %v, want %v", what, got, ids)
	}
}

func TestPostgresPrincipalStopFencesAdmissionAndVoidsAtClaim(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	limit := f.notesLimit(10)
	fake := &scripted{}
	svc := f.withAdapter(fake)
	awaiting := f.propose(human, quotaNote("stop-awaiting"))
	pending := f.escalated("stop-pending")
	stop, _, err := svc.Stop(ctx, operator, stopToken(), principalStop("stop-seat", human.PrincipalID))
	must(t, err)
	before, err := svc.StopOutcome(ctx, operator, stop.ID)
	must(t, err)
	if !before.Active || before.Stop.ID != stop.ID || before.Stop.ScopeKey != human.PrincipalID {
		t.Fatalf("principal Stop outcome = %+v", before)
	}
	wantAttemptIDs(t, "awaiting claim", before.AwaitingClaimAttemptIDs, awaiting.ID)
	wantAttemptIDs(t, "not yet voided", before.VoidedAtClaimAttemptIDs)
	if n := f.count(tenantA, `SELECT reserved FROM authority_counters WHERE limit_id = $1`, limit.ID); n != 1 {
		t.Fatalf("the Stop released a pre-claim hold: reserved = %d", n)
	}

	blocked := f.propose(human, quotaNote("stop-blocked"))
	wantState(t, "a fresh proposal", blocked, "DENIED", contracts.ReasonEmergencyStopFenced)
	if blocked.Permit != nil || len(blocked.Exposures) != 0 {
		t.Fatalf("a stopped proposal reserved exposure: %+v", blocked)
	}
	approved, _, err := svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(pending, ""))
	must(t, err)
	wantState(t, "approval re-admission", approved, "DENIED", contracts.ReasonEmergencyStopFenced)
	if approved.Permit != nil || len(approved.Exposures) != 0 {
		t.Fatalf("approval under Stop issued a permit or hold: %+v", approved)
	}
	voided, _, err := svc.Dispatch(ctx, workload, awaiting.ID)
	must(t, err)
	wantState(t, "the later claim", voided, "CANCELLED", contracts.ReasonEmergencyStopFenced)
	if voided.Permit == nil || voided.Permit.ConsumedAt != nil || voided.Permit.VoidReasonCode != string(contracts.ReasonEmergencyStopFenced) ||
		len(voided.Exposures) != 1 || voided.Exposures[0].Kind != "released" || fake.dispatched.Load() != 0 {
		t.Fatalf("the claim did not void and release without provider I/O: %+v; provider calls %d", voided, fake.dispatched.Load())
	}
	if n := f.count(tenantA, `SELECT reserved FROM authority_counters WHERE limit_id = $1`, limit.ID); n != 0 {
		t.Fatalf("reserved after void = %d", n)
	}
	f.ledgerBalances()

	// Another principal in the same tenant and workspace keeps its authority.
	f.rootMandate(tenantA, "human-b", skeletonTerms(f.now))
	outside := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-b", ActorID: actor}
	wantState(t, "outside the principal Stop", f.propose(outside, note("outside-stop")), "ADMITTED", "")
	after, err := svc.StopOutcome(ctx, operator, stop.ID)
	must(t, err)
	wantAttemptIDs(t, "blocked admissions", after.BlockedAdmissionAttemptIDs, blocked.ID, pending.ID)
	wantAttemptIDs(t, "awaiting claims", after.AwaitingClaimAttemptIDs)
	wantAttemptIDs(t, "voided at claim", after.VoidedAtClaimAttemptIDs, awaiting.ID)
	wantAttemptIDs(t, "checking", after.CheckingAttemptIDs)
	wantAttemptIDs(t, "human review", after.HumanReviewAttemptIDs)
}

func TestPostgresPrincipalStopKeepsDispatchedAndUnknownUntilReadback(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	limit := f.notesLimit(10)
	fake := &scripted{}
	svc := f.withAdapter(fake)

	// A sent write whose immediate read-back is absent stays DISPATCHED;
	// an indefinite send stays UNKNOWN. Both retain their held exposure.
	fake.set(nil, absent)
	dispatched := f.propose(human, quotaNote("stop-dispatched"))
	got, _, err := svc.Dispatch(ctx, workload, dispatched.ID)
	must(t, err)
	wantState(t, "sent but not yet observed", got, "DISPATCHED", "")
	fake.set(func(adapters.Effect) adapters.DispatchResult {
		return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: contracts.ReasonProviderError}
	}, nil)
	unknown := f.propose(human, quotaNote("stop-unknown"))
	got, _, err = svc.Dispatch(ctx, workload, unknown.ID)
	must(t, err)
	wantState(t, "indefinite provider answer", got, "UNKNOWN", contracts.ReasonProviderError)
	awaiting := f.propose(human, quotaNote("stop-awaiting"))
	providerCalls := fake.dispatched.Load()
	stop, _, err := svc.Stop(ctx, operator, stopToken(), principalStop("stop-inflight", human.PrincipalID))
	must(t, err)
	out, err := svc.StopOutcome(ctx, operator, stop.ID)
	must(t, err)
	wantAttemptIDs(t, "open provider outcomes", out.CheckingAttemptIDs, dispatched.ID, unknown.ID)
	wantAttemptIDs(t, "unclaimed", out.AwaitingClaimAttemptIDs, awaiting.ID)
	if n := f.count(tenantA, `SELECT reserved FROM authority_counters WHERE limit_id = $1`, limit.ID); n != 3 {
		t.Fatalf("the Stop released uncertain exposure: reserved = %d", n)
	}
	got, _, err = svc.Dispatch(ctx, workload, awaiting.ID)
	must(t, err)
	wantState(t, "unclaimed attempt", got, "CANCELLED", contracts.ReasonEmergencyStopFenced)
	if fake.dispatched.Load() != providerCalls {
		t.Fatal("the stopped unclaimed attempt reached the provider")
	}
	if n := f.count(tenantA, `SELECT reserved FROM authority_counters WHERE limit_id = $1`, limit.ID); n != 2 {
		t.Fatalf("the Stop released an in-flight hold: reserved = %d", n)
	}

	// Read-back after Stop still settles what may have reached the provider.
	fake.set(nil, nil)
	f.passFence(dispatched.ID)
	observed, _, err := svc.Observe(ctx, workload, dispatched.ID)
	must(t, err)
	wantState(t, "sent write read-back", observed, "OBSERVED", "")
	if observed.Outcome != "SUCCEEDED" || observed.Exposures[0].Kind != "confirmed" {
		t.Fatalf("sent write not settled: %+v", observed)
	}
	out, err = svc.StopOutcome(ctx, operator, stop.ID)
	must(t, err)
	wantAttemptIDs(t, "one action still being checked", out.CheckingAttemptIDs, unknown.ID)
	reconciled, _, err := svc.Observe(ctx, workload, unknown.ID)
	must(t, err)
	wantState(t, "unknown write read-back", reconciled, "RECONCILED", "")
	if reconciled.Outcome != "SUCCEEDED" || reconciled.Exposures[0].Kind != "confirmed" {
		t.Fatalf("unknown write not settled: %+v", reconciled)
	}
	out, err = svc.StopOutcome(ctx, operator, stop.ID)
	must(t, err)
	wantAttemptIDs(t, "resolved actions", out.CheckingAttemptIDs)
	wantAttemptIDs(t, "voided pre-claim action", out.VoidedAtClaimAttemptIDs, awaiting.ID)
	if fake.dispatched.Load() != providerCalls {
		t.Fatal("a read-back sent a provider write again")
	}
	if n := f.count(tenantA, `SELECT reserved FROM authority_counters WHERE limit_id = $1`, limit.ID); n != 0 {
		t.Fatalf("reserved after read-back = %d", n)
	}
	if n := f.count(tenantA, `SELECT used FROM authority_counters WHERE limit_id = $1`, limit.ID); n != 2 {
		t.Fatalf("used after read-back = %d", n)
	}
	f.ledgerBalances()
}

func TestPostgresPrincipalStopOutcomeScopeAndHumanReview(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	fake := &scripted{}
	fake.set(func(adapters.Effect) adapters.DispatchResult {
		return adapters.DispatchResult{Status: adapters.DispatchIndefinite}
	}, nil)
	svc := f.withAdapter(fake)
	a := f.propose(human, note("stop-review"))
	_, _, err := svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	stop, _, err := svc.Stop(ctx, operator, stopToken(), principalStop("stop-review-scope", human.PrincipalID))
	must(t, err)
	resolved, _, err := f.svc.Reconcile(ctx, tenantA, workspace, a.ID, true)
	must(t, err)
	if !resolved {
		t.Fatal("final read-back did not hand the uncertain write to a human")
	}
	out, err := svc.StopOutcome(ctx, operator, stop.ID)
	must(t, err)
	wantAttemptIDs(t, "human review", out.HumanReviewAttemptIDs, a.ID)
	wantAttemptIDs(t, "automatic checking", out.CheckingAttemptIDs)
	_, err = svc.StopOutcome(ctx, Caller{TenantID: tenantB, WorkspaceID: workspace, PrincipalID: operator.PrincipalID}, stop.ID)
	wantRefusal(t, "another tenant", err, CodeNotFound, "")
	otherWorkspace := operator
	otherWorkspace.WorkspaceID = "another-workspace"
	out, err = svc.StopOutcome(ctx, otherWorkspace, stop.ID)
	must(t, err)
	wantAttemptIDs(t, "another workspace", out.HumanReviewAttemptIDs)
	episode := operator
	episode.Episode = &Episode{EpisodeID: "episode-1", WorkItemID: "work-1"}
	_, err = svc.StopOutcome(ctx, episode, stop.ID)
	wantRefusal(t, "an episode token", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	_, err = svc.StopOutcome(ctx, operator, "not-a-uuid")
	wantRefusal(t, "invalid stop ID", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	tenantWide, _, err := svc.Stop(ctx, operator, stopToken(), tenantStop("stop-unsupported"))
	must(t, err)
	_, err = svc.StopOutcome(ctx, operator, tenantWide.ID)
	wantRefusal(t, "unsupported scope", err, CodeFailedPrecondition, "")
	// A lifted stop reports its persisted state rather than claiming to fence.
	f.exec(tenantA, `UPDATE authority_stops SET expires_at = now() + interval '1 millisecond' WHERE stop_id = $1`, stop.ID)
	// Expiry avoids manufacturing a lift approval receipt in this test.
	time.Sleep(10 * time.Millisecond)
	out, err = svc.StopOutcome(ctx, operator, stop.ID)
	must(t, err)
	if out.Active {
		t.Fatal("an expired principal Stop still reports active")
	}
}
