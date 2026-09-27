package admission

// HELM-751 s2 part (b) against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): Approve, Reject and Cancel, single-use
// decide and stop tokens, and re-admission on approval.

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

var approverB = Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-b", ActorID: actor}

var jtiCounter atomic.Int64

// decideToken is a fresh single-use token for scope.
func decideToken(scope string) Token {
	return Token{Issuer: "https://control-plane.test", ID: fmt.Sprintf("jti-%d", jtiCounter.Add(1)), Scope: scope, ExpiresAt: time.Now().Add(2 * time.Minute)}
}

// escalated proposes the skeleton's draft pull request, which the mandate
// escalates, over an observed branch.
func (f *fixture) escalated(key string) Attempt {
	f.t.Helper()
	branch := f.propose(human, proposal(key+"-branch", effectargs.GitHubBranchCreateFromChanges, repo, branchArgs("helm/"+key)))
	f.observeBranch(branch.ID, commitSHA)
	in := proposal(key, effectargs.GitHubPullRequestCreateDraft, repo, draftArgs(branch.ID, "helm/"+key, commitSHA))
	in.Quote = []Amount{{Unit: "effects", Amount: 1}}
	a := f.propose(human, in)
	wantState(f.t, "escalation", a, "ESCALATED", contracts.ReasonApprovalRequired)
	return a
}

func approval(a Attempt, reason string) DecideInput {
	return DecideInput{AttemptID: a.ID, ApprovalDigest: a.ApprovalDigest, Reason: reason}
}

func TestPostgresApproveByADistinctHumanAdmits(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, err := f.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &f.mandate.ID, Unit: "effects", Measure: "sum", Window: "day", Value: 10, Span: 1})
	must(t, err)
	a := f.escalated("pr1")
	if a.Permit != nil || len(a.Exposures) != 0 {
		t.Fatal("an escalated attempt holds a permit or a reservation")
	}
	approved, existing, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(a, "looks right"))
	must(t, err)
	wantState(t, "approved", approved, "ADMITTED", "")
	if existing || approved.Permit == nil || len(approved.Exposures) != 1 || approved.Exposures[0].Kind != "held" || approved.Exposures[0].Amount != 1 {
		t.Fatalf("re-admission = %+v", approved)
	}
	ap := approved.Approval
	if ap == nil || ap.ApproverPrincipalID != "human-b" || ap.ApproverActorID != actor || ap.Decision != "APPROVED" ||
		string(ap.ApprovalDigest) != string(a.ApprovalDigest) || ap.Reason != "looks right" {
		t.Fatalf("approval record = %+v", ap)
	}
	// An attempt no longer ESCALATED is returned unchanged.
	again, existing, err := f.svc.Approve(ctx, Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-c", ActorID: actor},
		decideToken("helm.gateway.decide"), approval(a, ""))
	must(t, err)
	if !existing || again.Version != approved.Version || again.Approval.ApproverPrincipalID != "human-b" {
		t.Fatalf("a second approval = %+v existing=%v", again, existing)
	}
}

func TestPostgresApprovalPreconditionsLeaveTheAttemptEscalated(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.escalated("pr1")
	unchanged := func(what string) {
		t.Helper()
		got, err := f.svc.Get(ctx, human, a.ID)
		must(t, err)
		if got.State != "ESCALATED" || got.Version != a.Version || got.Approval != nil {
			t.Fatalf("%s changed the attempt: %+v", what, got)
		}
	}
	token := decideToken("helm.gateway.decide")
	_, _, err := f.svc.Approve(ctx, human, token, approval(a, ""))
	wantRefusal(t, "self-approval", err, CodePermissionDenied, contracts.ReasonApproverNotDistinct)
	unchanged("self-approval")
	// The refused call used nothing up: the token still works for a proper
	// approver of the same attempt (the binding to the attempt is the
	// server's check, TestDecisionBinding).
	agent := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a"}
	_, _, err = f.svc.Approve(ctx, agent, decideToken("helm.gateway.decide"), approval(a, ""))
	wantRefusal(t, "an agent approver", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	unchanged("an agent approver")
	ghost := approverB
	ghost.PrincipalID = "ghost"
	_, _, err = f.svc.Approve(ctx, ghost, decideToken("helm.gateway.decide"), approval(a, ""))
	wantRefusal(t, "an unknown approver", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	wrong := approval(a, "")
	wrong.ApprovalDigest = make([]byte, 32)
	_, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), wrong)
	wantRefusal(t, "another digest", err, CodeFailedPrecondition, "")
	unchanged("another digest")
	_, _, err = f.svc.Reject(ctx, approverB, decideToken("helm.gateway.decide"), approval(a, ""))
	wantRefusal(t, "a rejection without a reason", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	unchanged("a rejection without a reason")

	// Known good after all that: the same distinct human approves.
	approved, _, err := f.svc.Approve(ctx, approverB, token, approval(a, ""))
	must(t, err)
	wantState(t, "approved after refusals", approved, "ADMITTED", "")
}

func TestPostgresDecideAndStopTokensAreSingleUse(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.escalated("pr1")
	b := f.escalated("pr2")
	token := decideToken("helm.gateway.decide")
	_, _, err := f.svc.Approve(ctx, approverB, token, approval(a, ""))
	must(t, err)
	_, _, err = f.svc.Approve(ctx, approverB, token, approval(b, ""))
	wantRefusal(t, "a reused decide token", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	if got, _ := f.svc.Get(ctx, human, b.ID); got.State != "ESCALATED" {
		t.Fatalf("a replayed token changed another attempt: %s", got.State)
	}
	// The replay row lives in Postgres: a second Service over the same
	// database refuses the jti too.
	other, err := New(f.runtime, Config{})
	must(t, err)
	_, _, err = other.Approve(ctx, approverB, token, approval(b, ""))
	wantRefusal(t, "a reused token on another gateway process", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	if n := f.count(tenantA, `SELECT count(*) FROM authority_token_replay WHERE jti = $1`, token.ID); n != 1 {
		t.Fatalf("%d replay rows for one jti", n)
	}
	// A token that carries no jti is refused.
	noJTI := decideToken("helm.gateway.decide")
	noJTI.ID = ""
	_, _, err = f.svc.Approve(ctx, approverB, noJTI, approval(b, ""))
	wantRefusal(t, "a token without a jti", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	// Stop tokens on Cancel are single-use too.
	stop := decideToken("helm.gateway.stop")
	_, _, err = f.svc.Cancel(ctx, approverB, stop, b.ID)
	must(t, err)
	c := f.escalated("pr3")
	_, _, err = f.svc.Cancel(ctx, approverB, stop, c.ID)
	wantRefusal(t, "a reused stop token", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	// Expired rows are purged once past exp plus the skew allowance.
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE authority_token_replay SET expires_at = now() - interval '1 minute'`)
		return err
	})
	_, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(c, ""))
	must(t, err)
	if n := f.count(tenantA, `SELECT count(*) FROM authority_token_replay`); n != 1 {
		t.Fatalf("%d replay rows after the purge, want only the newest", n)
	}
}

func TestPostgresApproveRereadsStopsAndTheMandate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.escalated("stopped")
	stop, err := f.rows.Stop(ctx, tenantA, authorityrows.StopSpec{Scope: authorityrows.Scope{Kind: authorityrows.ScopeEffectType, Key: effectargs.GitHubPullRequestCreateDraft}, Reason: "incident", IssuedBy: "human-c"})
	must(t, err)
	got, _, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(a, ""))
	must(t, err)
	wantState(t, "a stop issued before the approval", got, "DENIED", contracts.ReasonEmergencyStopFenced)
	if got.Permit != nil || got.Approval == nil {
		t.Fatalf("stopped re-admission = %+v", got)
	}
	must(t, f.rows.Lift(ctx, tenantA, stop.ID, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-c"}))

	b := f.escalated("revoked")
	must(t, f.rows.Revoke(ctx, tenantA, f.mandate.ID))
	got, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(b, ""))
	must(t, err)
	wantState(t, "a mandate revoked before the approval", got, "DENIED", contracts.ReasonMandateInactive)
}

func TestPostgresStepUpAndExpiryFailClosed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// A high-risk effect escalates by its risk class, and its approval needs
	// the step-up assertion that does not exist yet.
	must(t, f.rows.CreateEffectType(ctx, tenantA, "github.pull_request.merge", authorityrows.RiskHigh))
	terms := skeletonTerms(f.now)
	terms.EffectTypes = append(terms.EffectTypes, "github.pull_request.merge")
	terms.Condition = ""
	f.rootMandate(tenantA, "human-c", terms)
	requester := human
	requester.PrincipalID = "human-c"
	merge := f.propose(requester, proposal("merge-1", "github.pull_request.merge", repo, []byte(`{"merge_method":"squash"}`)))
	wantState(t, "high risk", merge, "ESCALATED", contracts.ReasonApprovalRequired)
	_, _, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(merge, ""))
	wantRefusal(t, "a high-risk approval without step-up", err, CodePermissionDenied, contracts.ReasonStepUpRequired)
	// A rejection needs no step-up.
	rejected, _, err := f.svc.Reject(ctx, approverB, decideToken("helm.gateway.decide"), approval(merge, "not now"))
	must(t, err)
	wantState(t, "rejected", rejected, "REJECTED", contracts.ReasonApprovalRejected)
	if rejected.Approval == nil || rejected.Approval.Decision != "REJECTED" || rejected.Approval.Reason != "not now" {
		t.Fatalf("rejection record = %+v", rejected.Approval)
	}
	// An expired escalation is refused.
	a := f.escalated("late")
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE authority_effect_attempts SET approval_expires_at = now() - interval '1 second' WHERE attempt_id = $1`, a.ID)
		return err
	})
	_, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(a, ""))
	wantRefusal(t, "an expired escalation", err, CodeFailedPrecondition, contracts.ReasonApprovalTimeout)
}

// quotaNote is a note that loads one unit of the "notes" limit.
func quotaNote(key string) ProposeInput {
	in := note(key)
	in.Quote = []Amount{{Unit: "notes", Amount: 1}}
	return in
}

func TestPostgresCancelReleasesAndFollowsTheAllowedEdges(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, err := f.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &f.mandate.ID, Unit: "notes", Measure: "sum", Window: "day", Value: 1, Span: 1})
	must(t, err)
	propose := decideToken("helm.gateway.propose")
	admitted := f.propose(human, quotaNote("n1"))
	wantState(t, "admitted", admitted, "ADMITTED", "")
	wantState(t, "the limit is held", f.propose(human, quotaNote("n2")), "DENIED", contracts.ReasonBudgetExceeded)

	// Another principal's propose token cannot cancel it.
	_, _, err = f.svc.Cancel(ctx, approverB, decideToken("helm.gateway.propose"), admitted.ID)
	wantRefusal(t, "another principal's propose token", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	// A read or decide token cannot either.
	_, _, err = f.svc.Cancel(ctx, human, decideToken("helm.gateway.decide"), admitted.ID)
	wantRefusal(t, "a decide token", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)

	cancelled, existing, err := f.svc.Cancel(ctx, human, propose, admitted.ID)
	must(t, err)
	if existing || cancelled.State != "CANCELLED" || cancelled.ReasonCode != "" || cancelled.Exposures[0].Kind != "released" || cancelled.Exposures[0].Amount != 0 {
		t.Fatalf("cancelled = %+v", cancelled)
	}
	if n := f.count(tenantA, `SELECT count(*) FROM authority_permits WHERE attempt_id = $1 AND voided_at IS NOT NULL AND consumed_at IS NULL`, admitted.ID); n != 1 {
		t.Fatal("the permit was not voided")
	}
	if r := f.count(tenantA, `SELECT COALESCE(sum(reserved), 0)::int FROM authority_counters`); r != 0 {
		t.Fatalf("reserved = %d after the release", r)
	}
	if bad := f.count(tenantA, `SELECT count(*) FROM (
			SELECT e.attempt_id FROM authority_exposures e LEFT JOIN authority_postings p USING (tenant_id, attempt_id, limit_id, bucket_start)
			GROUP BY e.tenant_id, e.attempt_id, e.limit_id, e.bucket_start, e.amount HAVING COALESCE(sum(p.amount), 0) <> e.amount) x`); bad != 0 {
		t.Fatalf("%d exposures disagree with their postings", bad)
	}
	// The released limit admits again.
	wantState(t, "after the release", f.propose(human, quotaNote("n3")), "ADMITTED", "")
	// Cancelling again is idempotent.
	again, existing, err := f.svc.Cancel(ctx, human, decideToken("helm.gateway.propose"), admitted.ID)
	must(t, err)
	if !existing || again.Version != cancelled.Version {
		t.Fatalf("a second cancel = %+v existing=%v", again, existing)
	}

	// ESCALATED -> CANCELLED by an operator's stop token.
	e := f.escalated("pr1")
	opCancelled, _, err := f.svc.Cancel(ctx, approverB, decideToken("helm.gateway.stop"), e.ID)
	must(t, err)
	wantState(t, "operator cancel", opCancelled, "CANCELLED", "")
	agent := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a"}
	e2 := f.escalated("pr2")
	_, _, err = f.svc.Cancel(ctx, agent, decideToken("helm.gateway.stop"), e2.ID)
	wantRefusal(t, "an agent operator", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	// Approving a cancelled attempt returns it unchanged.
	_, existing, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(e, ""))
	must(t, err)
	if !existing {
		t.Fatal("approving a cancelled attempt changed it")
	}

	// DISPATCHING or later cannot be cancelled.
	dispatched := f.propose(human, quotaNote("n4"))
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE authority_effect_attempts SET state = 'DISPATCHING' WHERE attempt_id = $1`, dispatched.ID)
		return err
	})
	_, _, err = f.svc.Cancel(ctx, human, decideToken("helm.gateway.propose"), dispatched.ID)
	wantRefusal(t, "a dispatching attempt", err, CodeFailedPrecondition, "")
	_, _, err = f.svc.Cancel(ctx, human, decideToken("helm.gateway.propose"), uuid.NewString())
	wantRefusal(t, "a missing attempt", err, CodeNotFound, "")
}

func TestPostgresConcurrentApprovalsAdmitOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.escalated("race")
	approvers := []Caller{approverB, {TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-c", ActorID: actor}}
	var wg sync.WaitGroup
	fresh := make([]bool, 8)
	errs := make([]error, 8)
	for i := range fresh {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, existing, err := f.svc.Approve(ctx, approvers[i%2], decideToken("helm.gateway.decide"), approval(a, ""))
			fresh[i], errs[i] = !existing, err
		}()
	}
	wg.Wait()
	decided := 0
	for i := range fresh {
		must(t, errs[i])
		if fresh[i] {
			decided++
		}
	}
	if decided != 1 {
		t.Fatalf("%d approvals decided the attempt, want 1", decided)
	}
	if n := f.count(tenantA, `SELECT count(*) FROM authority_approvals WHERE attempt_id = $1`, a.ID); n != 1 {
		t.Fatalf("%d approval rows", n)
	}
	if n := f.count(tenantA, `SELECT count(*) FROM authority_permits WHERE attempt_id = $1`, a.ID); n != 1 {
		t.Fatalf("%d permits", n)
	}
}

// L2: step-up follows the risk re-admission computes, not the risk stored at
// escalation.
func TestPostgresStepUpFollowsARiskRaisedAfterEscalation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.escalated("raised")
	if a.RiskClass != "medium" {
		t.Fatalf("escalated at %s, want medium", a.RiskClass)
	}
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE authority_effect_types SET risk_class = 'high', version = version + 1
			WHERE tenant_id = $1 AND effect_type = $2`, tenantA, effectargs.GitHubPullRequestCreateDraft)
		return err
	})
	_, _, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(a, ""))
	wantRefusal(t, "a risk raised to high after escalation", err, CodePermissionDenied, contracts.ReasonStepUpRequired)
	got, err := f.svc.Get(ctx, human, a.ID)
	must(t, err)
	if got.State != "ESCALATED" || got.Approval != nil || got.Version != a.Version {
		t.Fatalf("a refused step-up changed the attempt: %+v", got)
	}
	// Known good: back at medium, the same approval admits.
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE authority_effect_types SET risk_class = 'medium', version = version + 1
			WHERE tenant_id = $1 AND effect_type = $2`, tenantA, effectargs.GitHubPullRequestCreateDraft)
		return err
	})
	approved, _, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(a, ""))
	must(t, err)
	wantState(t, "medium again", approved, "ADMITTED", "")
}

// L1: a token the purge could already have forgotten is refused by the
// database clock, so skew between the gateway and the database never makes
// an accepted decide token replayable.
func TestPostgresSingleUseSurvivesClockSkew(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.escalated("skew-a")
	b := f.escalated("skew-b")
	var dbNow time.Time
	must(t, f.owner.QueryRow(`SELECT now()`).Scan(&dbNow))
	// A gateway clock 60 s behind the database accepts this token (exp plus
	// 30 s is still ahead of it); the database's purge would forget its row.
	skewed := decideToken("helm.gateway.decide")
	skewed.ExpiresAt = dbNow.Add(-40 * time.Second)
	for i, target := range []Attempt{a, b} {
		_, _, err := f.svc.Approve(ctx, approverB, skewed, approval(target, ""))
		wantRefusal(t, fmt.Sprintf("use %d of a token past exp plus skew by the database clock", i+1), err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	// Inside the window it is accepted once, and its row outlives any purge
	// that could still accept it.
	edge := decideToken("helm.gateway.decide")
	edge.ExpiresAt = dbNow.Add(-20 * time.Second)
	_, _, err := f.svc.Approve(ctx, approverB, edge, approval(a, ""))
	must(t, err)
	_, _, err = f.svc.Approve(ctx, approverB, edge, approval(b, ""))
	wantRefusal(t, "a replay inside the window", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	if got, _ := f.svc.Get(ctx, human, b.ID); got.State != "ESCALATED" {
		t.Fatalf("a replayed token decided another attempt: %s", got.State)
	}
}
