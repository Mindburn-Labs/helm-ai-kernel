package admission

// HELM-751 s3 against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): the dispatch claim, Dispatch and Observe,
// with a scripted adapter in place of a provider.
//
// quantum_posture: computes SHA-256 digests to compare with stored ones;
// signs nothing.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

// workload is the Control Plane runner's execute identity: the service
// principal the skeleton's human proposes through (its act.sub), never a
// human.
var workload = Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: actor}

// scripted is an adapter whose answers the test sets. By default Dispatch
// checks the permit digest and is SENT, and Observe is SUCCEEDED with the
// effect type's typed result.
type scripted struct {
	mu         sync.Mutex
	dispatch   func(adapters.Effect) adapters.DispatchResult
	observe    func(adapters.Effect) adapters.ObserveResult
	dispatched atomic.Int32
	observed   atomic.Int32
	tokens     []string
}

func (s *scripted) Declarations() []adapters.Declaration {
	var out []adapters.Declaration
	for _, t := range []string{noteType, effectargs.GitHubBranchCreateFromChanges, effectargs.GitHubPullRequestCreateDraft, effectargs.GitHubRepositoryGet} {
		out = append(out, adapters.Declaration{EffectType: t, Idempotent: adapters.IdempotentConditional, Observable: adapters.ObservableYes})
	}
	return out
}

func (s *scripted) Prepare(context.Context, adapters.TokenSource, adapters.Effect) (*adapters.Preparation, error) {
	return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "not used")
}

func (s *scripted) Dispatch(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect, digest []byte) adapters.DispatchResult {
	s.dispatched.Add(1)
	if r := adapters.CheckPermitDigest(effect.Arguments, digest); r != nil {
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: r.Reason, Detail: r.Detail}
	}
	token, err := creds.Token(ctx)
	if err != nil {
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: contracts.ReasonProviderCredentialRejected, Detail: err.Error()}
	}
	s.mu.Lock()
	s.tokens = append(s.tokens, token)
	fn := s.dispatch
	s.mu.Unlock()
	if fn != nil {
		return fn(effect)
	}
	return adapters.DispatchResult{Status: adapters.DispatchSent}
}

func (s *scripted) Observe(_ context.Context, _ adapters.TokenSource, effect adapters.Effect) adapters.ObserveResult {
	s.observed.Add(1)
	s.mu.Lock()
	fn := s.observe
	s.mu.Unlock()
	if fn != nil {
		return fn(effect)
	}
	return succeeded(effect)
}

func (s *scripted) set(dispatch func(adapters.Effect) adapters.DispatchResult, observe func(adapters.Effect) adapters.ObserveResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dispatch, s.observe = dispatch, observe
}

// succeeded is a read-back that establishes SUCCEEDED with the effect
// type's typed result.
func succeeded(effect adapters.Effect) adapters.ObserveResult {
	evidence := sha256.Sum256([]byte("provider bytes"))
	o := &adapters.Observation{Source: "fake.readback", TrustClass: "provider_readback", EvidenceDigest: evidence[:]}
	switch effect.EffectType {
	case effectargs.GitHubBranchCreateFromChanges:
		o.GitHubBranch = &adapters.GitHubBranchResult{Ref: "refs/heads/helm/x", CommitSHA: commitSHA,
			BaseSHA: "0123456789abcdef0123456789abcdef01234567", FilesDigest: evidence[:]}
	case effectargs.GitHubPullRequestCreateDraft:
		o.GitHubPullRequest = &adapters.GitHubPullRequestResult{URL: "https://github.com/Mindburn-Labs/example/pull/7", Number: 7, Draft: true, State: "open"}
	case effectargs.GitHubRepositoryGet:
		o.GitHubRepository = &adapters.GitHubRepositoryResult{DefaultBranch: "main", DefaultBranchSHA: commitSHA}
	}
	return adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded, Observation: o}
}

// absent is a read-back that finds no object the effect would create.
func absent(effect adapters.Effect) adapters.ObserveResult {
	r := succeeded(effect)
	r.Outcome, r.Reason, r.Absent = adapters.OutcomeFailed, contracts.ReasonReadbackMismatch, true
	return r
}

// contradicted is a read-back that finds an object that is not this effect.
func contradicted(effect adapters.Effect) adapters.ObserveResult {
	r := succeeded(effect)
	r.Outcome, r.Reason = adapters.OutcomeFailed, contracts.ReasonReadbackMismatch
	return r
}

type fakeCredentials struct{}

func (fakeCredentials) Token(_ context.Context, tenantID string, effect adapters.Effect) (string, error) {
	return "token-for-" + tenantID + "-" + effect.EffectType, nil
}

// withAdapter returns a Service over the fixture's runtime role that
// dispatches through a.
func (f *fixture) withAdapter(a adapters.Adapter) *Service {
	f.t.Helper()
	svc, err := New(f.runtime, Config{Adapters: []adapters.Adapter{a}, Credentials: fakeCredentials{}})
	must(f.t, err)
	return svc
}

// notesLimit adds a daily "notes" limit of value to the skeleton mandate.
func (f *fixture) notesLimit(value int64) authorityrows.Limit {
	f.t.Helper()
	l, err := f.rows.CreateLimit(context.Background(), tenantA, authorityrows.LimitSpec{MandateID: &f.mandate.ID, Unit: "notes", Measure: "sum", Window: "day", Value: value, Span: 1})
	must(f.t, err)
	return l
}

// ledgerBalances fails unless every counter carries exactly its current
// exposures (reserved = sum of held, used = sum of confirmed) and every
// exposure equals the sum of its postings (ADR-0003 S-I1).
func (f *fixture) ledgerBalances() {
	f.t.Helper()
	if bad := f.count(tenantA, `SELECT count(*) FROM authority_counters c WHERE
			c.reserved <> COALESCE((SELECT sum(amount) FROM authority_exposures e WHERE e.tenant_id = c.tenant_id AND e.limit_id = c.limit_id AND e.bucket_start = c.bucket_start AND kind = 'held'), 0)
			OR c.used <> COALESCE((SELECT sum(amount) FROM authority_exposures e WHERE e.tenant_id = c.tenant_id AND e.limit_id = c.limit_id AND e.bucket_start = c.bucket_start AND kind IN ('estimated', 'confirmed')), 0)`); bad != 0 {
		f.t.Fatalf("%d counters disagree with their exposures", bad)
	}
	if bad := f.count(tenantA, `SELECT count(*) FROM (
			SELECT e.attempt_id FROM authority_exposures e LEFT JOIN authority_postings p USING (tenant_id, attempt_id, limit_id, bucket_start)
			GROUP BY e.tenant_id, e.attempt_id, e.limit_id, e.bucket_start, e.amount HAVING COALESCE(sum(p.amount), 0) <> e.amount) x`); bad != 0 {
		f.t.Fatalf("%d exposures disagree with their postings", bad)
	}
}

func (f *fixture) exec(tenant, query string, args ...any) {
	f.t.Helper()
	f.ownerTx(tenant, func(tx *sql.Tx) error {
		_, err := tx.Exec(query, args...)
		return err
	})
}

func wantOutcome(t *testing.T, what string, a Attempt, state, outcome string, reason contracts.ReasonCode) {
	t.Helper()
	if a.State != state || a.Outcome != outcome || a.ReasonCode != string(reason) {
		t.Fatalf("%s: attempt is %s(%s) %q, want %s(%s) %q", what, a.State, a.Outcome, a.ReasonCode, state, outcome, reason)
	}
}

func TestPostgresDispatchClaimsThePermitOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.notesLimit(5)
	fake := &scripted{}
	svc := f.withAdapter(fake)
	admitted := f.propose(human, quotaNote("n1"))
	wantState(t, "admitted", admitted, "ADMITTED", "")

	// Concurrent Dispatch of one attempt: one claim, one provider call.
	var wg sync.WaitGroup
	var fresh atomic.Int32
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, existing, err := svc.Dispatch(ctx, workload, admitted.ID)
			if err != nil {
				errs <- err
				return
			}
			if !existing {
				fresh.Add(1)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := fake.dispatched.Load(); n != 1 || fresh.Load() != 1 {
		t.Fatalf("%d provider calls and %d fresh answers from 8 concurrent dispatches, want 1 and 1", n, fresh.Load())
	}
	got, err := svc.Get(ctx, human, admitted.ID)
	must(t, err)
	wantOutcome(t, "dispatched and read back", got, "OBSERVED", "SUCCEEDED", "")
	if got.OutcomeBasis != "OBSERVED" || got.Permit.ConsumedAt == nil || got.Permit.ClaimID == "" ||
		len(got.Exposures) != 1 || got.Exposures[0].Kind != "confirmed" || got.Exposures[0].Amount != 1 {
		t.Fatalf("settled attempt = %+v", got)
	}
	if o := got.LatestObservation; o == nil || o.Outcome != "SUCCEEDED" || o.Source != "fake.readback" || len(o.EvidenceDigest) != 32 || o.ResultRef != "" {
		t.Fatalf("observation = %+v", o)
	}
	if fake.tokens[0] != "token-for-tenant-a-ops.note" {
		t.Fatalf("the adapter was handed %q, not the custody's credential for this tenant and effect", fake.tokens[0])
	}
	if used := f.count(tenantA, `SELECT COALESCE(sum(used), 0)::int FROM authority_counters`); used != 1 {
		t.Fatalf("used = %d after a confirmed effect, want 1", used)
	}
	f.ledgerBalances()

	// Repeating Dispatch or Observe changes nothing and calls nothing.
	again, existing, err := svc.Dispatch(ctx, workload, admitted.ID)
	must(t, err)
	if !existing || again.Version != got.Version {
		t.Fatalf("a repeated Dispatch = %+v existing=%v", again, existing)
	}
	observed, existing, err := svc.Observe(ctx, workload, admitted.ID)
	must(t, err)
	if !existing || observed.Version != got.Version || fake.dispatched.Load() != 1 || fake.observed.Load() != 1 {
		t.Fatalf("a repeated Observe = %+v existing=%v; %d dispatches, %d reads", observed, existing, fake.dispatched.Load(), fake.observed.Load())
	}
}

func TestPostgresPermitIsConsumedOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	fake := &scripted{}
	svc := f.withAdapter(fake)
	a := f.propose(human, note("n1"))
	_, _, err := svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	// Replay: the attempt is put back to ADMITTED, as if the claim had never
	// committed. Its permit is consumed, so no second claim can use it.
	f.exec(tenantA, `UPDATE authority_effect_attempts SET state = 'ADMITTED', outcome = NULL, outcome_basis = NULL WHERE attempt_id = $1`, a.ID)
	_, _, err = svc.Dispatch(ctx, workload, a.ID)
	wantRefusal(t, "a replayed claim", err, CodeFailedPrecondition, "")
	if n := fake.dispatched.Load(); n != 1 {
		t.Fatalf("%d provider calls; a consumed permit was used again", n)
	}
	// A voided permit is refused the same way.
	b := f.propose(human, note("n2"))
	f.exec(tenantA, `UPDATE authority_permits SET voided_at = now() WHERE attempt_id = $1`, b.ID)
	_, _, err = svc.Dispatch(ctx, workload, b.ID)
	wantRefusal(t, "a voided permit", err, CodeFailedPrecondition, "")
	if n := fake.dispatched.Load(); n != 1 {
		t.Fatalf("%d provider calls; a voided permit was used", n)
	}
}

// claimOnly commits the dispatch claim and never calls the adapter: a
// gateway that dies between the claim and the provider call.
func (f *fixture) claimOnly(svc *Service, attemptID string) {
	f.t.Helper()
	ctx := context.Background()
	must(f.t, svc.inTenant(ctx, tenantA, func(tx *sql.Tx) error {
		a, err := lockAttempt(ctx, tx, workload, attemptID)
		if err != nil {
			return err
		}
		c, err := svc.claim(ctx, tx, a, workload)
		if err == nil && c == nil {
			f.t.Fatal("the claim was refused")
		}
		return err
	}))
}

func TestPostgresCrashAfterTheClaimIsReconciledNeverResent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.notesLimit(5)
	fake := &scripted{}
	svc := f.withAdapter(fake)

	a := f.propose(human, quotaNote("crash-1"))
	f.claimOnly(svc, a.ID)
	got, err := svc.Get(ctx, human, a.ID)
	must(t, err)
	if got.State != "DISPATCHING" || got.Permit.ConsumedAt == nil || got.Exposures[0].Kind != "held" {
		t.Fatalf("after the claim = %+v", got)
	}
	// Dispatch again: the permit is spent, nothing is sent.
	again, existing, err := svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	if !existing || again.State != "DISPATCHING" {
		t.Fatalf("Dispatch after a crash = %s existing=%v", again.State, existing)
	}
	// Before the fence the dispatch may still be in flight: Observe waits.
	early, existing, err := svc.Observe(ctx, workload, a.ID)
	must(t, err)
	if !existing || early.State != "DISPATCHING" || fake.observed.Load() != 0 {
		t.Fatalf("Observe inside the fence = %s existing=%v, %d reads", early.State, existing, fake.observed.Load())
	}
	// After the fence it is UNKNOWN and reconciled by read-back: nothing
	// was written, so the read-back finds nothing and the hold is released.
	f.exec(tenantA, `UPDATE authority_effect_attempts SET dispatch_deadline = now() - interval '1 second' WHERE attempt_id = $1`, a.ID)
	fake.set(nil, absent)
	reconciled, existing, err := svc.Observe(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "a crashed dispatch", reconciled, "RECONCILED", "FAILED", contracts.ReasonReadbackMismatch)
	if existing || reconciled.OutcomeBasis != "RECONCILED" || reconciled.Exposures[0].Kind != "released" {
		t.Fatalf("reconciled = %+v", reconciled)
	}

	// The other way round: the write had landed before the crash.
	b := f.propose(human, quotaNote("crash-2"))
	f.claimOnly(svc, b.ID)
	f.exec(tenantA, `UPDATE authority_effect_attempts SET dispatch_deadline = now() - interval '1 second' WHERE attempt_id = $1`, b.ID)
	fake.set(nil, nil)
	landed, _, err := svc.Observe(ctx, workload, b.ID)
	must(t, err)
	wantOutcome(t, "a crashed dispatch that landed", landed, "RECONCILED", "SUCCEEDED", "")
	if landed.Exposures[0].Kind != "confirmed" {
		t.Fatalf("exposure = %+v", landed.Exposures)
	}
	if n := fake.dispatched.Load(); n != 0 {
		t.Fatalf("%d provider calls; a claimed attempt was sent again", n)
	}
	f.ledgerBalances()
}

func TestPostgresLostResponseIsReconciledByObserve(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.notesLimit(5)
	fake := &scripted{}
	svc := f.withAdapter(fake)
	lost := func(adapters.Effect) adapters.DispatchResult {
		return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: contracts.ReasonProviderError, Detail: "502"}
	}
	inconclusive := func(adapters.Effect) adapters.ObserveResult {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: contracts.ReasonProviderError}
	}
	fake.set(lost, inconclusive)
	a := f.propose(human, quotaNote("lost"))
	dispatched, existing, err := svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "a lost answer", dispatched, "UNKNOWN", "", contracts.ReasonProviderError)
	if existing || dispatched.Exposures[0].Kind != "held" || fake.observed.Load() != 0 {
		t.Fatalf("UNKNOWN = %+v; %d reads (an indefinite dispatch is not read back at once)", dispatched, fake.observed.Load())
	}
	// An inconclusive read-back keeps it UNKNOWN and the hold in place.
	still, _, err := svc.Observe(ctx, workload, a.ID)
	must(t, err)
	if still.State != "UNKNOWN" || still.Exposures[0].Kind != "held" || still.LatestObservation != nil {
		t.Fatalf("after an inconclusive read-back = %+v", still)
	}
	fake.set(lost, nil)
	reconciled, existing, err := svc.Observe(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "reconciled", reconciled, "RECONCILED", "SUCCEEDED", "")
	if existing || reconciled.OutcomeBasis != "RECONCILED" || reconciled.Exposures[0].Kind != "confirmed" {
		t.Fatalf("reconciled = %+v", reconciled)
	}
	if n := fake.dispatched.Load(); n != 1 {
		t.Fatalf("%d provider calls; UNKNOWN was dispatched again", n)
	}
	f.ledgerBalances()
}

func TestPostgresNotSentIsObservedFailedAndReleased(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.notesLimit(1)
	fake := &scripted{}
	fake.set(func(adapters.Effect) adapters.DispatchResult {
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: contracts.ReasonPreconditionFailed, Detail: "head moved"}
	}, nil)
	svc := f.withAdapter(fake)
	a := f.propose(human, quotaNote("n1"))
	wantState(t, "the limit is held", f.propose(human, quotaNote("n2")), "DENIED", contracts.ReasonBudgetExceeded)
	failed, existing, err := svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "NOT_SENT", failed, "OBSERVED", "FAILED", contracts.ReasonPreconditionFailed)
	if existing || failed.OutcomeBasis != "OBSERVED" || failed.Exposures[0].Kind != "released" || failed.Exposures[0].Amount != 0 ||
		failed.LatestObservation == nil || failed.LatestObservation.Source != dispatchSource || fake.observed.Load() != 0 {
		t.Fatalf("NOT_SENT = %+v", failed)
	}
	if r := f.count(tenantA, `SELECT COALESCE(sum(reserved), 0)::int FROM authority_counters`); r != 0 {
		t.Fatalf("reserved = %d after a certain failure", r)
	}
	f.ledgerBalances()
	wantState(t, "the released limit admits again", f.propose(human, quotaNote("n3")), "ADMITTED", "")
	// No credential is NOT_SENT too, never UNKNOWN.
	bare, err := New(f.runtime, Config{Adapters: []adapters.Adapter{&scripted{}}})
	must(t, err)
	free := note("no-credential")
	free.Quote = []Amount{{Unit: "notes", Amount: 0}}
	b := f.propose(human, free)
	got, _, err := bare.Dispatch(ctx, workload, b.ID)
	must(t, err)
	wantOutcome(t, "no credential", got, "OBSERVED", "FAILED", contracts.ReasonProviderCredentialRejected)
}

func TestPostgresClaimRefusalsCancelAndRelease(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	limit := f.notesLimit(10)
	fake := &scripted{}
	svc := f.withAdapter(fake)
	refused := func(what string, id string, reason contracts.ReasonCode) {
		t.Helper()
		got, existing, err := svc.Dispatch(ctx, workload, id)
		must(t, err)
		wantState(t, what, got, "CANCELLED", reason)
		if existing || got.Permit.ConsumedAt != nil || got.Permit.VoidReasonCode != string(reason) ||
			(len(got.Exposures) > 0 && got.Exposures[0].Kind != "released") {
			t.Fatalf("%s: %+v", what, got)
		}
		if n := f.count(tenantA, `SELECT count(*) FROM authority_permits WHERE attempt_id = $1 AND voided_at IS NOT NULL`, id); n != 1 {
			t.Fatalf("%s: the permit was not voided", what)
		}
	}

	// A stop issued between approval and dispatch blocks the dispatch.
	pr := f.escalated("pr1")
	approved, _, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(pr, ""))
	must(t, err)
	wantState(t, "approved", approved, "ADMITTED", "")
	stop, err := f.rows.Stop(ctx, tenantA, authorityrows.StopSpec{Scope: authorityrows.Scope{Kind: authorityrows.ScopePrincipal, Key: "human-a"}, Reason: "incident", IssuedBy: "human-c"})
	must(t, err)
	refused("a stop after the approval", pr.ID, contracts.ReasonEmergencyStopFenced)
	must(t, f.rows.Lift(ctx, tenantA, stop.ID, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-c"}))

	// Any change to a row the permit was issued under.
	changed := f.propose(human, quotaNote("changed"))
	must(t, f.rows.LowerLimit(ctx, tenantA, limit.ID, 9))
	refused("a lowered limit", changed.ID, contracts.ReasonAuthorityChanged)
	revoked := f.propose(human, quotaNote("revoked"))
	child, err := f.rows.Delegate(ctx, tenantA, f.mandate.ID, "human-a", "human-c", skeletonTerms(f.now))
	must(t, err)
	must(t, f.rows.Revoke(ctx, tenantA, child.ID))
	wantState(t, "an unrelated mandate's revocation", func() Attempt {
		got, _, err := svc.Dispatch(ctx, workload, revoked.ID)
		must(t, err)
		return got
	}(), "OBSERVED", "")

	// An expired permit.
	expired := f.propose(human, quotaNote("expired"))
	f.exec(tenantA, `UPDATE authority_permits SET expires_at = now() - interval '1 second' WHERE attempt_id = $1`, expired.ID)
	refused("an expired permit", expired.ID, contracts.ReasonPermitExpired)

	// A mandate past its validity (the window ends without a version bump).
	late := f.propose(human, quotaNote("late"))
	f.exec(tenantA, `UPDATE authority_mandates SET valid_until = now() - interval '1 second', valid_from = now() - interval '2 hours' WHERE mandate_id = $1`, f.mandate.ID)
	refused("a mandate past its validity", late.ID, contracts.ReasonMandateOutsideValidity)
	f.exec(tenantA, `UPDATE authority_mandates SET valid_until = now() + interval '1 day' WHERE mandate_id = $1`, f.mandate.ID)

	// A stop on an unrelated effect type does not cancel.
	_, err = f.rows.Stop(ctx, tenantA, authorityrows.StopSpec{Scope: authorityrows.Scope{Kind: authorityrows.ScopeEffectType, Key: effectargs.GitHubPullRequestCreateDraft}, Reason: "x", IssuedBy: "human-c"})
	must(t, err)
	fine := f.propose(human, quotaNote("unrelated-stop"))
	got, _, err := svc.Dispatch(ctx, workload, fine.ID)
	must(t, err)
	wantOutcome(t, "an unrelated stop", got, "OBSERVED", "SUCCEEDED", "")

	if n := fake.dispatched.Load(); n != 2 {
		t.Fatalf("%d provider calls, want 2: a refused claim must not reach the adapter", n)
	}
	f.ledgerBalances()
}

func TestPostgresDispatchIsTenantWorkspaceAndWorkloadScoped(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	fake := &scripted{}
	svc := f.withAdapter(fake)
	a := f.propose(human, note("n1"))
	for name, caller := range map[string]Caller{
		"another tenant's workload":    {TenantID: tenantB, WorkspaceID: workspace, PrincipalID: actor},
		"another workspace's workload": {TenantID: tenantA, WorkspaceID: "ws-b", PrincipalID: actor},
	} {
		_, _, err := svc.Dispatch(ctx, caller, a.ID)
		wantRefusal(t, name+" dispatching", err, CodeNotFound, "")
		_, _, err = svc.Observe(ctx, caller, a.ID)
		wantRefusal(t, name+" observing", err, CodeNotFound, "")
	}
	for name, caller := range map[string]Caller{
		"a human":           human,
		"an unknown caller": {TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "ghost"},
	} {
		_, _, err := svc.Dispatch(ctx, caller, a.ID)
		wantRefusal(t, name+" dispatching", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
		_, _, err = svc.Observe(ctx, caller, a.ID)
		wantRefusal(t, name+" observing", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	e := f.escalated("pr1")
	_, _, err := svc.Dispatch(ctx, workload, e.ID)
	wantRefusal(t, "an escalated attempt", err, CodeFailedPrecondition, "")
	// A gateway without an adapter for the effect type does not claim.
	_, _, err = f.svc.Dispatch(ctx, workload, a.ID)
	wantRefusal(t, "no adapter", err, CodeFailedPrecondition, "")
	if got, _ := f.svc.Get(ctx, human, a.ID); got.State != "ADMITTED" || got.Permit.ConsumedAt != nil {
		t.Fatalf("a refused Dispatch changed the attempt: %+v", got)
	}
	if n := fake.dispatched.Load(); n != 0 {
		t.Fatalf("%d provider calls from refused dispatches", n)
	}
}

func TestPostgresObserveRecordsTheTypedResult(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	fake := &scripted{}
	svc := f.withAdapter(fake)
	branch := f.propose(human, proposal("b1", effectargs.GitHubBranchCreateFromChanges, repo, branchArgs("helm/b1")))
	got, _, err := svc.Dispatch(ctx, workload, branch.ID)
	must(t, err)
	wantOutcome(t, "branch", got, "OBSERVED", "SUCCEEDED", "")
	o := got.LatestObservation
	if o == nil || o.GitHubBranch == nil || o.GitHubBranch.CommitSHA != commitSHA || o.GitHubPullRequest != nil {
		t.Fatalf("observation = %+v", o)
	}
	// result_ref recomputes from the JSON Postgres returns: SHA-256 over its
	// JCS form, whatever JSONB did to the bytes.
	var stored, ref string
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT result::text, result_ref FROM authority_observations WHERE attempt_id = $1`, branch.ID).Scan(&stored, &ref)
	})
	canonical, err := canonicalize.JCS(json.RawMessage(stored))
	must(t, err)
	sum := sha256.Sum256(canonical)
	if o.ResultRef != ref || ref != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("result_ref %q is not SHA-256 of the stored result's JCS form %s", ref, canonical)
	}
	// The observed branch satisfies the draft pull request's precondition.
	in := proposal("pr1", effectargs.GitHubPullRequestCreateDraft, repo, draftArgs(branch.ID, "helm/b1", commitSHA))
	wantState(t, "the draft over an observed branch", f.propose(human, in), "ESCALATED", contracts.ReasonApprovalRequired)

	// A read-back whose typed result is not the effect type's breaks the
	// contract: inconclusive, UNKNOWN, nothing recorded.
	fake.set(nil, func(adapters.Effect) adapters.ObserveResult {
		return succeeded(adapters.Effect{EffectType: effectargs.GitHubPullRequestCreateDraft})
	})
	other := f.propose(human, proposal("b2", effectargs.GitHubBranchCreateFromChanges, repo, branchArgs("helm/b2")))
	got, _, err = svc.Dispatch(ctx, workload, other.ID)
	must(t, err)
	if got.State != "UNKNOWN" || got.LatestObservation != nil {
		t.Fatalf("a mismatched typed result = %+v", got)
	}
}

// passFence moves an attempt's dispatch fence into the past.
func (f *fixture) passFence(id string) {
	f.t.Helper()
	f.exec(tenantA, `UPDATE authority_effect_attempts SET dispatch_deadline = now() - interval '1 second' WHERE attempt_id = $1`, id)
}

// H1: a FAILED that rests on the object's absence is inconclusive until the
// dispatch fence has passed; the write may still land.
func TestPostgresAbsenceInsideTheFenceIsInconclusive(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.notesLimit(5)
	fake := &scripted{}
	svc := f.withAdapter(fake)

	// A lost answer, then an immediate read-back that finds nothing.
	fake.set(func(adapters.Effect) adapters.DispatchResult {
		return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: contracts.ReasonProviderError}
	}, absent)
	a := f.propose(human, quotaNote("lost"))
	_, _, err := svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	early, _, err := svc.Observe(ctx, workload, a.ID)
	must(t, err)
	if early.State != "UNKNOWN" || early.Exposures[0].Kind != "held" || early.LatestObservation != nil {
		t.Fatalf("absence inside the fence resolved an UNKNOWN attempt: %+v", early)
	}
	f.passFence(a.ID)
	late, _, err := svc.Observe(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "absence after the fence", late, "RECONCILED", "FAILED", contracts.ReasonReadbackMismatch)
	if late.Exposures[0].Kind != "released" {
		t.Fatalf("exposure = %+v", late.Exposures)
	}

	// SENT, and the read-back does not see the object yet.
	fake.set(nil, absent)
	b := f.propose(human, quotaNote("sent"))
	sent, _, err := svc.Dispatch(ctx, workload, b.ID)
	must(t, err)
	if sent.State != "DISPATCHED" || sent.Exposures[0].Kind != "held" {
		t.Fatalf("absence right after a SENT write = %+v", sent)
	}
	f.passFence(b.ID)
	observed, _, err := svc.Observe(ctx, workload, b.ID)
	must(t, err)
	wantOutcome(t, "absence after the fence", observed, "OBSERVED", "FAILED", contracts.ReasonReadbackMismatch)
	f.ledgerBalances()
}

// L4: an object that contradicts the effect after a SENT write means the
// write may well have happened: FAILED, and the reservation is consumed.
func TestPostgresContradictedReadBackConsumesTheReservation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.notesLimit(5)
	fake := &scripted{}
	fake.set(nil, contradicted)
	svc := f.withAdapter(fake)
	a := f.propose(human, quotaNote("differs"))
	got, _, err := svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "a contradicted read-back", got, "OBSERVED", "FAILED", contracts.ReasonReadbackMismatch)
	if got.Exposures[0].Kind != "confirmed" || got.Exposures[0].Amount != 1 {
		t.Fatalf("exposure = %+v, want the reservation consumed", got.Exposures)
	}
	if used := f.count(tenantA, `SELECT COALESCE(sum(used), 0)::int FROM authority_counters`); used != 1 {
		t.Fatalf("used = %d, want 1", used)
	}
	f.ledgerBalances()
}

// L3: an adapter answer that arrives after the fence, once Observe has
// reconciled the attempt, changes nothing.
func TestPostgresLateAnswerAfterTheFenceIsIgnored(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.notesLimit(5)
	entered, answer := make(chan struct{}), make(chan struct{})
	fake := &scripted{}
	fake.set(func(adapters.Effect) adapters.DispatchResult {
		close(entered)
		<-answer
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: contracts.ReasonPreconditionFailed}
	}, nil)
	svc := f.withAdapter(fake)
	a := f.propose(human, quotaNote("slow"))
	done := make(chan error, 1)
	go func() {
		_, _, err := svc.Dispatch(ctx, workload, a.ID)
		done <- err
	}()
	<-entered
	f.passFence(a.ID)
	reconciled, _, err := svc.Observe(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "reconciled while the dispatch hung", reconciled, "RECONCILED", "SUCCEEDED", "")
	close(answer)
	must(t, <-done)
	after, err := svc.Get(ctx, human, a.ID)
	must(t, err)
	wantOutcome(t, "after the late answer", after, "RECONCILED", "SUCCEEDED", "")
	if after.Version != reconciled.Version || after.Exposures[0].Kind != "confirmed" {
		t.Fatalf("the late NOT_SENT changed the attempt: %+v", after)
	}
	f.ledgerBalances()
}

// M3: only the workload an attempt was proposed through dispatches or
// observes it.
func TestPostgresOnlyTheProposingWorkloadDispatches(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	fake := &scripted{}
	svc := f.withAdapter(fake)
	agentB := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a"}
	a := f.propose(human, note("through-the-runner"))
	_, _, err := svc.Dispatch(ctx, agentB, a.ID)
	wantRefusal(t, "another workload's Dispatch", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	_, _, err = svc.Observe(ctx, agentB, a.ID)
	wantRefusal(t, "another workload's Observe", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	if got, _ := svc.Get(ctx, human, a.ID); got.State != "ADMITTED" || got.Version != a.Version || fake.dispatched.Load() != 0 {
		t.Fatalf("a refused Dispatch changed the attempt: %+v", got)
	}
	// The runner dispatches it, and the claim records who did.
	_, _, err = svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	if n := f.count(tenantA, `SELECT count(*) FROM authority_permits WHERE attempt_id = $1 AND claimed_by_principal_id = $2 AND claimed_by_actor_id = ''`, a.ID, actor); n != 1 {
		t.Fatal("the claim does not record its dispatcher")
	}
	// An agent that proposes directly dispatches its own attempt, and the
	// runner cannot.
	f.rootMandate(tenantA, "agent-a", skeletonTerms(f.now))
	own := f.propose(agentB, note("agent-direct"))
	_, _, err = svc.Dispatch(ctx, workload, own.ID)
	wantRefusal(t, "the runner on an agent's own attempt", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	got, _, err := svc.Dispatch(ctx, agentB, own.ID)
	must(t, err)
	wantOutcome(t, "the agent's own dispatch", got, "OBSERVED", "SUCCEEDED", "")
}
