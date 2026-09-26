package admission

// HELM-751 s2 against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt). Each test migrates a fresh schema with
// Migrate, seeds authority rows through authorityrows.Store as the owner, and
// runs admission as a restricted role (no BYPASSRLS, DML grants only), the way
// `helm-gateway serve` runs as helm_gateway (ADR-0004).
//
// quantum_posture: computes SHA-256 digests to compare with stored ones;
// signs nothing.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

const (
	tenantA   = "tenant-a"
	tenantB   = "tenant-b"
	workspace = "ws-a"
	actor     = "spiffe://helm/control-plane"
	repo      = "github.com/Mindburn-Labs/example"
	noteType  = "ops.note"
	commitSHA = "89abcdef0123456789abcdef0123456789abcdef"
	// The skeleton's mandate condition: every GitHub write's head starts
	// with helm/. A condition that reads a field an effect type lacks cannot
	// be evaluated and denies, so the read and the note are named first.
	skeletonCondition = `input.effect_type in ["ops.note", "github.repository.get"] || input.args.head.startsWith("helm/")`
)

type fixture struct {
	t       *testing.T
	owner   *sql.DB
	runtime *sql.DB
	svc     *Service
	rows    *authorityrows.Store
	mandate authorityrows.Mandate
	now     time.Time
}

// human is the skeleton's requester: human-a, carried by the Control Plane.
var human = Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-a", ActorID: actor}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the gateway admission proofs")
	}
	schema := fmt.Sprintf("helm_gateway_%d", time.Now().UnixNano())
	admin, err := sql.Open("postgres", base)
	must(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	_, err = admin.Exec(`CREATE SCHEMA ` + schema)
	must(t, err)
	role := schema + "_role"
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_, _ = admin.Exec(`DROP ROLE IF EXISTS ` + role)
	})
	owner, err := sql.Open("postgres", withSearchPath(t, base, schema, ""))
	must(t, err)
	t.Cleanup(func() { _ = owner.Close() })
	ctx := context.Background()
	must(t, Migrate(ctx, owner))

	tables := append(append([]string{}, authorityrows.Tables...), Tables...)
	for _, statement := range []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD 'gateway-probe' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB`,
		`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + role,
		`GRANT SELECT, INSERT, UPDATE ON ` + strings.Join(tables, ", ") + ` TO ` + role,
		`REVOKE UPDATE ON authority_postings FROM ` + role,
		`GRANT SELECT ON gateway_schema_migrations TO ` + role,
	} {
		_, err := owner.Exec(statement)
		must(t, err)
	}
	runtime, err := sql.Open("postgres", withSearchPath(t, base, schema, role))
	must(t, err)
	t.Cleanup(func() { _ = runtime.Close() })
	svc, err := New(runtime, Config{})
	must(t, err)
	rows, err := authorityrows.New(owner)
	must(t, err)

	f := &fixture{t: t, owner: owner, runtime: runtime, svc: svc, rows: rows}
	must(t, owner.QueryRow(`SELECT now()`).Scan(&f.now))
	for _, tenant := range []string{tenantA, tenantB} {
		must(t, rows.CreateTenant(ctx, tenant))
		for _, p := range []struct {
			id   string
			kind authorityrows.PrincipalKind
		}{{"human-a", authorityrows.PrincipalHuman}, {"human-b", authorityrows.PrincipalHuman}, {"human-c", authorityrows.PrincipalHuman}, {"agent-a", authorityrows.PrincipalAgent}} {
			must(t, rows.CreatePrincipal(ctx, tenant, p.id, p.kind))
		}
		must(t, rows.CreateEffectType(ctx, tenant, effectargs.GitHubBranchCreateFromChanges, authorityrows.RiskMedium))
		must(t, rows.CreateEffectType(ctx, tenant, effectargs.GitHubPullRequestCreateDraft, authorityrows.RiskMedium))
		must(t, rows.CreateEffectType(ctx, tenant, noteType, authorityrows.RiskLow))
		must(t, rows.CreateEffectType(ctx, tenant, effectargs.GitHubRepositoryGet, authorityrows.RiskLow))
	}
	f.mandate = f.rootMandate(tenantA, "human-a", skeletonTerms(f.now))
	return f
}

func skeletonTerms(now time.Time) authorityrows.Terms {
	return authorityrows.Terms{
		EffectTypes: []string{effectargs.GitHubRepositoryGet, effectargs.GitHubBranchCreateFromChanges, effectargs.GitHubPullRequestCreateDraft, noteType},
		ValidFrom:   now.Add(-time.Hour), ValidUntil: now.Add(24 * time.Hour),
		Targets:   []string{repo, "ops"},
		Condition: skeletonCondition,
		// The draft pull request is a medium effect the mandate escalates.
		ApprovalRequired: []string{effectargs.GitHubPullRequestCreateDraft},
	}
}

func (f *fixture) rootMandate(tenant, holder string, terms authorityrows.Terms) authorityrows.Mandate {
	f.t.Helper()
	approver := "human-b"
	if holder == approver {
		approver = "human-c"
	}
	m, err := f.rows.CreateMandate(context.Background(), tenant, holder, terms,
		authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: approver})
	must(f.t, err)
	return m
}

func withSearchPath(t *testing.T, raw, schema, role string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	must(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	if role != "" {
		parsed.User = url.UserPassword(role, "gateway-probe")
	}
	return parsed.String()
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ownerTx runs fn as the owner, bound to tenant.
func (f *fixture) ownerTx(tenant string, fn func(*sql.Tx) error) {
	f.t.Helper()
	tx, err := f.owner.Begin()
	must(f.t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenant)
	must(f.t, err)
	must(f.t, fn(tx))
	must(f.t, tx.Commit())
}

func (f *fixture) count(tenant, query string, args ...any) int {
	f.t.Helper()
	var n int
	f.ownerTx(tenant, func(tx *sql.Tx) error { return tx.QueryRow(query, args...).Scan(&n) })
	return n
}

func branchArgs(head string) []byte {
	return []byte(`{"schema":"helm.github.branch.create_from_changes.v1","base":"main",` +
		`"base_sha":"0123456789abcdef0123456789abcdef01234567","head":"` + head + `","message":"Add skeleton",` +
		`"files":[{"path":"docs/skeleton.md","mode":"100644","content_utf8":"# Skeleton\n"}]}`)
}

func draftArgs(branchAttempt, head, sha string) []byte {
	return []byte(`{"schema":"helm.github.pull_request.create_draft.v1","branch_attempt_id":"` + branchAttempt +
		`","base":"main","head":"` + head + `","head_sha":"` + sha + `","title":"Skeleton","body":""}`)
}

func proposal(key, effectType, target string, args []byte) ProposeInput {
	return ProposeInput{IdempotencyKey: key, CommitmentID: "commitment-1", EffectType: effectType, Target: target, Arguments: args}
}

func note(key string) ProposeInput {
	return proposal(key, noteType, "ops", []byte(`{"text":"hi"}`))
}

func (f *fixture) propose(caller Caller, in ProposeInput) Attempt {
	f.t.Helper()
	a, _, err := f.svc.Propose(context.Background(), caller, in)
	must(f.t, err)
	return a
}

func wantRefusal(t *testing.T, what string, err error, code Code, reason contracts.ReasonCode) {
	t.Helper()
	var refusal *Error
	if !errors.As(err, &refusal) || refusal.Code != code || refusal.Reason != reason {
		t.Fatalf("%s: err = %v, want code %d reason %q", what, err, code, reason)
	}
}

func wantState(t *testing.T, what string, a Attempt, state string, reason contracts.ReasonCode) {
	t.Helper()
	if a.State != state || a.ReasonCode != string(reason) {
		t.Fatalf("%s: attempt is %s %q, want %s %q", what, a.State, a.ReasonCode, state, reason)
	}
}

// observeBranch makes a branch attempt OBSERVED(SUCCEEDED) with commit as its
// read-back commit: the fixture row slice 3's Observe will write.
func (f *fixture) observeBranch(attemptID, commit string) {
	f.t.Helper()
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE authority_effect_attempts SET state = 'OBSERVED', outcome = 'SUCCEEDED', outcome_basis = 'OBSERVED'
			WHERE tenant_id = $1 AND attempt_id = $2`, tenantA, attemptID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO authority_observations (tenant_id, attempt_id, source, trust_class, outcome, result_kind, result)
			VALUES ($1, $2, 'adapter.readback', 'provider_readback', 'SUCCEEDED', 'github_branch', jsonb_build_object('commit_sha', $3::text))`,
			tenantA, attemptID, commit)
		return err
	})
}

func TestPostgresProposeAdmitsDeniesAndEscalates(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// Known good: the skeleton's safe read, and a branch under the mandate
	// with its head under helm/.
	read := f.propose(human, proposal("read-1", effectargs.GitHubRepositoryGet, repo, []byte(`{"schema":"helm.github.repository.get.v1"}`)))
	wantState(t, "repository read", read, "ADMITTED", "")
	if read.RiskClass != "low" {
		t.Fatalf("repository read risk = %s", read.RiskClass)
	}
	branch := f.propose(human, proposal("branch-1", effectargs.GitHubBranchCreateFromChanges, repo, branchArgs("helm/skeleton")))
	wantState(t, "branch", branch, "ADMITTED", "")
	argumentDigest := sha256.Sum256(branchArgs("helm/skeleton"))
	if branch.MandateID != f.mandate.ID.String() || branch.RiskClass != "medium" || branch.RequesterActorID != actor ||
		string(branch.ArgumentDigest) != string(argumentDigest[:]) || branch.Permit == nil ||
		string(branch.Permit.ArgumentDigest) != string(argumentDigest[:]) || branch.WorkspaceID != workspace {
		t.Fatalf("admitted attempt = %+v", branch)
	}
	kinds := map[string]bool{}
	for _, v := range branch.Permit.AuthorityVersions {
		kinds[v.Kind] = true
	}
	for _, kind := range []string{"tenant", "principal", "mandate", "effect_type"} {
		if !kinds[kind] {
			t.Fatalf("permit versions %+v lack a %s row", branch.Permit.AuthorityVersions, kind)
		}
	}
	content, err := f.svc.GetContent(ctx, human, branch.ID)
	must(t, err)
	if string(content) != string(branchArgs("helm/skeleton")) {
		t.Fatalf("content = %s", content)
	}

	// Known bad: the default branch as head, and a repository off the list.
	wantState(t, "head on the default branch",
		f.propose(human, proposal("branch-main", effectargs.GitHubBranchCreateFromChanges, repo, branchArgs("main"))), "DENIED", contracts.ReasonMissingRequirement)
	other := f.propose(human, proposal("branch-other", effectargs.GitHubBranchCreateFromChanges, "github.com/Mindburn-Labs/other", branchArgs("helm/x")))
	wantState(t, "repository off the allowlist", other, "DENIED", contracts.ReasonEffectOutOfScope)
	if other.Permit != nil {
		t.Fatal("a denied attempt carries a permit")
	}

	// The draft pull request is medium risk, and the mandate requires approval
	// for it: it escalates, with approval digest v1 over what an approver is
	// shown.
	f.observeBranch(branch.ID, commitSHA)
	soon := f.now.Add(time.Hour + 500*time.Millisecond)
	in := proposal("draft-1", effectargs.GitHubPullRequestCreateDraft, repo, draftArgs(branch.ID, "helm/skeleton", commitSHA))
	in.Quote = []Amount{{Unit: "count", Amount: 1}}
	in.ApprovalExpiresAt = &soon
	draft := f.propose(human, in)
	wantState(t, "draft pull request", draft, "ESCALATED", contracts.ReasonApprovalRequired)
	if draft.RiskClass != "medium" || draft.Permit != nil || draft.ApprovalExpiresAt == nil ||
		!draft.ApprovalExpiresAt.Equal(soon.Truncate(time.Second)) {
		t.Fatalf("escalated attempt = %+v", draft)
	}
	want := ApprovalDigestV1(draft.ID, draft.TargetDigest, draft.ArgumentDigest, in.Quote, *draft.ApprovalExpiresAt)
	if string(draft.ApprovalDigest) != string(want) {
		t.Fatal("the stored approval digest is not approval digest v1 of the stored attempt")
	}
	// The escalation comes from the mandate: one without the requirement
	// admits the same medium effect.
	unrequired := skeletonTerms(f.now)
	unrequired.ApprovalRequired = nil
	f.rootMandate(tenantA, "human-c", unrequired)
	other3 := human
	other3.PrincipalID = "human-c"
	wantState(t, "a mandate without the approval requirement",
		f.propose(other3, proposal("draft-3", effectargs.GitHubPullRequestCreateDraft, repo, draftArgs(branch.ID, "helm/skeleton", commitSHA))), "ADMITTED", "")
	// Without a sooner request, the approval window applies.
	later := proposal("draft-2", effectargs.GitHubPullRequestCreateDraft, repo, draftArgs(branch.ID, "helm/skeleton", commitSHA))
	windowed := f.propose(human, later)
	if !windowed.ApprovalExpiresAt.After(soon) || windowed.ApprovalExpiresAt.Nanosecond() != 0 {
		t.Fatalf("approval expiry = %v", windowed.ApprovalExpiresAt)
	}
}

func TestPostgresDraftPullRequestNeedsItsObservedBranch(t *testing.T) {
	f := newFixture(t)
	branch := f.propose(human, proposal("branch-1", effectargs.GitHubBranchCreateFromChanges, repo, branchArgs("helm/skeleton")))
	draftCount := func() int {
		return f.count(tenantA, `SELECT count(*) FROM authority_effect_attempts WHERE effect_type = $1`, effectargs.GitHubPullRequestCreateDraft)
	}
	refused := func(what, key, target string, args []byte) {
		t.Helper()
		before := draftCount()
		_, _, err := f.svc.Propose(context.Background(), human, proposal(key, effectargs.GitHubPullRequestCreateDraft, target, args))
		wantRefusal(t, what, err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
		if draftCount() != before {
			t.Fatalf("%s: a refused precondition left an attempt", what)
		}
	}
	refused("an unknown branch attempt", "d1", repo, draftArgs(uuid.NewString(), "helm/skeleton", commitSHA))
	refused("a branch attempt not observed yet", "d2", repo, draftArgs(branch.ID, "helm/skeleton", commitSHA))
	f.observeBranch(branch.ID, commitSHA)
	setBranchState := func(state, basis string) {
		f.ownerTx(tenantA, func(tx *sql.Tx) error {
			_, err := tx.Exec(`UPDATE authority_effect_attempts SET state = $3, outcome_basis = $4 WHERE tenant_id = $1 AND attempt_id = $2`,
				tenantA, branch.ID, state, basis)
			return err
		})
	}
	setBranchState("SETTLED", "OBSERVED")
	refused("a settled branch attempt", "d2b", repo, draftArgs(branch.ID, "helm/skeleton", commitSHA))
	setBranchState("RECONCILED", "RECONCILED")
	wantState(t, "a reconciled branch", f.propose(human, proposal("d2c", effectargs.GitHubPullRequestCreateDraft, repo, draftArgs(branch.ID, "helm/skeleton", commitSHA))),
		"ESCALATED", contracts.ReasonApprovalRequired)
	setBranchState("OBSERVED", "OBSERVED")
	refused("another head", "d3", repo, draftArgs(branch.ID, "helm/other", commitSHA))
	refused("another commit", "d4", repo, draftArgs(branch.ID, "helm/skeleton", strings.Repeat("0", 40)))
	refused("another repository", "d5", "github.com/Mindburn-Labs/other", draftArgs(branch.ID, "helm/skeleton", commitSHA))
	note := f.propose(human, note("n1"))
	refused("an attempt that is not a branch", "d6", repo, draftArgs(note.ID, "helm/skeleton", commitSHA))
	// Known good: the observed branch, its head and its commit.
	wantState(t, "the observed branch", f.propose(human, proposal("d7", effectargs.GitHubPullRequestCreateDraft, repo, draftArgs(branch.ID, "helm/skeleton", commitSHA))),
		"ESCALATED", contracts.ReasonApprovalRequired)
	// Tenant B cannot point at tenant A's branch attempt.
	bCaller := human
	bCaller.TenantID = tenantB
	f.rootMandate(tenantB, "human-a", skeletonTerms(f.now))
	_, _, err := f.svc.Propose(context.Background(), bCaller, proposal("d8", effectargs.GitHubPullRequestCreateDraft, repo, draftArgs(branch.ID, "helm/skeleton", commitSHA)))
	wantRefusal(t, "another tenant's branch attempt", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
}

func TestPostgresProposeIsIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, err := f.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &f.mandate.ID, Unit: "effects", Measure: "count", Window: "day", Value: 10, Span: 1})
	must(t, err)
	first, existing, err := f.svc.Propose(ctx, human, note("same-key"))
	must(t, err)
	if existing {
		t.Fatal("a new key reported existing")
	}
	reserved := func() int { return f.count(tenantA, `SELECT COALESCE(sum(reserved), 0)::int FROM authority_counters`) }
	if reserved() != 1 {
		t.Fatalf("reserved = %d after one admission", reserved())
	}
	// Same key, same request: the stored attempt, untouched; no second hold.
	again, existing, err := f.svc.Propose(ctx, human, note("same-key"))
	must(t, err)
	if !existing || again.ID != first.ID || again.Version != first.Version || reserved() != 1 {
		t.Fatalf("replay = %+v existing=%v reserved=%d; want the stored attempt", again, existing, reserved())
	}
	// Same key, different request, or the same request from another principal.
	changed := note("same-key")
	changed.Arguments = []byte(`{"text":"bye"}`)
	_, _, err = f.svc.Propose(ctx, human, changed)
	wantRefusal(t, "same key, different content", err, CodeAlreadyExists, contracts.ReasonIdempotencyConflict)
	otherPrincipal := human
	otherPrincipal.PrincipalID = "human-b"
	_, _, err = f.svc.Propose(ctx, otherPrincipal, note("same-key"))
	wantRefusal(t, "same key, another principal", err, CodeAlreadyExists, contracts.ReasonIdempotencyConflict)
	if n := f.count(tenantA, `SELECT count(*) FROM authority_effect_attempts WHERE idempotency_key = 'same-key'`); n != 1 {
		t.Fatalf("%d attempts under one key", n)
	}
	// The key is tenant-scoped: tenant B may reuse it.
	bCaller := human
	bCaller.TenantID = tenantB
	f.rootMandate(tenantB, "human-a", skeletonTerms(f.now))
	b, existing, err := f.svc.Propose(ctx, bCaller, note("same-key"))
	must(t, err)
	if existing || b.ID == first.ID {
		t.Fatal("tenant B's key collided with tenant A's")
	}
}

func TestPostgresConcurrentProposalsAdmitOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, err := f.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &f.mandate.ID, Unit: "effects", Measure: "count", Window: "day", Value: 1, Span: 1})
	must(t, err)

	// One key, sixteen racers: one attempt, created once.
	const racers = 16
	var wg sync.WaitGroup
	ids := make([]string, racers)
	fresh := make([]bool, racers)
	errs := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, existing, err := f.svc.Propose(ctx, human, note("race"))
			ids[i], fresh[i], errs[i] = a.ID, !existing, err
		}()
	}
	wg.Wait()
	created := 0
	for i := range racers {
		must(t, errs[i])
		if ids[i] != ids[0] {
			t.Fatalf("racers got attempts %s and %s", ids[0], ids[i])
		}
		if fresh[i] {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("%d racers created the attempt, want 1", created)
	}

	// Distinct keys racing for a limit of one that the first attempt holds:
	// every one is denied, and the counter never exceeds the limit (I3).
	states := make([]string, racers)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, _, err := f.svc.Propose(ctx, human, note(fmt.Sprintf("race-%d", i)))
			states[i], errs[i] = a.State+" "+a.ReasonCode, err
		}()
	}
	wg.Wait()
	for i := range racers {
		must(t, errs[i])
		if states[i] != "DENIED "+string(contracts.ReasonBudgetExceeded) {
			t.Fatalf("racer %d: %s", i, states[i])
		}
	}
	if r := f.count(tenantA, `SELECT COALESCE(sum(reserved), 0)::int FROM authority_counters`); r != 1 {
		t.Fatalf("reserved = %d, want 1", r)
	}
}

func TestPostgresStopsDenyAdmission(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// human-a delegates to human-c; human-c proposes under the child.
	child, err := f.rows.Delegate(ctx, tenantA, f.mandate.ID, "human-a", "human-c", skeletonTerms(f.now))
	must(t, err)
	delegate := human
	delegate.PrincipalID = "human-c"
	wantState(t, "before any stop", f.propose(delegate, note("before")), "ADMITTED", "")

	for i, scope := range []authorityrows.Scope{
		{Kind: authorityrows.ScopeTenant, Key: tenantA},
		{Kind: authorityrows.ScopePrincipal, Key: "human-c"},
		// The delegator: a stopped link suspends everything below it.
		{Kind: authorityrows.ScopePrincipal, Key: "human-a"},
		{Kind: authorityrows.ScopeMandate, Key: f.mandate.ID.String()},
		{Kind: authorityrows.ScopeMandate, Key: child.ID.String()},
		{Kind: authorityrows.ScopeEffectType, Key: noteType},
	} {
		stop, err := f.rows.Stop(ctx, tenantA, authorityrows.StopSpec{Scope: scope, Reason: "incident", IssuedBy: "human-b"})
		must(t, err)
		wantState(t, fmt.Sprintf("stop on %s %s", scope.Kind, scope.Key), f.propose(delegate, note(fmt.Sprintf("stopped-%d", i))),
			"DENIED", contracts.ReasonEmergencyStopFenced)
		must(t, f.rows.Lift(ctx, tenantA, stop.ID, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-b"}))
		wantState(t, "after the lift", f.propose(delegate, note(fmt.Sprintf("lifted-%d", i))), "ADMITTED", "")
	}
	// A stop on an unrelated effect type does not deny this one.
	_, err = f.rows.Stop(ctx, tenantA, authorityrows.StopSpec{Scope: authorityrows.Scope{Kind: authorityrows.ScopeEffectType, Key: effectargs.GitHubPullRequestCreateDraft}, Reason: "x", IssuedBy: "human-b"})
	must(t, err)
	wantState(t, "unrelated stop", f.propose(delegate, note("unrelated")), "ADMITTED", "")
	// A revoked parent denies the child.
	must(t, f.rows.Revoke(ctx, tenantA, f.mandate.ID))
	wantState(t, "revoked parent", f.propose(delegate, note("revoked")), "DENIED", contracts.ReasonMandateInactive)
}

func TestPostgresReadsAreTenantAndWorkspaceScoped(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.propose(human, note("mine"))
	for name, caller := range map[string]Caller{
		"another tenant":    {TenantID: tenantB, WorkspaceID: workspace, PrincipalID: "human-a", ActorID: actor},
		"another workspace": {TenantID: tenantA, WorkspaceID: "ws-b", PrincipalID: "human-a", ActorID: actor},
	} {
		_, err := f.svc.Get(ctx, caller, a.ID)
		wantRefusal(t, name+" reads the attempt", err, CodeNotFound, "")
		_, err = f.svc.GetContent(ctx, caller, a.ID)
		wantRefusal(t, name+" reads the content", err, CodeNotFound, "")
	}
	_, err := f.svc.Get(ctx, human, uuid.NewString())
	wantRefusal(t, "a missing attempt", err, CodeNotFound, "")
	_, err = f.svc.Get(ctx, human, "not-a-uuid")
	wantRefusal(t, "a malformed id", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	got, err := f.svc.Get(ctx, human, a.ID)
	must(t, err)
	if got.ID != a.ID {
		t.Fatal("the owner cannot read its attempt")
	}

	// Row security under the restricted role, without the service's
	// predicates: tenant B's transaction sees none of A's rows, and an unbound
	// one sees nothing.
	for _, tenant := range []string{tenantB, ""} {
		tx, err := f.runtime.Begin()
		must(t, err)
		if tenant != "" {
			_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenant)
			must(t, err)
		}
		for _, table := range Tables {
			var n int
			must(t, tx.QueryRow(`SELECT count(*) FROM `+table).Scan(&n))
			if n != 0 {
				t.Fatalf("tenant %q sees %d rows of %s", tenant, n, table)
			}
		}
		res, err := tx.Exec(`UPDATE authority_effect_attempts SET state = 'CANCELLED' WHERE attempt_id = $1`, a.ID)
		must(t, err)
		if n, _ := res.RowsAffected(); n != 0 {
			t.Fatalf("tenant %q updated tenant A's attempt", tenant)
		}
		_ = tx.Rollback()
	}
}

func TestPostgresMalformedProposalsCreateNoAttempt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	attempts := func() int { return f.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`) }
	for _, test := range []struct {
		name   string
		caller Caller
		in     ProposeInput
		code   Code
		reason contracts.ReasonCode
	}{
		{"duplicate keys", human, proposal("k1", effectargs.GitHubBranchCreateFromChanges, repo,
			[]byte(strings.Replace(string(branchArgs("helm/x")), `"base":"main"`, `"base":"main","base":"dev"`, 1))), CodeInvalidArgument, contracts.ReasonSchemaViolation},
		{"unknown field", human, proposal("k2", effectargs.GitHubBranchCreateFromChanges, repo,
			[]byte(strings.Replace(string(branchArgs("helm/x")), `"base":"main"`, `"base":"main","force":true`, 1))), CodeInvalidArgument, contracts.ReasonSchemaViolation},
		{"oversize", human, proposal("k3", noteType, "ops", []byte(`{"text":"`+strings.Repeat("x", effectargs.MaxBytes)+`"}`)), CodeInvalidArgument, contracts.ReasonSchemaViolation},
		{"workflow file", human, proposal("k4", effectargs.GitHubBranchCreateFromChanges, repo,
			[]byte(strings.Replace(string(branchArgs("helm/x")), "docs/skeleton.md", ".github/workflows/x.yml", 1))), CodeInvalidArgument, contracts.ReasonSchemaViolation},
		{"no work reference", human, ProposeInput{IdempotencyKey: "k5", EffectType: noteType, Target: "ops", Arguments: []byte(`{}`)}, CodeInvalidArgument, contracts.ReasonSchemaViolation},
		{"empty key", human, note(""), CodeInvalidArgument, contracts.ReasonSchemaViolation},
		{"negative quote", human, func() ProposeInput { in := note("k6"); in.Quote = []Amount{{"usd", -1}}; return in }(), CodeInvalidArgument, contracts.ReasonSchemaViolation},
		{"a human without the workload actor", Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-a"}, note("k7"), CodePermissionDenied, contracts.ReasonInsufficientPrivilege},
		{"an unprovisioned tenant", Caller{TenantID: "tenant-z", WorkspaceID: workspace, PrincipalID: "human-a", ActorID: actor}, note("k8"), CodePermissionDenied, contracts.ReasonTenantIsolation},
	} {
		before := attempts()
		_, _, err := f.svc.Propose(ctx, test.caller, test.in)
		wantRefusal(t, test.name, err, test.code, test.reason)
		if attempts() != before {
			t.Fatalf("%s: left an attempt", test.name)
		}
	}
	// Known good: the same shapes, well formed.
	wantState(t, "well formed", f.propose(human, note("k9")), "ADMITTED", "")
	agent := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a"}
	f.rootMandate(tenantA, "agent-a", skeletonTerms(f.now))
	wantState(t, "an agent's direct token", f.propose(agent, note("k10")), "ADMITTED", "")
}

func TestPostgresMandateSelectionIsBoundToThePrincipal(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	others := f.rootMandate(tenantA, "human-b", skeletonTerms(f.now))

	selected := note("own")
	selected.MandateID = f.mandate.ID.String()
	wantState(t, "the principal's own mandate", f.propose(human, selected), "ADMITTED", "")

	foreign := note("foreign")
	foreign.MandateID = others.ID.String()
	a := f.propose(human, foreign)
	wantState(t, "another principal's mandate", a, "DENIED", contracts.ReasonMandateInactive)
	if a.MandateID != "" {
		t.Fatalf("a mandate the principal does not hold was recorded: %s", a.MandateID)
	}
	missing := note("missing")
	missing.MandateID = uuid.NewString()
	wantState(t, "a mandate that does not exist", f.propose(human, missing), "DENIED", contracts.ReasonMandateInactive)

	stranger := human
	stranger.PrincipalID = "human-c"
	wantState(t, "a principal with no mandate", f.propose(stranger, note("none")), "DENIED", contracts.ReasonMandateInactive)
	unknown := human
	unknown.PrincipalID = "ghost"
	wantState(t, "an unknown principal", f.propose(unknown, note("ghost")), "DENIED", contracts.ReasonPrincipalInactive)

	// Per-call limits and sum limits hold across the chain.
	limited := f.rootMandate(tenantA, "human-c", func() authorityrows.Terms {
		terms := skeletonTerms(f.now)
		terms.PerCallLimit = amountPtr(100)
		return terms
	}())
	_, err := f.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &limited.ID, Unit: "usd", Measure: "sum", Window: "month", Value: 150, Span: 1})
	must(t, err)
	spend := func(key string, amount int64) ProposeInput {
		in := note(key)
		in.Quote = []Amount{{Unit: "usd", Amount: amount}}
		return in
	}
	wantState(t, "over the per-call limit", f.propose(stranger, spend("s1", 101)), "DENIED", contracts.ReasonPerCallLimit)
	wantState(t, "within both limits", f.propose(stranger, spend("s2", 100)), "ADMITTED", "")
	wantState(t, "over the monthly sum", f.propose(stranger, spend("s3", 60)), "DENIED", contracts.ReasonBudgetExceeded)
	wantState(t, "up to the monthly sum", f.propose(stranger, spend("s4", 50)), "ADMITTED", "")
}

func TestPostgresMigrateIsVersioned(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, Migrate(ctx, f.owner))
	version, err := SchemaVersion(ctx, f.owner)
	must(t, err)
	if version != HeadVersion() {
		t.Fatalf("schema version %d, want %d", version, HeadVersion())
	}
	_, err = f.owner.Exec(`INSERT INTO gateway_schema_migrations (version, name) VALUES (999, 'from the future')`)
	must(t, err)
	if err := Migrate(ctx, f.owner); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("Migrate over a newer schema = %v, want a refusal", err)
	}
}
