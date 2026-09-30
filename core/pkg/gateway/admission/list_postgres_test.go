package admission

// ListAttempts against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt), through the restricted role admission runs
// as: filters, order and paging over timestamps the tests pin, the tenant and
// workspace scope, the page size bounds, and the index the page query uses.
//
// quantum_posture: compares SHA-256 filter digests carried in page tokens;
// signs nothing and makes no post-quantum claim.

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// attemptIDs are the attempts of one workspace, in creation order: attempt ids
// are time-ordered UUIDs.
func (f *fixture) attemptIDs(tenant, ws string) []string {
	f.t.Helper()
	var ids []string
	f.ownerTx(tenant, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT attempt_id::text FROM authority_effect_attempts WHERE tenant_id = $1 AND workspace_id = $2 ORDER BY attempt_id`, tenant, ws)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids
}

// pin sets attempts' updated_at, so a test chooses the listing order and its
// ties.
func (f *fixture) pin(tenant string, at map[string]time.Time) {
	f.t.Helper()
	f.ownerTx(tenant, func(tx *sql.Tx) error {
		for id, when := range at {
			if _, err := tx.Exec(`UPDATE authority_effect_attempts SET updated_at = $3 WHERE tenant_id = $1 AND attempt_id = $2`, tenant, id, when); err != nil {
				return err
			}
		}
		return nil
	})
}

func (f *fixture) list(caller Caller, in ListInput) ListResult {
	f.t.Helper()
	page, err := f.svc.List(context.Background(), caller, in)
	must(f.t, err)
	if in.PageToken == "" {
		f.checkSettled(page, MaxTransaction)
	} else {
		q, err := parseList(caller, in)
		must(f.t, err)
		if q.settledBefore == nil || !page.SettledBefore.Equal(*q.settledBefore) {
			f.t.Fatalf("continuation changed settled_before: got %v, want %v", page.SettledBefore, q.settledBefore)
		}
	}
	return page
}

// checkSettled requires the page's settled_before to be the database's time,
// bound and margin ago: set on every page, however empty, and never from the
// Go clock. The database's own time is read after the page, so the lag can
// only be a little more.
func (f *fixture) checkSettled(page ListResult, bound time.Duration) {
	f.t.Helper()
	var now time.Time
	must(f.t, f.owner.QueryRow(`SELECT now()`).Scan(&now))
	want := bound + settledMargin
	if lag := now.Sub(page.SettledBefore); page.SettledBefore.IsZero() || lag < want || lag > want+10*time.Second {
		f.t.Fatalf("settled_before = %v, %v before the database's %v; want %v", page.SettledBefore, lag, now, want)
	}
}

// waitForLock waits until a statement containing fragment is waiting for a
// lock: the moment a test may act on the transaction it is stuck in.
func (f *fixture) waitForLock(fragment string) {
	f.t.Helper()
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var waiting int
		must(f.t, f.owner.QueryRow(`SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%' || $1 || '%' AND pid <> pg_backend_pid()`, fragment).Scan(&waiting))
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("no statement with %q is waiting for a lock", fragment)
		}
	}
}

// brief names attempts by key, state, version and updated_at, for a failure
// message that can be read.
func brief(attempts []Attempt) []string {
	out := make([]string, 0, len(attempts))
	for _, a := range attempts {
		out = append(out, fmt.Sprintf("%s %s v%d %s", a.IdempotencyKey, a.State, a.Version, a.UpdatedAt.Format(time.RFC3339Nano)))
	}
	return out
}

func listedIDs(attempts []Attempt) []string {
	ids := make([]string, 0, len(attempts))
	for _, a := range attempts {
		ids = append(ids, a.ID)
	}
	return ids
}

// walk pages through a listing, pageSize attempts at a time, from in's page
// token if it has one. It returns the attempts in the order received and the
// size of each page, and fails on a page that is empty, over the size, or
// endless.
func (f *fixture) walk(caller Caller, in ListInput, pageSize int) ([]Attempt, []int) {
	f.t.Helper()
	in.PageSize = pageSize
	var got []Attempt
	var sizes []int
	for {
		page := f.list(caller, in)
		if n := len(page.Attempts); n == 0 || n > pageSize || len(sizes) > 500 {
			f.t.Fatalf("a page of %d attempts (size %d, page %d), token %q", n, pageSize, len(sizes)+1, page.NextPageToken)
		}
		got = append(got, page.Attempts...)
		sizes = append(sizes, len(page.Attempts))
		if page.NextPageToken == "" {
			return got, sizes
		}
		in.PageToken = page.NextPageToken
	}
}

// cancel withdraws the attempt as its requester, which changes its state and
// moves its updated_at to now.
func (f *fixture) cancel(caller Caller, id string) {
	f.t.Helper()
	_, _, err := f.svc.Cancel(context.Background(), caller, Token{Scope: scopePropose}, id)
	must(f.t, err)
}

func TestPostgresListAttemptsFiltersOrderAndPaging(t *testing.T) {
	f := newFixture(t)

	// Fifteen attempts of one workspace: eight notes, a note for a case, a
	// branch that is admitted and one that is denied, a draft pull request
	// that escalates (over a branch of its own), a note of another requester,
	// and a note that is cancelled.
	for i := range 8 {
		f.propose(human, note(fmt.Sprintf("note-%d", i)))
	}
	caseNote := note("case-note")
	caseNote.CommitmentID, caseNote.CaseID = "", "case-1"
	f.propose(human, caseNote)
	f.propose(human, proposal("branch-1", effectargs.GitHubBranchCreateFromChanges, repo, branchArgs("helm/skeleton")))
	f.propose(human, proposal("denied-1", effectargs.GitHubBranchCreateFromChanges, repo, branchArgs("main")))
	f.escalated("pr1")
	f.rootMandate(tenantA, "agent-a", skeletonTerms(f.now))
	f.propose(Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a"}, note("agent-note"))
	f.cancel(human, f.propose(human, note("doomed")).ID)
	ids := f.attemptIDs(tenantA, workspace)
	if len(ids) != 15 {
		t.Fatalf("%d attempts, want 15", len(ids))
	}

	// Pin their updated_at: ties (three at one instant), neighbours one
	// microsecond apart, and gaps, so a page can end inside a tie.
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	us, s := time.Microsecond, time.Second
	offsets := []time.Duration{0, 0, 0, us, us, 2 * us, s, s, s, s + us, 5 * s, 5 * s, 9 * s, 9*s + us, 9*s + 2*us}
	pinned := map[string]time.Time{}
	for i, id := range ids {
		pinned[id] = t0.Add(offsets[i])
	}
	f.pin(tenantA, pinned)

	// The oracle: every attempt as Get returns it, in (updated_at, attempt_id)
	// order.
	all := make([]Attempt, 0, len(ids))
	for _, id := range ids {
		a, err := f.svc.Get(context.Background(), human, id)
		must(t, err)
		all = append(all, a)
	}
	slices.SortFunc(all, func(a, b Attempt) int {
		if c := a.UpdatedAt.Compare(b.UpdatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	for i, a := range all {
		if !a.UpdatedAt.Equal(t0.Add(offsets[i])) {
			t.Fatalf("attempt %d has updated_at %v, want %v", i, a.UpdatedAt, t0.Add(offsets[i]))
		}
	}
	states := map[string]int{}
	for _, a := range all {
		states[a.State]++
	}
	if states["ADMITTED"] != 11 || states["OBSERVED"] != 1 || states["ESCALATED"] != 1 || states["DENIED"] != 1 || states["CANCELLED"] != 1 || len(states) != 5 {
		t.Fatalf("states = %v", states)
	}

	// Known good: every attempt, in order, each as Get returns it.
	full := f.list(human, ListInput{PageSize: 200})
	if full.NextPageToken != "" || !slices.Equal(listedIDs(full.Attempts), listedIDs(all)) || !reflect.DeepEqual(full.Attempts, all) {
		t.Fatalf("one page = %v (token %q), want %v", listedIDs(full.Attempts), full.NextPageToken, listedIDs(all))
	}

	// Paging, at every size, visits each attempt once in order, across ties.
	// A token exists only while more follows: a last page that is exactly full
	// has none.
	for _, size := range []int{1, 2, 3, 4, 5, 7, 14, 15, 16, 200} {
		got, _ := f.walk(human, ListInput{}, size)
		if !reflect.DeepEqual(got, all) {
			t.Fatalf("page size %d walked %v, want %v", size, listedIDs(got), listedIDs(all))
		}
	}
	if _, sizes := f.walk(human, ListInput{}, 4); !slices.Equal(sizes, []int{4, 4, 4, 3}) {
		t.Fatalf("pages of 4 = %v", sizes)
	}
	if _, sizes := f.walk(human, ListInput{}, 5); !slices.Equal(sizes, []int{5, 5, 5}) {
		t.Fatalf("pages of 5 = %v", sizes)
	}
	if page := f.list(human, ListInput{PageSize: 15}); page.NextPageToken != "" || len(page.Attempts) != 15 {
		t.Fatalf("an exactly full last page has a token: %d attempts, %q", len(page.Attempts), page.NextPageToken)
	}
	if page := f.list(human, ListInput{PageSize: 14}); page.NextPageToken == "" || len(page.Attempts) != 14 {
		t.Fatalf("a page with one attempt to follow has no token: %d attempts", len(page.Attempts))
	}

	// Filters, alone and together, and paged.
	where := func(match func(Attempt) bool) []string {
		var out []string
		for _, a := range all {
			if match(a) {
				out = append(out, a.ID)
			}
		}
		return out
	}
	is := func(field func(Attempt) string, value string) func(Attempt) bool {
		return func(a Attempt) bool { return field(a) == value }
	}
	state := func(a Attempt) string { return a.State }
	effect := func(a Attempt) string { return a.EffectType }
	requester := func(a Attempt) string { return a.RequesterPrincipalID }
	after := func(at time.Time) func(Attempt) bool { return func(a Attempt) bool { return a.UpdatedAt.After(at) } }
	both := func(x, y func(Attempt) bool) func(Attempt) bool { return func(a Attempt) bool { return x(a) && y(a) } }
	either := func(x, y func(Attempt) bool) func(Attempt) bool { return func(a Attempt) bool { return x(a) || y(a) } }
	late := all[4].UpdatedAt // the second of two attempts at one instant
	for _, test := range []struct {
		name  string
		in    ListInput
		match func(Attempt) bool
		n     int
	}{
		{"a state", ListInput{States: []string{"ESCALATED"}}, is(state, "ESCALATED"), 1},
		{"either of two states", ListInput{States: []string{"DENIED", "ESCALATED"}}, either(is(state, "DENIED"), is(state, "ESCALATED")), 2},
		{"a state named twice", ListInput{States: []string{"DENIED", "DENIED"}}, is(state, "DENIED"), 1},
		{"a state nothing is in", ListInput{States: []string{"SETTLED"}}, is(state, "SETTLED"), 0},
		{"a commitment", ListInput{CommitmentID: "commitment-1"}, func(a Attempt) bool { return a.CommitmentID == "commitment-1" }, 14},
		{"a case", ListInput{CaseID: "case-1"}, func(a Attempt) bool { return a.CaseID == "case-1" }, 1},
		{"a commitment nothing serves", ListInput{CommitmentID: "commitment-9"}, func(a Attempt) bool { return a.CommitmentID == "commitment-9" }, 0},
		{"a requester", ListInput{RequesterPrincipalID: "agent-a"}, is(requester, "agent-a"), 1},
		{"the other requester", ListInput{RequesterPrincipalID: "human-a"}, is(requester, "human-a"), 14},
		{"a requester with no attempts", ListInput{RequesterPrincipalID: "human-b"}, is(requester, "human-b"), 0},
		{"an effect type", ListInput{EffectType: noteType}, is(effect, noteType), 11},
		{"a branch effect type", ListInput{EffectType: effectargs.GitHubBranchCreateFromChanges}, is(effect, effectargs.GitHubBranchCreateFromChanges), 3},
		{"the draft effect type", ListInput{EffectType: effectargs.GitHubPullRequestCreateDraft}, is(effect, effectargs.GitHubPullRequestCreateDraft), 1},
		{"every filter at once", ListInput{States: []string{"ADMITTED"}, CommitmentID: "commitment-1", RequesterPrincipalID: "human-a", EffectType: noteType, UpdatedAfter: &t0},
			both(both(is(state, "ADMITTED"), is(effect, noteType)), both(is(requester, "human-a"), func(a Attempt) bool { return a.CommitmentID == "commitment-1" && a.UpdatedAt.After(t0) })), 5},
		{"updated_after is exclusive", ListInput{UpdatedAfter: &late}, after(late), 10},
		{"updated_after at a tie leaves the tie out", ListInput{UpdatedAfter: &t0}, after(t0), 12},
		// updated_at is whole microseconds, and "after x" is "after x rounded
		// down": PostgreSQL would round the parameter up to the next
		// microsecond and drop the attempt that sits on it.
		{"updated_after inside a microsecond", ListInput{UpdatedAfter: timePtr(late.Add(999 * time.Nanosecond))}, after(late), 10},
		{"updated_after a nanosecond past one", ListInput{UpdatedAfter: timePtr(late.Add(time.Nanosecond))}, after(late), 10},
		{"updated_after before everything", ListInput{UpdatedAfter: timePtr(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))}, after(time.Time{}), 15},
		{"updated_after past everything", ListInput{UpdatedAfter: timePtr(all[14].UpdatedAt)}, after(all[14].UpdatedAt), 0},
	} {
		want := where(test.match)
		if len(want) != test.n {
			t.Fatalf("%s: the oracle holds %d attempts, want %d", test.name, len(want), test.n)
		}
		single := f.list(human, test.in)
		if got := listedIDs(single.Attempts); !slices.Equal(got, want) || single.NextPageToken != "" {
			t.Fatalf("%s: listed %v (token %q), want %v", test.name, got, single.NextPageToken, want)
		}
		if test.n == 0 {
			continue
		}
		paged, _ := f.walk(human, test.in, 2)
		if got := listedIDs(paged); !slices.Equal(got, want) {
			t.Fatalf("%s: paged %v, want %v", test.name, got, want)
		}
	}

	// A change while the caller pages: one attempt already listed and one not
	// yet listed are cancelled between two pages. Paging continues from where
	// it was, lists the unlisted one once at its new position, and lists the
	// listed one again at its new position, after everything that did not
	// change.
	first := f.list(human, ListInput{PageSize: 4})
	if !slices.Equal(listedIDs(first.Attempts), listedIDs(all[:4])) || first.NextPageToken == "" {
		t.Fatalf("first page = %v", listedIDs(first.Attempts))
	}
	moved, unseen := all[1], all[9]
	if moved.State != "ADMITTED" || unseen.State != "ADMITTED" {
		t.Fatalf("the attempts to change are %s and %s, want ADMITTED", moved.State, unseen.State)
	}
	f.cancel(human, moved.ID)
	f.cancel(human, unseen.ID)
	rest, _ := f.walk(human, ListInput{PageToken: first.NextPageToken}, 4)
	var wantRest []string
	for _, a := range all[4:] {
		if a.ID != unseen.ID {
			wantRest = append(wantRest, a.ID)
		}
	}
	wantRest = append(wantRest, moved.ID, unseen.ID)
	if got := listedIDs(rest); !slices.Equal(got, wantRest) {
		t.Fatalf("after the changes the pages continued with %v, want %v", got, wantRest)
	}
	for _, a := range rest[len(rest)-2:] {
		if a.State != "CANCELLED" || !a.UpdatedAt.After(all[14].UpdatedAt) {
			t.Fatalf("a changed attempt is listed as %+v", a)
		}
	}

	// updated_after lists what changed after an instant: nothing is newer than
	// the last change until an attempt changes, and then exactly that attempt
	// is listed, in its new state. (Where a reader may safely resume is
	// settled_before, not the last updated_at: see
	// TestPostgresListAttemptsSettledBeforeCoversATransactionThatCommitsOutOfOrder.)
	end := f.list(human, ListInput{PageSize: 200})
	cursor := end.Attempts[len(end.Attempts)-1].UpdatedAt
	if got := f.list(human, ListInput{UpdatedAfter: &cursor}); len(got.Attempts) != 0 || got.NextPageToken != "" {
		t.Fatalf("attempts after the last updated_at seen: %v", listedIDs(got.Attempts))
	}
	changed := all[6]
	if changed.State != "ADMITTED" {
		t.Fatalf("attempt to change is %s", changed.State)
	}
	f.cancel(human, changed.ID)
	news := f.list(human, ListInput{UpdatedAfter: &cursor})
	if len(news.Attempts) != 1 || news.Attempts[0].ID != changed.ID || news.Attempts[0].State != "CANCELLED" ||
		news.Attempts[0].Version != changed.Version+1 || news.NextPageToken != "" {
		t.Fatalf("after one change, updated_after lists %+v", news.Attempts)
	}
}

func TestPostgresListAttemptsPageIsOneSnapshot(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := range 4 {
		f.propose(human, note(fmt.Sprintf("snap-%d", i)))
	}
	ids := f.attemptIDs(tenantA, workspace)
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	pinned := map[string]time.Time{}
	for i, id := range ids {
		pinned[id] = t0.Add(time.Duration(i) * time.Second)
	}
	f.pin(tenantA, pinned)
	input := ListInput{PageSize: 3}
	expected := f.list(human, input)
	if len(expected.Attempts) != 3 || expected.NextPageToken == "" {
		t.Fatalf("the page to compare with holds %d attempts (token %q)", len(expected.Attempts), expected.NextPageToken)
	}

	// Freeze the listing between its statements: List reads the keyset, then
	// each attempt in turn, and its first read of an attempt's approval waits
	// for this table lock. While it waits, two of the attempts it has yet to
	// read are cancelled and committed.
	lock, err := f.owner.Begin()
	must(t, err)
	defer func() { _ = lock.Rollback() }()
	_, err = lock.Exec(`LOCK TABLE authority_approvals IN ACCESS EXCLUSIVE MODE`)
	must(t, err)
	var got ListResult
	var listErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		got, listErr = f.svc.List(ctx, human, input)
	}()
	f.waitForLock("FROM authority_approvals")
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE authority_effect_attempts SET state = 'CANCELLED', version = version + 1, updated_at = now()
			WHERE tenant_id = $1 AND attempt_id = ANY($2::uuid[])`, tenantA, "{"+ids[1]+","+ids[2]+"}")
		return err
	})
	must(t, lock.Rollback())
	<-done
	must(t, listErr)

	// The page is what the keyset read saw: neither the states nor the
	// updated_at of the attempts read later differ from it, so the token's
	// position is the last attempt's own, and a client that keeps that
	// updated_at as its cursor misses nothing.
	if !reflect.DeepEqual(got.Attempts, expected.Attempts) {
		t.Fatalf("a change during the listing showed in the page:\n got %v\nwant %v", brief(got.Attempts), brief(expected.Attempts))
	}
	last := got.Attempts[len(got.Attempts)-1]
	query, err := parseList(human, input)
	must(t, err)
	if token := encodePageToken(listPosition{updatedAt: last.UpdatedAt, id: uuid.MustParse(last.ID)}, query.digest, got.SettledBefore); token != got.NextPageToken {
		t.Fatal("the page token does not continue from the last attempt of its own page")
	}
	// Once the listing is over, the change is there to see.
	if after := f.list(human, input); reflect.DeepEqual(after.Attempts, expected.Attempts) || after.Attempts[len(after.Attempts)-1].State != "CANCELLED" {
		t.Fatalf("the cancellations did not commit: %+v", after.Attempts)
	}
}

func TestPostgresListAttemptsSettledBeforeCoversATransactionThatCommitsOutOfOrder(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const bound = 10 * time.Second
	svc, err := New(f.runtime, Config{MaxTransaction: bound})
	must(t, err)

	// T1 begins first and commits last: a note is admitted, and the admission
	// waits for its permit to be written, which this lock holds up, after the
	// attempt row exists with T1's start as its updated_at.
	lock, err := f.owner.Begin()
	must(t, err)
	defer func() { _ = lock.Rollback() }()
	_, err = lock.Exec(`LOCK TABLE authority_permits IN SHARE MODE`)
	must(t, err)
	type proposed struct {
		attempt Attempt
		err     error
	}
	slow := make(chan proposed, 1)
	go func() {
		a, _, err := svc.Propose(ctx, human, note("slow"))
		slow <- proposed{a, err}
	}()
	f.waitForLock("INSERT INTO authority_permits")

	// T2 begins later and commits first: a denial writes no permit.
	quick, _, err := svc.Propose(ctx, human, proposal("quick", effectargs.GitHubBranchCreateFromChanges, repo, branchArgs("main")))
	must(t, err)
	wantState(t, "the transaction that commits first", quick, "DENIED", contracts.ReasonMissingRequirement)

	// A page read between the two commits lists T2's attempt and not T1's.
	between, err := svc.List(ctx, human, ListInput{})
	must(t, err)
	f.checkSettled(between, bound)
	if got := listedIDs(between.Attempts); !slices.Equal(got, []string{quick.ID}) {
		t.Fatalf("the page between the commits lists %v, want only T2's attempt", got)
	}
	lastSeen := quick.UpdatedAt
	resume := between.SettledBefore

	must(t, lock.Rollback())
	r := <-slow
	must(t, r.err)
	late := r.attempt
	wantState(t, "the transaction that commits last", late, "ADMITTED", "")

	// The hazard: T1 committed after T2 with an earlier updated_at, so a
	// reader that resumes at the last updated_at it saw never finds it.
	if !late.UpdatedAt.Before(lastSeen) {
		t.Fatalf("T1's updated_at %v is not before T2's %v: the transactions did not commit out of order", late.UpdatedAt, lastSeen)
	}
	afterLastSeen := f.list(human, ListInput{UpdatedAfter: &lastSeen})
	if len(afterLastSeen.Attempts) != 0 {
		t.Fatalf("resuming at the last updated_at seen lists %v", listedIDs(afterLastSeen.Attempts))
	}
	// The fix: settled_before lay before both updated_at, and a reader that
	// resumes there finds T1's attempt, and T2's again.
	if !resume.Before(late.UpdatedAt) {
		t.Fatalf("settled_before %v is not before T1's updated_at %v", resume, late.UpdatedAt)
	}
	afterSettled := f.list(human, ListInput{UpdatedAfter: &resume})
	if got := listedIDs(afterSettled.Attempts); !slices.Equal(got, []string{late.ID, quick.ID}) {
		t.Fatalf("resuming at settled_before lists %v, want %v", got, []string{late.ID, quick.ID})
	}
}

func TestPostgresListAttemptsPinsWatermarkAcrossALateCommitAndLongTraversal(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const bound = 5 * time.Second
	svc, err := New(f.runtime, Config{MaxTransaction: bound})
	must(t, err)

	lock, err := f.owner.Begin()
	must(t, err)
	defer func() { _ = lock.Rollback() }()
	_, err = lock.Exec(`LOCK TABLE authority_permits IN SHARE MODE`)
	must(t, err)
	type proposed struct {
		attempt Attempt
		err     error
	}
	slow := make(chan proposed, 1)
	go func() {
		a, _, err := svc.Propose(ctx, human, note("late-during-paging"))
		slow <- proposed{a, err}
	}()
	f.waitForLock("INSERT INTO authority_permits")

	quick1, _, err := svc.Propose(ctx, human, proposal("quick-page-one", effectargs.GitHubBranchCreateFromChanges, repo, branchArgs("main")))
	must(t, err)
	quick2, _, err := svc.Propose(ctx, human, proposal("quick-page-two", effectargs.GitHubBranchCreateFromChanges, repo, branchArgs("main")))
	must(t, err)
	wantState(t, "first committed denial", quick1, "DENIED", contracts.ReasonMissingRequirement)
	wantState(t, "second committed denial", quick2, "DENIED", contracts.ReasonMissingRequirement)
	first, err := svc.List(ctx, human, ListInput{PageSize: 1})
	must(t, err)
	if got := listedIDs(first.Attempts); !slices.Equal(got, []string{quick1.ID}) || first.NextPageToken == "" {
		t.Fatalf("first page = %v, token %q; want first denial with continuation", got, first.NextPageToken)
	}
	f.checkSettled(first, bound)

	must(t, lock.Rollback())
	r := <-slow
	must(t, r.err)
	late := r.attempt
	wantState(t, "late commit", late, "ADMITTED", "")
	if !late.UpdatedAt.Before(quick1.UpdatedAt) || !first.SettledBefore.Before(late.UpdatedAt) {
		t.Fatalf("late commit %v must be behind cursor %v but ahead of first watermark %v", late.UpdatedAt, quick1.UpdatedAt, first.SettledBefore)
	}

	// Traversal exceeds the safety margin: a freshly computed last-page
	// watermark would now pass the committed row behind the page cursor.
	time.Sleep(bound + settledMargin + time.Second)
	last, err := svc.List(ctx, human, ListInput{PageSize: 1, PageToken: first.NextPageToken})
	must(t, err)
	if got := listedIDs(last.Attempts); !slices.Equal(got, []string{quick2.ID}) || last.NextPageToken != "" {
		t.Fatalf("last page = %v, token %q; want second denial and end", got, last.NextPageToken)
	}
	if !last.SettledBefore.Equal(first.SettledBefore) {
		t.Fatalf("last-page watermark advanced from %v to %v", first.SettledBefore, last.SettledBefore)
	}
	fresh, err := svc.List(ctx, human, ListInput{})
	must(t, err)
	if !fresh.SettledBefore.After(late.UpdatedAt) {
		t.Fatalf("traversal did not reach the hazard: new watermark %v, late row %v", fresh.SettledBefore, late.UpdatedAt)
	}
	incremental, err := svc.List(ctx, human, ListInput{UpdatedAfter: &last.SettledBefore})
	must(t, err)
	if !slices.Contains(listedIDs(incremental.Attempts), late.ID) {
		t.Fatalf("resuming at last-page watermark lost late commit %s: %v", late.ID, listedIDs(incremental.Attempts))
	}
}

func TestPostgresATransactionPastMaxTransactionIsAborted(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	svc, err := New(f.runtime, Config{MaxTransaction: 300 * time.Millisecond})
	must(t, err)
	a := f.propose(human, note("subject"))

	// A transaction that has written and then runs on: the statement in
	// flight is cancelled, and the write is rolled back. The statement is
	// given the caller's context, which has no deadline; the bound does not
	// depend on it.
	start := time.Now()
	err = svc.inTenant(ctx, tenantA, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE authority_effect_attempts SET state = 'CANCELLED' WHERE tenant_id = $1 AND attempt_id = $2`, tenantA, a.ID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `SELECT pg_sleep(30)`)
		return err
	})
	if elapsed := time.Since(start); err == nil || elapsed > 10*time.Second {
		t.Fatalf("a transaction sleeping for 30s ended after %v with %v; want it aborted at the bound", elapsed, err)
	}
	if got, err := f.svc.Get(ctx, human, a.ID); err != nil || got.State != "ADMITTED" || got.Version != a.Version {
		t.Fatalf("the aborted transaction's write survived: %+v (%v)", got, err)
	}

	// A transaction stuck waiting for a lock is aborted too, and the service
	// works once the lock is gone.
	lock, err := f.owner.Begin()
	must(t, err)
	defer func() { _ = lock.Rollback() }()
	_, err = lock.Exec(`LOCK TABLE authority_effect_attempts IN ACCESS EXCLUSIVE MODE`)
	must(t, err)
	start = time.Now()
	_, err = svc.Get(ctx, human, a.ID)
	if elapsed := time.Since(start); err == nil || elapsed > 10*time.Second {
		t.Fatalf("a read that waited for a lock ended after %v with %v; want it aborted at the bound", elapsed, err)
	}
	must(t, lock.Rollback())
	if got, err := svc.Get(ctx, human, a.ID); err != nil || got.ID != a.ID {
		t.Fatalf("the service does not work after an aborted transaction: %v", err)
	}

	// Nothing is left open on the database.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		var open int
		must(t, f.owner.QueryRow(`SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND state LIKE 'idle in transaction%' AND pid <> pg_backend_pid()`).Scan(&open))
		if open == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions are still idle in a transaction", open)
		}
	}
}

func TestPostgresListAttemptsPageSizeDefaultsAndCaps(t *testing.T) {
	f := newFixture(t)
	f.propose(human, note("seed"))
	// 205 more, cloned from the seed with their own keys and instants.
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO authority_effect_attempts
				(tenant_id, attempt_id, workspace_id, idempotency_key, request_digest, requester_principal_id, requester_actor_id,
				 commitment_id, effect_type, target, target_digest, argument_digest, state, updated_at)
			SELECT tenant_id, gen_random_uuid(), workspace_id, 'bulk-' || n, request_digest, requester_principal_id, requester_actor_id,
				commitment_id, effect_type, target, target_digest, argument_digest, state, $2::timestamptz + n * interval '1 microsecond'
			FROM authority_effect_attempts, generate_series(1, 205) n
			WHERE tenant_id = $1 AND idempotency_key = 'seed'`, tenantA, t0)
		return err
	})
	if n := len(f.attemptIDs(tenantA, workspace)); n != 206 {
		t.Fatalf("%d attempts, want 206", n)
	}

	// Zero is 50.
	page := f.list(human, ListInput{})
	if len(page.Attempts) != 50 || page.NextPageToken == "" {
		t.Fatalf("the default page holds %d attempts (token %q), want 50 and a token", len(page.Attempts), page.NextPageToken)
	}
	var walked []Attempt
	in := ListInput{}
	var sizes []int
	for {
		page := f.list(human, in)
		walked, sizes = append(walked, page.Attempts...), append(sizes, len(page.Attempts))
		if page.NextPageToken == "" {
			break
		}
		in.PageToken = page.NextPageToken
	}
	if !slices.Equal(sizes, []int{50, 50, 50, 50, 6}) {
		t.Fatalf("default pages = %v", sizes)
	}

	// 200 is the most a page holds, and 201 is refused.
	big := f.list(human, ListInput{PageSize: 200})
	if len(big.Attempts) != 200 || big.NextPageToken == "" {
		t.Fatalf("a page of 200 holds %d attempts (token %q)", len(big.Attempts), big.NextPageToken)
	}
	_, err := f.svc.List(context.Background(), human, ListInput{PageSize: 201})
	wantRefusal(t, "a page size of 201", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	tail := f.list(human, ListInput{PageSize: 200, PageToken: big.NextPageToken})
	if len(tail.Attempts) != 6 || tail.NextPageToken != "" {
		t.Fatalf("the rest holds %d attempts (token %q), want 6", len(tail.Attempts), tail.NextPageToken)
	}

	// However it is paged, the listing is every attempt once, in order.
	got := append(append([]Attempt(nil), big.Attempts...), tail.Attempts...)
	if !reflect.DeepEqual(got, walked) || len(walked) != 206 {
		t.Fatalf("pages of 200 and pages of 50 list different attempts (%d and %d)", len(got), len(walked))
	}
	for i := 1; i < len(walked); i++ {
		prev, next := walked[i-1], walked[i]
		if c := prev.UpdatedAt.Compare(next.UpdatedAt); c > 0 || c == 0 && prev.ID >= next.ID {
			t.Fatalf("attempt %d (%v %s) is listed before attempt %d (%v %s)", i-1, prev.UpdatedAt, prev.ID, i, next.UpdatedAt, next.ID)
		}
	}
}

func TestPostgresListAttemptsAreTenantAndWorkspaceScoped(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	elsewhere := human
	elsewhere.WorkspaceID = "ws-b"
	otherTenant := human
	otherTenant.TenantID = tenantB
	f.rootMandate(tenantB, "human-a", skeletonTerms(f.now))

	// The same requester, work reference, effect type and state in three
	// scopes.
	mine := []string{f.propose(human, note("mine-1")).ID, f.propose(human, note("mine-2")).ID}
	inWorkspace := []string{f.propose(elsewhere, note("ws-1")).ID, f.propose(elsewhere, note("ws-2")).ID, f.propose(elsewhere, note("ws-3")).ID}
	inTenant := []string{f.propose(otherTenant, note("tenant-1")).ID}
	epoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	matching := ListInput{States: []string{"ADMITTED"}, CommitmentID: "commitment-1", RequesterPrincipalID: "human-a", EffectType: noteType, UpdatedAfter: &epoch}

	// Known good, and known bad in the same breath: each caller lists its own
	// scope and nothing else, however the filters name the others.
	for name, scope := range map[string]struct {
		caller Caller
		want   []string
	}{
		"the workspace":     {human, mine},
		"another workspace": {elsewhere, inWorkspace},
		"another tenant":    {otherTenant, inTenant},
	} {
		for label, in := range map[string]ListInput{"unfiltered": {}, "matching every attempt": matching} {
			if got := listedIDs(f.list(scope.caller, in).Attempts); !slices.Equal(got, scope.want) {
				t.Fatalf("%s, %s: listed %v, want %v", name, label, got, scope.want)
			}
			paged, _ := f.walk(scope.caller, in, 1)
			if got := listedIDs(paged); !slices.Equal(got, scope.want) {
				t.Fatalf("%s, %s, paged: listed %v, want %v", name, label, got, scope.want)
			}
		}
	}
	// A tenant with no authority rows has no attempts, and is not an error.
	nobody := Caller{TenantID: "tenant-z", WorkspaceID: workspace, PrincipalID: "human-a", ActorID: actor}
	if page := f.list(nobody, matching); len(page.Attempts) != 0 || page.NextPageToken != "" {
		t.Fatalf("a tenant with no rows lists %v", listedIDs(page.Attempts))
	}

	// A page token belongs to the scope it was issued in: replayed from
	// another workspace or tenant with the very same filters, it is refused.
	first := f.list(human, ListInput{PageSize: 1})
	if first.NextPageToken == "" {
		t.Fatal("the first page has no token")
	}
	for name, caller := range map[string]Caller{"another workspace": elsewhere, "another tenant": otherTenant} {
		_, err := f.svc.List(ctx, caller, ListInput{PageSize: 1, PageToken: first.NextPageToken})
		wantRefusal(t, "a token replayed from "+name, err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	}
	if rest := f.list(human, ListInput{PageSize: 1, PageToken: first.NextPageToken}); !slices.Equal(listedIDs(rest.Attempts), mine[1:]) {
		t.Fatalf("the token does not continue its own listing: %v", listedIDs(rest.Attempts))
	}
	// A token whose position names another workspace's attempt is only a
	// position: the listing after it still holds nothing but the caller's own.
	foreign, err := f.svc.Get(ctx, elsewhere, inWorkspace[0])
	must(t, err)
	forged := tokenFor(t, human, ListInput{}, listPosition{updatedAt: epoch, id: uuid.MustParse(foreign.ID)})
	if got := listedIDs(f.list(human, ListInput{PageToken: forged}).Attempts); !slices.Equal(got, mine) {
		t.Fatalf("a token positioned at another workspace's attempt lists %v, want %v", got, mine)
	}
}

func TestPostgresListAttemptsPageQueryUsesItsIndex(t *testing.T) {
	f := newFixture(t)
	// The page query is served in order from the (tenant, workspace,
	// updated_at, attempt_id) index of migration 1, so no page sorts a
	// workspace, and a page after a cursor starts at the cursor: the row
	// comparison is an index condition, not a filter. The planner is kept off
	// every other way to answer, since the tables are empty.
	cursor := tokenFor(t, human, ListInput{States: []string{"ESCALATED"}}, somewhere)
	for name, in := range map[string]ListInput{
		"the first page":       {},
		"filters":              {States: []string{"ESCALATED", "ADMITTED"}, CommitmentID: "c", RequesterPrincipalID: "human-a", EffectType: noteType, UpdatedAfter: timePtr(f.now)},
		"a page after a token": {States: []string{"ESCALATED"}, PageToken: cursor},
	} {
		q, err := parseList(human, in)
		must(t, err)
		statement, args := q.statement(human)
		tx, err := f.runtime.Begin()
		must(t, err)
		_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA)
		must(t, err)
		for _, setting := range []string{"enable_seqscan", "enable_bitmapscan", "enable_sort"} {
			_, err = tx.Exec(`SET LOCAL ` + setting + ` = off`)
			must(t, err)
		}
		rows, err := tx.Query(`EXPLAIN `+statement, args...)
		must(t, err)
		var plan []string
		for rows.Next() {
			var line string
			must(t, rows.Scan(&line))
			plan = append(plan, line)
		}
		must(t, rows.Err())
		must(t, rows.Close())
		_ = tx.Rollback()
		text := strings.Join(plan, "\n")
		if !strings.Contains(text, "authority_effect_attempts_by_update") || strings.Contains(text, "Sort") {
			t.Fatalf("%s: the plan does not read the index in order:\n%s", name, text)
		}
		if in.PageToken != "" && !regexp.MustCompile(`Index Cond:.*\(updated_at, attempt_id\) >`).MatchString(text) {
			t.Fatalf("%s: the cursor is not an index condition:\n%s", name, text)
		}
	}
}
