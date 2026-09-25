package authorityrows

// HELM-750 s2a against real Postgres (listed in scripts/ci/postgres-proofs.txt):
// narrowing-only delegation over random chains, stop expiry and approved lift,
// a version bump on every narrowing, and tenant isolation under a restricted
// role. Each test migrates a fresh schema with the kernel's own migration.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/postgresmigration"
)

const tenantA = "tenant-a"

var (
	humans = []string{"human-a", "human-b"}
	agents = []string{"agent-a", "agent-b", "agent-c"}
	root   = WideningApproval{RequesterID: "agent-a", ApproverID: "human-a"}
)

// postgresStore migrates a fresh schema and returns a store over it, the
// owner connection, and the base URL and schema for opening other roles.
func postgresStore(t *testing.T) (*Store, *sql.DB, string, string) {
	t.Helper()
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the authority rows proofs")
	}
	schema := fmt.Sprintf("helm_authority_rows_%d", time.Now().UnixNano())
	admin, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) })
	db, err := sql.Open("postgres", withSearchPath(t, base, schema))
	if err != nil {
		t.Fatalf("open schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := postgresmigration.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	return store, db, base, schema
}

func withSearchPath(t *testing.T, raw, schema string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse postgres url: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// seed creates a tenant with humans, agents, a service principal and every
// effect type of allEffectTypes.
func seed(t *testing.T, s *Store, tenant string) {
	t.Helper()
	ctx := context.Background()
	must(t, s.CreateTenant(ctx, tenant))
	for _, id := range humans {
		must(t, s.CreatePrincipal(ctx, tenant, id, PrincipalHuman))
	}
	for _, id := range agents {
		must(t, s.CreatePrincipal(ctx, tenant, id, PrincipalAgent))
	}
	must(t, s.CreatePrincipal(ctx, tenant, "service-a", PrincipalService))
	for i, effectType := range allEffectTypes {
		must(t, s.CreateEffectType(ctx, tenant, effectType, []RiskClass{RiskLow, RiskHigh}[i%2]))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: err = %v, want %v", what, err, want)
	}
}

// inTenant runs raw SQL bound to a tenant, the way the store does.
func inTenant(t *testing.T, db *sql.DB, tenant string, fn func(*sql.Tx) error) error {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func scalar[T any](t *testing.T, db *sql.DB, tenant, query string, args ...any) T {
	t.Helper()
	var out T
	must(t, inTenant(t, db, tenant, func(tx *sql.Tx) error { return tx.QueryRow(query, args...).Scan(&out) }))
	return out
}

func dbNow(t *testing.T, db *sql.DB) time.Time {
	t.Helper()
	var now time.Time
	must(t, db.QueryRow(`SELECT now()`).Scan(&now))
	return now.UTC()
}

// Delegation only narrows, over random chains. A delegation succeeds exactly
// when every mandate above it is active and the child's terms are within each
// of them, including ancestors narrowed after the parent was delegated. A
// refused delegation writes nothing, and a delegation-only tree satisfies the
// narrowing invariant at rest.
func TestPostgresDelegationOnlyNarrowsOverRandomChains(t *testing.T) {
	s, db, _, _ := postgresStore(t)
	ctx := context.Background()
	seed(t, s, tenantA)
	holders := append(append([]string(nil), agents...), humans...)
	count := func() int {
		return scalar[int](t, db, tenantA, `SELECT count(*) FROM authority_mandates`)
	}

	for run := 0; run < 8; run++ {
		r := rand.New(rand.NewPCG(750, uint64(run)))
		rootTerms := randomTerms(r)
		m, err := s.CreateMandate(ctx, tenantA, holders[r.IntN(len(holders))], rootTerms, root)
		must(t, err)
		tree := []Mandate{m}

		// Phase 1: delegations only.
		for step := 0; step < 30; step++ {
			parent := tree[r.IntN(len(tree))]
			if child, ok := delegateRandomly(t, s, r, parent, holders, count); ok {
				tree = append(tree, child)
			}
		}
		for _, m := range tree {
			chain, err := s.Chain(ctx, tenantA, m.ID)
			must(t, err)
			for _, ancestor := range chain {
				if err := m.Terms.Within(ancestor.Terms); err != nil {
					t.Fatalf("run %d: mandate %s at depth %d is wider than ancestor %s: %v", run, m.ID, m.Depth, ancestor.ID, err)
				}
			}
		}

		// Phase 2: delegations interleaved with narrowing and revocation.
		for step := 0; step < 30; step++ {
			target := tree[r.IntN(len(tree))]
			current, err := s.Chain(ctx, tenantA, target.ID)
			must(t, err)
			leaf := current[len(current)-1]
			switch op := r.IntN(10); {
			case op < 5:
				if child, ok := delegateRandomly(t, s, r, target, holders, count); ok {
					tree = append(tree, child)
				}
			case op < 8:
				narrower := narrowed(r, leaf.Terms)
				got, err := s.Narrow(ctx, tenantA, leaf.ID, narrower)
				if !leaf.Active {
					wantErr(t, "narrow a revoked mandate", err, ErrInactive)
					continue
				}
				must(t, err)
				if got.Version != leaf.Version+1 {
					t.Fatalf("run %d: narrow bumped version %d to %d", run, leaf.Version, got.Version)
				}
				wide, field := widened(r, got.Terms, got.Terms)
				_, err = s.Narrow(ctx, tenantA, leaf.ID, wide)
				wantErr(t, "narrow that widens "+field, err, ErrWidens)
			case op < 9:
				err := s.Revoke(ctx, tenantA, leaf.ID)
				if leaf.Active {
					must(t, err)
				} else {
					wantErr(t, "revoke twice", err, ErrInactive)
				}
			default:
				before := count()
				_, err := s.Delegate(ctx, tenantA, leaf.ID, "human-b-not-holder", holders[0], leaf.Terms)
				wantErr(t, "delegate by a non-holder", err, ErrNotDelegator)
				if count() != before {
					t.Fatalf("run %d: a refused delegation wrote a mandate", run)
				}
			}
		}
	}
}

// delegateRandomly delegates from parent with terms that are either narrowed
// from the parent's current terms or widened in one term, and checks the
// outcome against the reference: active chain, and within every link.
func delegateRandomly(t *testing.T, s *Store, r *rand.Rand, parent Mandate, holders []string, count func() int) (Mandate, bool) {
	t.Helper()
	ctx := context.Background()
	chain, err := s.Chain(ctx, tenantA, parent.ID)
	must(t, err)
	leaf := chain[len(chain)-1]
	terms := narrowed(r, leaf.Terms)
	if r.IntN(3) == 0 {
		terms, _ = widened(r, leaf.Terms, terms)
	}
	normalizedTerms := mustNormalize(t, terms)
	var want error
	for _, link := range chain {
		if !link.Active {
			want = ErrInactive
			break
		}
		if err := normalizedTerms.Within(link.Terms); err != nil {
			want = ErrWidens
			break
		}
	}
	before := count()
	child, err := s.Delegate(ctx, tenantA, leaf.ID, leaf.HolderID, holders[r.IntN(len(holders))], terms)
	if want != nil {
		wantErr(t, "delegation", err, want)
		if count() != before {
			t.Fatal("a refused delegation wrote a mandate")
		}
		return Mandate{}, false
	}
	must(t, err)
	stored, err := s.Chain(ctx, tenantA, child.ID)
	must(t, err)
	got := stored[len(stored)-1]
	if got.Depth != leaf.Depth+1 || got.ParentID == nil || *got.ParentID != leaf.ID || got.CreatedBy != leaf.HolderID || got.ApprovedBy != "" {
		t.Fatalf("delegated mandate stored as %+v under %s", got, leaf.ID)
	}
	if got.Terms.Within(normalizedTerms) != nil || normalizedTerms.Within(got.Terms) != nil {
		t.Fatalf("stored terms %+v differ from requested %+v", got.Terms, normalizedTerms)
	}
	return got, true
}

// A stop is active until it expires or is lifted. Lifting widens authority:
// without an approval by a distinct, active human it is refused and changes
// nothing, and the schema itself refuses a lifted stop without its approval.
func TestPostgresStopExpiresAndLiftNeedsApproval(t *testing.T) {
	s, db, _, _ := postgresStore(t)
	ctx := context.Background()
	seed(t, s, tenantA)
	now := dbNow(t, db)
	m, err := s.CreateMandate(ctx, tenantA, "agent-a", Terms{
		EffectTypes: []string{"email.send"}, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(24 * time.Hour),
	}, root)
	must(t, err)

	expires := now.Add(time.Hour)
	expiring, err := s.Stop(ctx, tenantA, StopSpec{Scope: Scope{Kind: ScopePrincipal, Key: "agent-a"}, Reason: "incident 17", IssuedBy: "service-a", ExpiresAt: &expires})
	must(t, err)
	standing, err := s.Stop(ctx, tenantA, StopSpec{Scope: Scope{Kind: ScopeMandate, Key: m.ID.String()}, Reason: "review", IssuedBy: "human-b"})
	must(t, err)

	active := func(at time.Time, scopes ...Scope) []uuid.UUID {
		t.Helper()
		stops, err := s.ActiveStops(ctx, tenantA, at, scopes...)
		must(t, err)
		ids := make([]uuid.UUID, 0, len(stops))
		for _, stop := range stops {
			ids = append(ids, stop.ID)
		}
		return ids
	}
	sameIDs := func(what string, got []uuid.UUID, want ...uuid.UUID) {
		t.Helper()
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s: active stops %v, want %v", what, got, want)
		}
	}
	agentScope := Scope{Kind: ScopePrincipal, Key: "agent-a"}
	sameIDs("before expiry", active(now, agentScope), expiring.ID)
	sameIDs("a microsecond before expiry", active(expires.Add(-time.Microsecond), agentScope), expiring.ID)
	sameIDs("at expiry", active(expires, agentScope))
	sameIDs("after expiry", active(now.Add(2*time.Hour), agentScope))
	sameIDs("every scope after expiry", active(now.Add(2*time.Hour)), standing.ID)
	sameIDs("unrelated scope", active(now, Scope{Kind: ScopePrincipal, Key: "agent-b"}))

	past := now.Add(-time.Minute)
	_, err = s.Stop(ctx, tenantA, StopSpec{Scope: agentScope, Reason: "late", IssuedBy: "service-a", ExpiresAt: &past})
	wantErr(t, "a stop that expired before it was issued", err, ErrInvalid)
	_, err = s.Stop(ctx, tenantA, StopSpec{Scope: Scope{Kind: ScopePrincipal, Key: "nobody"}, Reason: "x", IssuedBy: "service-a"})
	wantErr(t, "a stop on a missing principal", err, ErrNotFound)

	version := func() int64 {
		return scalar[int64](t, db, tenantA, `SELECT version FROM authority_mandates WHERE mandate_id = $1`, m.ID)
	}
	before := version()
	for _, refused := range []struct {
		approval WideningApproval
		want     error
	}{
		{WideningApproval{}, ErrApprovalRequired},
		{WideningApproval{RequesterID: "agent-a"}, ErrApprovalRequired},
		{WideningApproval{RequesterID: "human-a", ApproverID: "human-a"}, ErrApproverNotDistinct},
		{WideningApproval{RequesterID: "agent-a", ApproverID: "agent-b"}, ErrApproverNotEligible},
		{WideningApproval{RequesterID: "agent-a", ApproverID: "ghost"}, ErrApproverNotEligible},
		{WideningApproval{RequesterID: "ghost", ApproverID: "human-a"}, ErrApproverNotEligible},
	} {
		wantErr(t, fmt.Sprintf("lift with %+v", refused.approval), s.Lift(ctx, tenantA, standing.ID, refused.approval), refused.want)
	}
	sameIDs("after refused lifts", active(now), expiring.ID, standing.ID)
	if version() != before {
		t.Fatal("a refused lift changed the mandate's version")
	}

	must(t, s.Lift(ctx, tenantA, standing.ID, WideningApproval{RequesterID: "agent-a", ApproverID: "human-b"}))
	sameIDs("after the approved lift", active(now), expiring.ID)
	if version() != before+1 {
		t.Fatalf("lift did not bump the scope's control row: %d -> %d", before, version())
	}
	var requester, approver string
	must(t, inTenant(t, db, tenantA, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT lift_requested_by, lift_approved_by FROM authority_stops WHERE stop_id = $1`, standing.ID).Scan(&requester, &approver)
	}))
	if requester != "agent-a" || approver != "human-b" {
		t.Fatalf("lift recorded requester %q and approver %q", requester, approver)
	}
	wantErr(t, "lift twice", s.Lift(ctx, tenantA, standing.ID, WideningApproval{RequesterID: "agent-a", ApproverID: "human-b"}), ErrInactive)
	wantErr(t, "lift a missing stop", s.Lift(ctx, tenantA, uuid.New(), WideningApproval{RequesterID: "agent-a", ApproverID: "human-b"}), ErrNotFound)

	// The schema refuses a lift or a root mandate that carries no approval,
	// whatever code writes it.
	err = inTenant(t, db, tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE authority_stops SET lifted_at = now() WHERE stop_id = $1`, expiring.ID)
		return err
	})
	wantConstraint(t, "lift without approval columns", err, "23514")
	err = inTenant(t, db, tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE authority_stops SET lifted_at = now(), lift_requested_by = 'human-a', lift_approved_by = 'human-a' WHERE stop_id = $1`, expiring.ID)
		return err
	})
	wantConstraint(t, "lift approved by its requester", err, "23514")
	err = inTenant(t, db, tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO authority_mandates (tenant_id, mandate_id, holder_id, depth, effect_types, valid_from, valid_until, created_by)
			VALUES ($1, $2, 'agent-a', 0, '{email.send}', now(), now() + interval '1 hour', 'agent-a')`, tenantA, uuid.New())
		return err
	})
	wantConstraint(t, "root mandate without an approver", err, "23514")
}

func wantConstraint(t *testing.T, what string, err error, code string) {
	t.Helper()
	var pgErr *pq.Error
	if !errors.As(err, &pgErr) || string(pgErr.Code) != code {
		t.Fatalf("%s: err = %v, want SQLSTATE %s", what, err, code)
	}
}

// Every narrowing transition bumps its scope's control row in the same
// transaction as its detail row; a refused one changes nothing; a narrowing
// waits for a transaction that holds the row FOR SHARE, as admission will;
// and version arithmetic fails instead of wrapping.
func TestPostgresEveryNarrowingBumpsItsControlRowVersion(t *testing.T) {
	s, db, _, _ := postgresStore(t)
	ctx := context.Background()
	seed(t, s, tenantA)
	now := dbNow(t, db)
	rootMandate, err := s.CreateMandate(ctx, tenantA, "agent-a", Terms{
		EffectTypes: []string{"email.send", "payment.transfer"}, PerCallLimit: amount(1000),
		ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(24 * time.Hour),
	}, root)
	must(t, err)
	child, err := s.Delegate(ctx, tenantA, rootMandate.ID, "agent-a", "agent-b", Terms{
		EffectTypes: []string{"email.send"}, PerCallLimit: amount(100),
		ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(12 * time.Hour),
	})
	must(t, err)

	type row struct{ table, where, key string }
	version := func(r row) int64 {
		return scalar[int64](t, db, tenantA, `SELECT version FROM `+r.table+` WHERE `+r.where+` = $1`, r.key)
	}
	tenantRow := row{"authority_tenants", "tenant_id", tenantA}
	principalRow := row{"authority_principals", "principal_id", "agent-b"}
	effectRow := row{"authority_effect_types", "effect_type", "payment.transfer"}
	rootRow := row{"authority_mandates", "mandate_id::text", rootMandate.ID.String()}
	childRow := row{"authority_mandates", "mandate_id::text", child.ID.String()}

	var tenantLimit, childLimit Limit
	var liftable Stop
	for _, step := range []struct {
		name string
		row  func() row
		op   func() error
		bump bool
	}{
		{"stop the tenant", func() row { return tenantRow }, func() error {
			_, err := s.Stop(ctx, tenantA, StopSpec{Scope: Scope{Kind: ScopeTenant, Key: tenantA}, Reason: "freeze", IssuedBy: "human-a"})
			return err
		}, true},
		{"stop a principal", func() row { return principalRow }, func() error {
			var err error
			liftable, err = s.Stop(ctx, tenantA, StopSpec{Scope: Scope{Kind: ScopePrincipal, Key: "agent-b"}, Reason: "loop", IssuedBy: "service-a"})
			return err
		}, true},
		{"stop an effect type", func() row { return effectRow }, func() error {
			_, err := s.Stop(ctx, tenantA, StopSpec{Scope: Scope{Kind: ScopeEffectType, Key: "payment.transfer"}, Reason: "fraud", IssuedBy: "human-a"})
			return err
		}, true},
		{"stop a mandate", func() row { return rootRow }, func() error {
			_, err := s.Stop(ctx, tenantA, StopSpec{Scope: Scope{Kind: ScopeMandate, Key: rootMandate.ID.String()}, Reason: "audit", IssuedBy: "human-a"})
			return err
		}, true},
		{"narrow a mandate", func() row { return rootRow }, func() error {
			_, err := s.Narrow(ctx, tenantA, rootMandate.ID, Terms{EffectTypes: []string{"email.send", "payment.transfer"}, PerCallLimit: amount(500),
				ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(24 * time.Hour)})
			return err
		}, true},
		{"add a tenant limit", func() row { return tenantRow }, func() error {
			var err error
			tenantLimit, err = s.CreateLimit(ctx, tenantA, LimitSpec{Unit: "usd_cents", Measure: "sum", Window: "month", Value: 100_000, Span: 1})
			return err
		}, true},
		{"add a mandate limit", func() row { return rootRow }, func() error {
			_, err := s.CreateLimit(ctx, tenantA, LimitSpec{MandateID: &rootMandate.ID, Unit: "effects", Measure: "count", Window: "day", Value: 50, Span: 1})
			return err
		}, true},
		{"add a delegated limit within the parent's", func() row { return childRow }, func() error {
			var err error
			childLimit, err = s.CreateLimit(ctx, tenantA, LimitSpec{MandateID: &child.ID, Unit: "effects", Measure: "count", Window: "day", Value: 50, Span: 1})
			return err
		}, true},
		{"lower a limit", func() row { return row{"authority_limits", "limit_id::text", childLimit.ID.String()} }, func() error {
			return s.LowerLimit(ctx, tenantA, childLimit.ID, 10)
		}, true},
		{"revoke a mandate", func() row { return childRow }, func() error { return s.Revoke(ctx, tenantA, child.ID) }, true},
		{"lift a stop (widening, approved)", func() row { return principalRow }, func() error {
			return s.Lift(ctx, tenantA, liftable.ID, WideningApproval{RequesterID: "agent-b", ApproverID: "human-a"})
		}, true},

		// Refused transitions leave the control row alone.
		{"narrow that widens", func() row { return rootRow }, func() error {
			_, err := s.Narrow(ctx, tenantA, rootMandate.ID, Terms{EffectTypes: []string{"email.send", "payment.transfer"}, PerCallLimit: amount(501),
				ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(24 * time.Hour)})
			return expect(err, ErrWidens)
		}, false},
		{"a delegated limit above the parent's", func() row { return rootRow }, func() error {
			grandchild, err := s.Delegate(ctx, tenantA, rootMandate.ID, "agent-a", "agent-c", Terms{
				EffectTypes: []string{"email.send"}, PerCallLimit: amount(10), ValidFrom: now, ValidUntil: now.Add(time.Hour)})
			if err != nil {
				return err
			}
			before := version(row{"authority_mandates", "mandate_id::text", grandchild.ID.String()})
			_, err = s.CreateLimit(ctx, tenantA, LimitSpec{MandateID: &grandchild.ID, Unit: "effects", Measure: "count", Window: "day", Value: 51, Span: 1})
			if err := expect(err, ErrWidens); err != nil {
				return err
			}
			if after := version(row{"authority_mandates", "mandate_id::text", grandchild.ID.String()}); after != before {
				return fmt.Errorf("refused limit bumped the grandchild from %d to %d", before, after)
			}
			return nil
		}, false},
		{"raise a limit", func() row { return row{"authority_limits", "limit_id::text", tenantLimit.ID.String()} }, func() error {
			return expect(s.LowerLimit(ctx, tenantA, tenantLimit.ID, 100_001), ErrWidens)
		}, false},
		{"revoke twice", func() row { return childRow }, func() error { return expect(s.Revoke(ctx, tenantA, child.ID), ErrInactive) }, false},
	} {
		before := version(step.row())
		if err := step.op(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		after := version(step.row())
		if step.bump && after != before+1 {
			t.Fatalf("%s: version %d -> %d, want a bump of one", step.name, before, after)
		}
		if !step.bump && after != before {
			t.Fatalf("%s: a refused transition moved the version %d -> %d", step.name, before, after)
		}
	}

	// A narrowing waits for a transaction holding its control row FOR SHARE.
	holder, err := db.Begin()
	must(t, err)
	_, err = holder.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA)
	must(t, err)
	_, err = holder.Exec(`SELECT version FROM authority_effect_types WHERE effect_type = 'email.send' FOR SHARE`)
	must(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := s.Stop(ctx, tenantA, StopSpec{Scope: Scope{Kind: ScopeEffectType, Key: "email.send"}, Reason: "blocked", IssuedBy: "human-a"})
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("a stop committed while admission held its control row FOR SHARE: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	must(t, holder.Commit())
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the stop never proceeded after the FOR SHARE holder committed")
	}

	// Version overflow is an error, and the stop is not written.
	must(t, inTenant(t, db, tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE authority_principals SET version = $1 WHERE principal_id = 'agent-c'`, int64(math.MaxInt64))
		return err
	}))
	stopsBefore := scalar[int](t, db, tenantA, `SELECT count(*) FROM authority_stops`)
	_, err = s.Stop(ctx, tenantA, StopSpec{Scope: Scope{Kind: ScopePrincipal, Key: "agent-c"}, Reason: "overflow", IssuedBy: "human-a"})
	wantConstraint(t, "version overflow", err, "22003")
	if got := scalar[int](t, db, tenantA, `SELECT count(*) FROM authority_stops`); got != stopsBefore {
		t.Fatal("a stop was written although its control row could not be bumped")
	}
}

func expect(err, want error) error {
	if !errors.Is(err, want) {
		return fmt.Errorf("err = %v, want %v", err, want)
	}
	return nil
}

// ADR-0004 B-I5 for the authority rows: a NOSUPERUSER NOBYPASSRLS role reads
// and writes only the tenant its transaction is bound to, through the store
// and through raw SQL.
func TestPostgresAuthorityRowsIsolateTenantsForARestrictedRole(t *testing.T) {
	_, owner, base, schema := postgresStore(t)
	ctx := context.Background()
	role := schema + "_gateway"
	statements := []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD 'rls-probe' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB`,
		`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + role,
		`GRANT SELECT, INSERT, UPDATE ON ` + strings.Join(postgresmigration.AuthorityRowTables, ", ") + ` TO ` + role,
	}
	for _, statement := range statements {
		if _, err := owner.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(`REVOKE ALL ON ALL TABLES IN SCHEMA ` + schema + ` FROM ` + role)
		_, _ = owner.Exec(`REVOKE ALL ON SCHEMA ` + schema + ` FROM ` + role)
		_, _ = owner.Exec(`DROP ROLE IF EXISTS ` + role)
	})
	parsed, err := url.Parse(withSearchPath(t, base, schema))
	must(t, err)
	parsed.User = url.UserPassword(role, "rls-probe")
	runtime, err := sql.Open("postgres", parsed.String())
	must(t, err)
	defer runtime.Close()
	s, err := New(runtime)
	must(t, err)

	seed(t, s, tenantA)
	seed(t, s, "tenant-b")
	now := dbNow(t, runtime)
	mandateA, err := s.CreateMandate(ctx, tenantA, "agent-a", Terms{
		EffectTypes: []string{"email.send"}, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
	}, root)
	must(t, err)
	limitA, err := s.CreateLimit(ctx, tenantA, LimitSpec{MandateID: &mandateA.ID, Unit: "effects", Measure: "count", Window: "day", Value: 5, Span: 1})
	must(t, err)
	stopA, err := s.Stop(ctx, tenantA, StopSpec{Scope: Scope{Kind: ScopePrincipal, Key: "agent-a"}, Reason: "a", IssuedBy: "human-a"})
	must(t, err)
	versionA := scalar[int64](t, runtime, tenantA, `SELECT version FROM authority_mandates WHERE mandate_id = $1`, mandateA.ID)

	// Tenant B holds principals with the same ids, and still cannot reach A.
	const b = "tenant-b"
	_, err = s.Delegate(ctx, b, mandateA.ID, "agent-a", "agent-b", Terms{EffectTypes: []string{"email.send"}, ValidFrom: now, ValidUntil: now.Add(time.Minute)})
	wantErr(t, "B delegates A's mandate", err, ErrNotFound)
	_, err = s.Chain(ctx, b, mandateA.ID)
	wantErr(t, "B reads A's chain", err, ErrNotFound)
	wantErr(t, "B revokes A's mandate", s.Revoke(ctx, b, mandateA.ID), ErrNotFound)
	_, err = s.Narrow(ctx, b, mandateA.ID, Terms{EffectTypes: []string{"email.send"}, ValidFrom: now, ValidUntil: now.Add(time.Minute)})
	wantErr(t, "B narrows A's mandate", err, ErrNotFound)
	_, err = s.Stop(ctx, b, StopSpec{Scope: Scope{Kind: ScopeMandate, Key: mandateA.ID.String()}, Reason: "b", IssuedBy: "human-a"})
	wantErr(t, "B stops A's mandate", err, ErrNotFound)
	_, err = s.Stop(ctx, b, StopSpec{Scope: Scope{Kind: ScopeTenant, Key: tenantA}, Reason: "b", IssuedBy: "human-a"})
	wantErr(t, "B stops tenant A", err, ErrInvalid)
	wantErr(t, "B lifts A's stop", s.Lift(ctx, b, stopA.ID, WideningApproval{RequesterID: "agent-a", ApproverID: "human-a"}), ErrNotFound)
	wantErr(t, "B lowers A's limit", s.LowerLimit(ctx, b, limitA.ID, 0), ErrNotFound)
	_, err = s.CreateLimit(ctx, b, LimitSpec{MandateID: &mandateA.ID, Unit: "effects", Measure: "count", Window: "day", Value: 1, Span: 1})
	wantErr(t, "B limits A's mandate", err, ErrNotFound)
	stopsB, err := s.ActiveStops(ctx, b, now)
	must(t, err)
	if len(stopsB) != 0 {
		t.Fatalf("tenant B sees tenant A's stops: %+v", stopsB)
	}
	if got := scalar[int64](t, runtime, tenantA, `SELECT version FROM authority_mandates WHERE mandate_id = $1`, mandateA.ID); got != versionA {
		t.Fatalf("tenant B's attempts moved A's mandate version %d -> %d", versionA, got)
	}

	// Raw SQL: no tenant bound sees nothing; B sees none of A; a row for A
	// written under B is refused.
	for _, table := range postgresmigration.AuthorityRowTables {
		var n int
		must(t, runtime.QueryRow(`SELECT count(*) FROM `+table).Scan(&n))
		if n != 0 {
			t.Fatalf("%s: %d rows visible with no tenant bound", table, n)
		}
		if got := scalar[int](t, runtime, b, `SELECT count(*) FROM `+table+` WHERE tenant_id = $1`, tenantA); got != 0 {
			t.Fatalf("%s: tenant B sees %d of tenant A's rows", table, got)
		}
	}
	for what, statement := range map[string]string{
		"a stop for A":   `INSERT INTO authority_stops (tenant_id, stop_id, scope_kind, scope_key, reason, issued_by) VALUES ('tenant-a', gen_random_uuid(), 'tenant', 'tenant-a', 'x', 'human-a')`,
		"a tenant row":   `INSERT INTO authority_tenants (tenant_id) VALUES ('tenant-c')`,
		"moving A's row": `UPDATE authority_principals SET tenant_id = 'tenant-a' WHERE tenant_id = 'tenant-b' AND principal_id = 'agent-c'`,
	} {
		err := inTenant(t, runtime, b, func(tx *sql.Tx) error {
			_, err := tx.Exec(statement)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Fatalf("tenant B wrote %s: err=%v", what, err)
		}
	}
}

// Delegation reads its chain under FOR SHARE, so a narrowing of the parent
// that has not committed yet makes it wait, and it then checks the child
// against the narrowed terms instead of the stale ones.
func TestPostgresDelegationWaitsForAConcurrentNarrowing(t *testing.T) {
	s, db, _, _ := postgresStore(t)
	ctx := context.Background()
	seed(t, s, tenantA)
	now := dbNow(t, db)
	window := Terms{EffectTypes: []string{"email.send"}, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	parentTerms := window
	parentTerms.PerCallLimit = amount(100)
	parent, err := s.CreateMandate(ctx, tenantA, "agent-a", parentTerms, root)
	must(t, err)

	narrowing, err := db.Begin()
	must(t, err)
	defer func() { _ = narrowing.Rollback() }()
	_, err = narrowing.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA)
	must(t, err)
	_, err = narrowing.Exec(`UPDATE authority_mandates SET per_call_limit = 10, version = version + 1 WHERE mandate_id = $1`, parent.ID)
	must(t, err)

	childTerms := window
	childTerms.PerCallLimit = amount(50) // within the committed 100, not within the pending 10
	done := make(chan error, 1)
	go func() {
		_, err := s.Delegate(ctx, tenantA, parent.ID, "agent-a", "agent-b", childTerms)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("delegation did not wait for the pending narrowing: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	must(t, narrowing.Commit())
	select {
	case err := <-done:
		wantErr(t, "delegation after the parent narrowed", err, ErrWidens)
	case <-time.After(10 * time.Second):
		t.Fatal("delegation never proceeded after the narrowing committed")
	}
}
