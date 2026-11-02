package authorityrows

// CTL-046 against real Postgres (listed in scripts/ci/postgres-proofs.txt),
// complementing store_postgres_test.go: every term of a mandate is held to the
// ceiling one at a time, a delegation is held to every mandate above it and
// not only its parent, a mandate narrowed after it was delegated still bounds
// what is delegated from beneath it, and a limit is held to the lowest limit
// above it at any depth. The same operations run on a scripted driver, without
// a database, in narrowing_scripted_test.go, where deleting each check is shown
// to fail them.

import (
	"context"
	"testing"
	"time"
)

// termsAround is a ceiling that sets every term, in a window of whole seconds
// the database stores exactly.
func termsAround(now time.Time) Terms {
	now = now.Truncate(time.Second)
	return Terms{
		EffectTypes: []string{"email.send", "repo.push"}, PerCallLimit: amount(100), ApprovalThreshold: amount(50),
		ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(9 * time.Hour),
		Targets:          []string{"github.com/o/a", "github.com/o/b"},
		ApprovalRequired: []string{"repo.push"}, RiskClasses: map[string]RiskClass{"repo.push": RiskHigh},
	}
}

func mandateCount(t *testing.T, s *Store) int {
	t.Helper()
	return scalar[int](t, s.db, tenantA, `SELECT count(*) FROM authority_mandates`)
}

// Allowed and forbidden: against a mandate that sets every term, a child that
// narrows any one term is stored, and a child that widens any one term is
// refused by name and writes nothing, whatever it narrows elsewhere.
func TestPostgresDelegationHoldsEveryTermToTheCeiling(t *testing.T) {
	s, db, _, _ := postgresStore(t)
	ctx := context.Background()
	seed(t, s, tenantA)
	ceiling := termsAround(dbNow(t, db))
	parent, err := s.CreateMandate(ctx, tenantA, "agent-a", ceiling, root)
	must(t, err)

	for _, test := range []struct {
		name string
		edit func(*Terms)
	}{
		{"the same terms", func(*Terms) {}},
		{"fewer effect types", func(t *Terms) { t.EffectTypes = []string{"repo.push"} }},
		{"a lower per-call limit", func(t *Terms) { t.PerCallLimit = amount(99) }},
		{"a lower approval threshold", func(t *Terms) { t.ApprovalThreshold = amount(0) }},
		{"a window inside", func(t *Terms) {
			t.ValidFrom, t.ValidUntil = t.ValidFrom.Add(time.Second), t.ValidUntil.Add(-time.Second)
		}},
		{"fewer targets", func(t *Terms) { t.Targets = []string{"github.com/o/b"} }},
		{"a raised risk class", func(t *Terms) { t.RiskClasses = map[string]RiskClass{"repo.push": RiskIrreversible} }},
		{"more approval requirements", func(t *Terms) { t.ApprovalRequired = []string{"email.send", "repo.push"} }},
	} {
		terms := ceiling
		test.edit(&terms)
		before := mandateCount(t, s)
		child, err := s.Delegate(ctx, tenantA, parent.ID, "agent-a", "agent-b", terms)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		stored, err := s.Chain(ctx, tenantA, child.ID)
		must(t, err)
		if got := stored[len(stored)-1]; mandateCount(t, s) != before+1 || got.Terms.Within(ceiling) != nil || got.Depth != 1 {
			t.Fatalf("%s: stored %+v", test.name, got)
		}
	}

	for _, test := range []struct {
		field string
		edit  func(*Terms)
	}{
		{"effect_types", func(t *Terms) { t.EffectTypes = []string{"email.send", "payment.transfer", "repo.push"} }},
		{"per_call_limit", func(t *Terms) { t.PerCallLimit = amount(101) }},
		{"per_call_limit", func(t *Terms) { t.PerCallLimit = nil }},
		{"approval_threshold", func(t *Terms) { t.ApprovalThreshold = amount(51) }},
		{"approval_threshold", func(t *Terms) { t.ApprovalThreshold = nil }},
		{"valid_from", func(t *Terms) { t.ValidFrom = t.ValidFrom.Add(-time.Second) }},
		{"valid_until", func(t *Terms) { t.ValidUntil = t.ValidUntil.Add(time.Second) }},
		{"targets", func(t *Terms) { t.Targets = nil }},
		{"targets", func(t *Terms) { t.Targets = []string{"github.com/o/a", "github.com/o/c"} }},
		{"risk_classes", func(t *Terms) { t.RiskClasses = map[string]RiskClass{"repo.push": RiskMedium} }},
		{"risk_classes", func(t *Terms) { t.RiskClasses = nil }},
		{"approval_required", func(t *Terms) { t.ApprovalRequired = nil }},
		// A narrowing in one term does not pay for a widening in another.
		{"valid_until", func(t *Terms) { t.PerCallLimit, t.ValidUntil = amount(1), t.ValidUntil.Add(time.Second) }},
	} {
		terms := ceiling
		test.edit(&terms)
		before := mandateCount(t, s)
		_, err := s.Delegate(ctx, tenantA, parent.ID, "agent-a", "agent-b", terms)
		wantErr(t, "a child wider in "+test.field, err, ErrWidens)
		wantWidens(t, "a child wider in "+test.field, err, test.field)
		if mandateCount(t, s) != before {
			t.Fatalf("a child wider in %s wrote a mandate", test.field)
		}
	}
}

// Bypass: a mandate narrowed in place leaves the rows beneath it as they were,
// so a mandate can be within its parent and wider than an ancestor. A
// delegation from it is held to the ancestor too; a narrowed mandate cannot be
// widened again, by narrowing it back or by delegating its old terms from it;
// and a revoked link, or a delegator who does not hold the parent, ends it.
func TestPostgresNarrowedAuthorityCannotBeRegainedThroughAnyLink(t *testing.T) {
	s, db, _, _ := postgresStore(t)
	ctx := context.Background()
	seed(t, s, tenantA)
	now := dbNow(t, db).Truncate(time.Second)
	wide := Terms{EffectTypes: []string{"email.send", "payment.transfer"}, PerCallLimit: amount(100),
		ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(9 * time.Hour)}
	narrow := Terms{EffectTypes: []string{"email.send"}, PerCallLimit: amount(40), ValidFrom: wide.ValidFrom, ValidUntil: wide.ValidUntil}

	top, err := s.CreateMandate(ctx, tenantA, "agent-a", wide, root)
	must(t, err)
	middle, err := s.Delegate(ctx, tenantA, top.ID, "agent-a", "agent-b", wide)
	must(t, err)
	narrowedTop, err := s.Narrow(ctx, tenantA, top.ID, narrow)
	must(t, err)
	if stored, err := s.Chain(ctx, tenantA, middle.ID); err != nil || stored[1].Terms.Within(narrow) == nil {
		t.Fatalf("the middle mandate was narrowed along with the top one (%+v, %v): the case needs a wider row beneath", stored, err)
	}

	// Within the middle mandate, outside the top one.
	for _, test := range []struct {
		name  string
		terms Terms
		field string
	}{
		{"a limit above the narrowed ancestor", Terms{EffectTypes: []string{"email.send"}, PerCallLimit: amount(60), ValidFrom: wide.ValidFrom, ValidUntil: wide.ValidUntil}, "per_call_limit"},
		{"an effect type the ancestor lost", Terms{EffectTypes: []string{"payment.transfer"}, PerCallLimit: amount(40), ValidFrom: wide.ValidFrom, ValidUntil: wide.ValidUntil}, "effect_types"},
		{"the middle mandate's own terms", wide, "effect_types"},
	} {
		before := mandateCount(t, s)
		_, err := s.Delegate(ctx, tenantA, middle.ID, "agent-b", "agent-c", test.terms)
		wantWidens(t, test.name, err, test.field)
		if mandateCount(t, s) != before {
			t.Fatalf("%s wrote a mandate", test.name)
		}
	}
	leafTerms := narrow
	leafTerms.PerCallLimit = amount(30)
	leaf, err := s.Delegate(ctx, tenantA, middle.ID, "agent-b", "agent-c", leafTerms)
	must(t, err)
	// And a level further down, the leaf bounds what is delegated from it: 35
	// is within the narrowed top's 40 and the middle's 100, so only the leaf's
	// 30 refuses it.
	_, err = s.Delegate(ctx, tenantA, leaf.ID, "agent-c", "agent-a", Terms{EffectTypes: []string{"email.send"}, PerCallLimit: amount(35), ValidFrom: wide.ValidFrom, ValidUntil: wide.ValidUntil})
	wantWidens(t, "a limit above the leaf's", err, "per_call_limit")

	// The narrowed mandate stays narrowed.
	_, err = s.Delegate(ctx, tenantA, top.ID, "agent-a", "agent-b", wide)
	wantWidens(t, "its old terms delegated from it", err, "effect_types")
	_, err = s.Narrow(ctx, tenantA, top.ID, wide)
	wantWidens(t, "narrowing it back", err, "effect_types")
	if got := scalar[int64](t, db, tenantA, `SELECT version FROM authority_mandates WHERE mandate_id = $1`, top.ID); got != narrowedTop.Version {
		t.Fatalf("a refused widening moved the version %d -> %d", narrowedTop.Version, got)
	}

	// Only the parent's holder delegates it.
	_, err = s.Delegate(ctx, tenantA, top.ID, "agent-c", "agent-c", narrow)
	wantErr(t, "a delegator who does not hold the parent", err, ErrNotDelegator)
	_, err = s.Delegate(ctx, tenantA, middle.ID, "agent-a", "agent-a", narrow)
	wantErr(t, "the top holder delegating the middle mandate", err, ErrNotDelegator)

	// A revoked intermediate ends everything beneath it.
	must(t, s.Revoke(ctx, tenantA, middle.ID))
	_, err = s.Delegate(ctx, tenantA, middle.ID, "agent-b", "agent-c", narrow)
	wantErr(t, "delegating a revoked mandate", err, ErrInactive)
	_, err = s.Delegate(ctx, tenantA, leaf.ID, "agent-c", "agent-a", leafTerms)
	wantErr(t, "delegating beneath a revoked mandate", err, ErrInactive)
}

// Bypass and forbidden: a limit is held to the lowest limit of its unit,
// measure, window and span on any mandate above it, not only its parent's, and
// no path raises one: not CreateLimit, not LowerLimit, not SetLimit.
func TestPostgresLimitsNeverExceedALimitAboveAtAnyDepth(t *testing.T) {
	s, db, _, _ := postgresStore(t)
	ctx := context.Background()
	seed(t, s, tenantA)
	now := dbNow(t, db)
	terms := Terms{EffectTypes: []string{"email.send"}, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(9 * time.Hour)}
	top, err := s.CreateMandate(ctx, tenantA, "agent-a", terms, root)
	must(t, err)
	middle, err := s.Delegate(ctx, tenantA, top.ID, "agent-a", "agent-b", terms)
	must(t, err)
	leaf, err := s.Delegate(ctx, tenantA, middle.ID, "agent-b", "agent-c", terms)
	must(t, err)

	_, err = s.CreateLimit(ctx, tenantA, dayCount(&top.ID, 100))
	must(t, err)
	limits := func() int { return scalar[int](t, db, tenantA, `SELECT count(*) FROM authority_limits`) }
	before := limits()
	// The middle mandate sets none, so only the top one bounds the leaf.
	_, err = s.CreateLimit(ctx, tenantA, dayCount(&leaf.ID, 101))
	wantWidens(t, "a leaf limit above the top mandate's", err, "limit_value")
	if limits() != before {
		t.Fatal("a refused limit was written")
	}
	// Another window is another limit, and is not bounded by this one.
	hourly := dayCount(&leaf.ID, 5000)
	hourly.Window = "hour"
	_, err = s.CreateLimit(ctx, tenantA, hourly)
	must(t, err)
	atCeiling, err := s.CreateLimit(ctx, tenantA, dayCount(&leaf.ID, 100))
	must(t, err)

	limitState := func() (value, version int64) {
		return scalar[int64](t, db, tenantA, `SELECT limit_value FROM authority_limits WHERE limit_id = $1`, atCeiling.ID),
			scalar[int64](t, db, tenantA, `SELECT version FROM authority_limits WHERE limit_id = $1`, atCeiling.ID)
	}
	value, version := limitState()
	wantWidens(t, "raise a limit", s.LowerLimit(ctx, tenantA, atCeiling.ID, 101), "limit_value")
	err = s.InTenant(ctx, tenantA, func(tx *Tx) error {
		_, err := tx.SetLimit(ctx, dayCount(&leaf.ID, 101))
		return err
	})
	wantWidens(t, "raise a limit by setting it", err, "limit_value")
	if v, ver := limitState(); v != value || ver != version {
		t.Fatalf("a refused raise moved the limit (%d, v%d) to (%d, v%d)", value, version, v, ver)
	}

	// Setting a lower value lowers it, and bumps its version.
	err = s.InTenant(ctx, tenantA, func(tx *Tx) error {
		_, err := tx.SetLimit(ctx, dayCount(&leaf.ID, 70))
		return err
	})
	must(t, err)
	if v, ver := limitState(); v != 70 || ver != version+1 {
		t.Fatalf("set to 70: limit (%d, v%d), want (70, v%d)", v, ver, version+1)
	}
}
