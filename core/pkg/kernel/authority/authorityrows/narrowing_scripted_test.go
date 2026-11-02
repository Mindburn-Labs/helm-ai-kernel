package authorityrows

// CTL-046 removal proofs that need no database. Each test runs one of the
// store's write operations on a scripted driver that serves exactly the
// statements the operation is supposed to issue, in order, and nothing else.
// A refusal therefore ends the script early: if the check that makes it is
// deleted, the operation goes on to a statement the script does not have, and
// the test fails on that. The effect of the statements on real rows (locks,
// versions, constraints, concurrent writers) is proved against Postgres in
// store_postgres_test.go and narrowing_postgres_test.go; nothing here reads
// HELM_TEST_POSTGRES_URL.

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// squashed makes whitespace irrelevant when a statement is matched.
func squashed(s string) string { return strings.Join(strings.Fields(s), " ") }

// statementContains matches a statement that contains the expected text.
var statementContains = sqlmock.QueryMatcherFunc(func(expected, actual string) error {
	if !strings.Contains(squashed(actual), squashed(expected)) {
		return fmt.Errorf("statement %q does not contain %q", squashed(actual), squashed(expected))
	}
	return nil
})

// scriptedTx returns a Tx over a transaction on a scripted driver.
func scriptedTx(t *testing.T) (*Tx, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(statementContains))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	return &Tx{tx: tx, tenantID: tenantA}, mock
}

// served fails the test when the script has statements left over: the
// operation stopped before a statement it should have issued.
func served(t *testing.T, what string, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("%s: %v", what, err)
	}
}

var mandateColumnNames = []string{"mandate_id", "parent_id", "depth", "holder_id", "effect_types", "per_call_limit",
	"approval_threshold", "valid_from", "valid_until", "status", "created_by", "approved_by", "version", "targets",
	"condition", "risk_classes", "approval_required"}

func nullableAmount(v *int64) driver.Value {
	if v == nil {
		return nil
	}
	return *v
}

func arrayValue(xs []string) driver.Value {
	if xs == nil {
		return nil
	}
	v, err := pq.StringArray(xs).Value()
	if err != nil {
		panic(err)
	}
	return v
}

func mandateRow(m Mandate) []driver.Value {
	var parent, approvedBy, condition, risks driver.Value
	if m.ParentID != nil {
		parent = m.ParentID.String()
	}
	if m.ApprovedBy != "" {
		approvedBy = m.ApprovedBy
	}
	if m.Terms.Condition != "" {
		condition = m.Terms.Condition
	}
	if len(m.Terms.RiskClasses) > 0 {
		encoded, err := json.Marshal(m.Terms.RiskClasses)
		if err != nil {
			panic(err)
		}
		risks = encoded
	}
	status := "revoked"
	if m.Active {
		status = "active"
	}
	return []driver.Value{m.ID.String(), parent, int64(m.Depth), m.HolderID, arrayValue(m.Terms.EffectTypes),
		nullableAmount(m.Terms.PerCallLimit), nullableAmount(m.Terms.ApprovalThreshold), m.Terms.ValidFrom, m.Terms.ValidUntil,
		status, m.CreatedBy, approvedBy, m.Version, arrayValue(m.Terms.Targets), condition, risks, arrayValue(m.Terms.ApprovalRequired)}
}

func mandateRows(chain ...Mandate) *sqlmock.Rows {
	rows := sqlmock.NewRows(mandateColumnNames)
	for _, m := range chain {
		rows.AddRow(mandateRow(m)...)
	}
	return rows
}

// ceilingTerms sets every term Within compares.
func ceilingTerms() Terms {
	return Terms{
		EffectTypes: []string{"email.send", "repo.push"}, PerCallLimit: amount(100), ApprovalThreshold: amount(50),
		ValidFrom: epoch, ValidUntil: epoch.Add(10 * time.Hour),
		Targets:          []string{"github.com/o/a", "github.com/o/b"},
		ApprovalRequired: []string{"repo.push"}, RiskClasses: map[string]RiskClass{"repo.push": RiskHigh},
	}
}

func edited(edit func(*Terms)) Terms {
	terms := ceilingTerms()
	edit(&terms)
	return terms
}

// rootOf and childOf build stored mandates of a chain.
func rootOf(holder string, terms Terms) Mandate {
	return Mandate{ID: uuid.Must(uuid.NewV7()), HolderID: holder, Terms: terms, Active: true,
		CreatedBy: "agent-a", ApprovedBy: "human-a", Version: 1}
}

func childOf(parent Mandate, holder string, terms Terms) Mandate {
	id := parent.ID
	return Mandate{ID: uuid.Must(uuid.NewV7()), ParentID: &id, Depth: parent.Depth + 1, HolderID: holder, Terms: terms,
		Active: true, CreatedBy: parent.HolderID, Version: 1}
}

// widenings is one edit per term, each making the terms wider than ceilingTerms
// in that term alone. The map key is the field Within reports.
var widenings = map[string]func(*Terms){
	"effect_types":       func(t *Terms) { t.EffectTypes = []string{"email.send", "payment.transfer", "repo.push"} },
	"per_call_limit":     func(t *Terms) { t.PerCallLimit = amount(101) },
	"approval_threshold": func(t *Terms) { t.ApprovalThreshold = nil },
	"valid_from":         func(t *Terms) { t.ValidFrom = epoch.Add(-time.Second) },
	"valid_until":        func(t *Terms) { t.ValidUntil = epoch.Add(10*time.Hour + time.Second) },
	"targets":            func(t *Terms) { t.Targets = nil },
	"risk_classes":       func(t *Terms) { t.RiskClasses = map[string]RiskClass{"repo.push": RiskMedium} },
	"approval_required":  func(t *Terms) { t.ApprovalRequired = nil },
}

// narrowings is one edit per term, each making a ceiling narrower in that term
// alone, as Narrow does to a mandate whose children keep their rows: a child
// that still has the old ceiling's terms now exceeds it in that term.
var narrowings = map[string]func(*Terms){
	"effect_types":       func(t *Terms) { t.EffectTypes, t.ApprovalRequired, t.RiskClasses = []string{"email.send"}, nil, nil },
	"per_call_limit":     func(t *Terms) { t.PerCallLimit = amount(40) },
	"approval_threshold": func(t *Terms) { t.ApprovalThreshold = amount(20) },
	"valid_from":         func(t *Terms) { t.ValidFrom = epoch.Add(time.Hour) },
	"valid_until":        func(t *Terms) { t.ValidUntil = epoch.Add(9 * time.Hour) },
	"targets":            func(t *Terms) { t.Targets = []string{"github.com/o/a"} },
	"risk_classes":       func(t *Terms) { t.RiskClasses = map[string]RiskClass{"repo.push": RiskIrreversible} },
	"approval_required":  func(t *Terms) { t.ApprovalRequired = []string{"email.send", "repo.push"} },
}

func wantWidens(t *testing.T, what string, err error, field string) {
	t.Helper()
	var widens *WidensError
	if !errors.As(err, &widens) || !errors.Is(err, ErrWidens) || widens.Field != field {
		t.Fatalf("%s: err = %v, want a widening of %s", what, err, field)
	}
}

// stopScopes matches the stop scopes a delegation checks, in order.
type stopScopes []string

func (s stopScopes) Match(v driver.Value) bool {
	want, err := pq.StringArray(s).Value()
	return err == nil && v == want
}

// expectDelegationReads scripts the statements Delegate issues before it reads
// the stops: the tenant row, the two principals and the chain.
func expectDelegationReads(mock sqlmock.Sqlmock, delegator, holder string, chain []Mandate) {
	mock.ExpectQuery("FROM authority_tenants WHERE tenant_id = $1 FOR SHARE").WithArgs(tenantA).
		WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(int64(1)))
	mock.ExpectQuery("FROM authority_principals").WithArgs(tenantA, sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"principal_id", "status"}).AddRow(delegator, "active").AddRow(holder, "active"))
	mock.ExpectQuery("WITH RECURSIVE chain").WithArgs(tenantA, chain[len(chain)-1].ID.String()).WillReturnRows(mandateRows(chain...))
}

func expectStopRead(mock sqlmock.Sqlmock, delegator string, chain []Mandate, stopped bool) {
	scopes := stopScopes{"tenant:" + tenantA, "principal:" + delegator}
	for _, link := range chain {
		scopes = append(scopes, "mandate:"+link.ID.String())
	}
	mock.ExpectQuery("FROM authority_stops").WithArgs(tenantA, scopes).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(stopped))
}

// Allowed: terms within every link of an active chain are stored as a child of
// the delegator's mandate, one level down, created by the delegator and
// approved by nobody (a delegation needs no approval; it only narrows).
func TestDelegateStoresTermsWithinEveryLinkOfTheChain(t *testing.T) {
	root := rootOf("agent-a", ceilingTerms())
	middle := childOf(root, "agent-b", edited(func(t *Terms) { t.PerCallLimit = amount(80); t.Targets = []string{"github.com/o/a"} }))
	chain := []Mandate{root, middle}
	child := edited(func(t *Terms) {
		t.PerCallLimit = amount(80) // at the middle link's ceiling
		t.Targets = []string{"github.com/o/a"}
		t.EffectTypes = []string{"repo.push"}
	})

	tx, mock := scriptedTx(t)
	expectDelegationReads(mock, "agent-b", "agent-c", chain)
	expectStopRead(mock, "agent-b", chain, false)
	mock.ExpectExec("INSERT INTO authority_mandates").WithArgs(tenantA, sqlmock.AnyArg(), "agent-c", middle.ID.String(), int64(2),
		arrayValue([]string{"repo.push"}), int64(80), int64(50), sqlmock.AnyArg(), sqlmock.AnyArg(), "agent-b", nil,
		arrayValue([]string{"github.com/o/a"}), nil, sqlmock.AnyArg(), arrayValue([]string{"repo.push"})).
		WillReturnResult(sqlmock.NewResult(0, 1))

	got, err := tx.Delegate(context.Background(), middle.ID, "agent-b", "agent-c", child)
	if err != nil {
		t.Fatal(err)
	}
	if got.ParentID == nil || *got.ParentID != middle.ID || got.Depth != 2 || got.CreatedBy != "agent-b" || got.ApprovedBy != "" || !got.Active {
		t.Fatalf("delegated mandate = %+v", got)
	}
	served(t, "delegation", mock)
}

// Forbidden: a child wider than its parent in any one term is refused, naming
// the term, and nothing is written (the script has no stop read and no insert).
func TestDelegateRefusesTermsWiderThanTheParentInAnyOneTerm(t *testing.T) {
	for field, widen := range widenings {
		root := rootOf("agent-a", ceilingTerms())
		parent := childOf(root, "agent-b", ceilingTerms())
		chain := []Mandate{root, parent}
		tx, mock := scriptedTx(t)
		expectDelegationReads(mock, "agent-b", "agent-c", chain)
		_, err := tx.Delegate(context.Background(), parent.ID, "agent-b", "agent-c", edited(widen))
		wantWidens(t, "a child wider in "+field, err, field)
		served(t, "a child wider in "+field, mock)
	}
}

// Bypass: the check is against every mandate above the parent, not the parent
// alone. A mandate narrowed in place leaves its children's rows as they were,
// so a child can be within its parent and wider than the root.
func TestDelegateRefusesTermsWiderThanAnAncestorTheParentExceeds(t *testing.T) {
	for field, narrow := range narrowings {
		root := rootOf("agent-a", edited(narrow))
		parent := childOf(root, "agent-b", ceilingTerms()) // the old width, now wider than root
		chain := []Mandate{root, parent}
		tx, mock := scriptedTx(t)
		expectDelegationReads(mock, "agent-b", "agent-c", chain)
		_, err := tx.Delegate(context.Background(), parent.ID, "agent-b", "agent-c", ceilingTerms())
		wantWidens(t, "a child within its parent, wider than the root in "+field, err, field)
		served(t, "a child wider than the root in "+field, mock)
	}
}

// Forbidden: a chain with a revoked link, a delegator who is not the parent's
// holder, and an active stop each refuse a delegation that is otherwise within.
func TestDelegateRefusesARevokedLinkAWrongDelegatorAndAnActiveStop(t *testing.T) {
	within := edited(func(t *Terms) { t.PerCallLimit = amount(10) })
	build := func() (Mandate, Mandate) {
		root := rootOf("agent-a", ceilingTerms())
		return root, childOf(root, "agent-b", ceilingTerms())
	}

	for name, revoke := range map[string]func(root, middle *Mandate){
		"a revoked root":         func(root, _ *Mandate) { root.Active = false },
		"a revoked intermediate": func(_, middle *Mandate) { middle.Active = false },
	} {
		root, middle := build()
		revoke(&root, &middle)
		chain := []Mandate{root, middle}
		tx, mock := scriptedTx(t)
		expectDelegationReads(mock, "agent-b", "agent-c", chain)
		_, err := tx.Delegate(context.Background(), middle.ID, "agent-b", "agent-c", within)
		wantErr(t, name, err, ErrMandateInactive)
		served(t, name, mock)
	}

	{
		root, middle := build()
		chain := []Mandate{root, middle}
		tx, mock := scriptedTx(t)
		expectDelegationReads(mock, "agent-a", "agent-c", chain) // agent-a holds the root, not the middle mandate
		_, err := tx.Delegate(context.Background(), middle.ID, "agent-a", "agent-c", within)
		wantErr(t, "a delegator who does not hold the parent", err, ErrNotDelegator)
		served(t, "a delegator who does not hold the parent", mock)
	}

	{
		root, middle := build()
		chain := []Mandate{root, middle}
		tx, mock := scriptedTx(t)
		expectDelegationReads(mock, "agent-b", "agent-c", chain)
		expectStopRead(mock, "agent-b", chain, true) // the scopes: the tenant, the delegator, every mandate of the chain
		_, err := tx.Delegate(context.Background(), middle.ID, "agent-b", "agent-c", within)
		wantErr(t, "an active stop", err, ErrStopped)
		served(t, "an active stop", mock)
	}
}

func narrowRead(mock sqlmock.Sqlmock, current Mandate) {
	mock.ExpectQuery("FROM authority_mandates m WHERE tenant_id = $1 AND mandate_id = $2 FOR NO KEY UPDATE").
		WithArgs(tenantA, current.ID.String()).WillReturnRows(mandateRows(current))
}

// Allowed: Narrow stores terms within the current ones, and bumps the
// mandate's own control row in the same statement. It may add a condition to a
// mandate that has none, and keep the one it has.
func TestNarrowStoresTermsWithinTheCurrentOnesAndBumpsTheVersion(t *testing.T) {
	const condition = `input.args.head.startsWith("helm/")`
	for name, test := range map[string]struct {
		current Mandate
		next    Terms
	}{
		"a lower limit": {rootOf("agent-a", ceilingTerms()), edited(func(t *Terms) { t.PerCallLimit = amount(10) })},
		"a condition added to a mandate with none": {rootOf("agent-a", ceilingTerms()), edited(func(t *Terms) { t.Condition = condition })},
		"the condition kept": {rootOf("agent-a", edited(func(t *Terms) { t.Condition = condition })),
			edited(func(t *Terms) { t.Condition = condition; t.PerCallLimit = amount(10) })},
	} {
		tx, mock := scriptedTx(t)
		narrowRead(mock, test.current)
		mock.ExpectQuery("approval_required = $11, version = version + 1 WHERE tenant_id = $1 AND mandate_id = $2 RETURNING version").
			WithArgs(append([]driver.Value{tenantA, test.current.ID.String()}, anyArgs(9)...)...).
			WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(int64(2)))
		got, err := tx.Narrow(context.Background(), test.current.ID, test.next)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Version != 2 {
			t.Fatalf("%s: version = %d, want the stored version 2", name, got.Version)
		}
		served(t, name, mock)
	}
}

func anyArgs(n int) []driver.Value {
	out := make([]driver.Value, n)
	for i := range out {
		out[i] = sqlmock.AnyArg()
	}
	return out
}

// Forbidden: Narrow refuses terms wider than the current ones in any one term,
// a revoked mandate, and a replaced condition; no UPDATE follows.
func TestNarrowRefusesWideningARevokedMandateAndAReplacedCondition(t *testing.T) {
	for field, widen := range widenings {
		current := rootOf("agent-a", ceilingTerms())
		tx, mock := scriptedTx(t)
		narrowRead(mock, current)
		_, err := tx.Narrow(context.Background(), current.ID, edited(widen))
		wantWidens(t, "narrowing to a wider "+field, err, field)
		served(t, "narrowing to a wider "+field, mock)
	}

	revoked := rootOf("agent-a", ceilingTerms())
	revoked.Active = false
	tx, mock := scriptedTx(t)
	narrowRead(mock, revoked)
	_, err := tx.Narrow(context.Background(), revoked.ID, ceilingTerms())
	wantErr(t, "narrowing a revoked mandate", err, ErrMandateInactive)
	served(t, "narrowing a revoked mandate", mock)

	const kept = `input.args.head.startsWith("helm/")`
	withCondition := rootOf("agent-a", edited(func(t *Terms) { t.Condition = kept }))
	for name, replacement := range map[string]string{
		"a dropped condition":  "",
		"a replaced condition": `input.args.head.startsWith("")`,
	} {
		tx, mock := scriptedTx(t)
		narrowRead(mock, withCondition)
		_, err := tx.Narrow(context.Background(), withCondition.ID, edited(func(t *Terms) { t.Condition = replacement }))
		wantWidens(t, name, err, "condition")
		served(t, name, mock)
	}
}

// Allowed and forbidden: Revoke narrows by marking the active row revoked and
// bumping its version in one statement; a second revoke changes nothing.
func TestRevokeBumpsTheVersionOnceAndRefusesASecondRevoke(t *testing.T) {
	const revoke = "UPDATE authority_mandates SET status = 'revoked', version = version + 1 WHERE tenant_id = $1 AND mandate_id = $2 AND status = 'active'"
	m := rootOf("agent-a", ceilingTerms())

	tx, mock := scriptedTx(t)
	mock.ExpectExec(revoke).WithArgs(tenantA, m.ID).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := tx.Revoke(context.Background(), m.ID); err != nil {
		t.Fatal(err)
	}
	served(t, "revoke", mock)

	m.Active = false
	tx, mock = scriptedTx(t)
	mock.ExpectExec(revoke).WithArgs(tenantA, m.ID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM authority_mandates m WHERE tenant_id = $1 AND mandate_id = $2").WithArgs(tenantA, m.ID.String()).WillReturnRows(mandateRows(m))
	wantErr(t, "revoke twice", tx.Revoke(context.Background(), m.ID), ErrMandateInactive)
	served(t, "revoke twice", mock)
}

const (
	bumpMandate = "UPDATE authority_mandates SET version = version + 1 WHERE tenant_id = $1 AND mandate_id = $2::uuid"
	bumpTenant  = "UPDATE authority_tenants SET version = version + 1 WHERE tenant_id = $1"
)

func dayCount(mandate *uuid.UUID, value int64) LimitSpec {
	return LimitSpec{MandateID: mandate, Unit: "effects", Measure: "count", Window: "day", Value: value, Span: 1}
}

func expectLimitReads(mock sqlmock.Sqlmock, chain []Mandate, ceiling driver.Value) {
	leaf := chain[len(chain)-1]
	mock.ExpectExec(bumpMandate).WithArgs(tenantA, leaf.ID.String()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("WITH RECURSIVE chain").WithArgs(tenantA, leaf.ID.String()).WillReturnRows(mandateRows(chain...))
	var ancestors []string
	for _, link := range chain[:len(chain)-1] {
		ancestors = append(ancestors, link.ID.String())
	}
	mock.ExpectQuery("SELECT min(limit_value)").
		WithArgs(tenantA, arrayValue(ancestors), "effects", "count", "day", int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"min"}).AddRow(ceiling))
}

// Allowed and forbidden: a limit on a delegated mandate is stored no higher
// than the lowest limit of the same unit, measure, window and span on any
// mandate above it, and bumps the mandate's control row first; a tenant limit
// bumps the tenant's. A higher one is refused and inserts nothing.
func TestCreateLimitStaysUnderTheLowestLimitAboveAndBumpsItsControlRow(t *testing.T) {
	grandparent := rootOf("agent-a", ceilingTerms())
	parent := childOf(grandparent, "agent-b", ceilingTerms())
	leaf := childOf(parent, "agent-c", ceilingTerms())
	chain := []Mandate{grandparent, parent, leaf}

	for _, value := range []int64{40, 100} {
		tx, mock := scriptedTx(t)
		expectLimitReads(mock, chain, int64(100))
		mock.ExpectExec("INSERT INTO authority_limits").WithArgs(tenantA, sqlmock.AnyArg(), leaf.ID.String(), "effects", "count", "day", value, int64(1)).
			WillReturnResult(sqlmock.NewResult(0, 1))
		if _, err := tx.CreateLimit(context.Background(), dayCount(&leaf.ID, value)); err != nil {
			t.Fatalf("a limit of %d under a ceiling of 100: %v", value, err)
		}
		served(t, "a limit within the ceiling", mock)
	}

	tx, mock := scriptedTx(t)
	expectLimitReads(mock, chain, int64(100))
	_, err := tx.CreateLimit(context.Background(), dayCount(&leaf.ID, 101))
	wantWidens(t, "a limit above an ancestor's", err, "limit_value")
	served(t, "a limit above an ancestor's", mock)

	// Nothing above sets the limit: any value stands.
	tx, mock = scriptedTx(t)
	expectLimitReads(mock, chain, nil)
	mock.ExpectExec("INSERT INTO authority_limits").WithArgs(tenantA, sqlmock.AnyArg(), leaf.ID.String(), "effects", "count", "day", int64(1_000_000), int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if _, err := tx.CreateLimit(context.Background(), dayCount(&leaf.ID, 1_000_000)); err != nil {
		t.Fatal(err)
	}
	served(t, "a limit nothing above sets", mock)

	tx, mock = scriptedTx(t)
	mock.ExpectExec(bumpTenant).WithArgs(tenantA).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO authority_limits").WithArgs(tenantA, sqlmock.AnyArg(), nil, "effects", "count", "day", int64(500), int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if _, err := tx.CreateLimit(context.Background(), dayCount(nil, 500)); err != nil {
		t.Fatal(err)
	}
	served(t, "a tenant limit", mock)
}

const lowerLimit = "UPDATE authority_limits SET limit_value = $3, version = version + 1 WHERE tenant_id = $1 AND limit_id = $2 AND limit_value >= $3"

// Allowed and forbidden: a limit is lowered, or kept, in one statement that
// bumps its version; a higher value updates no row and is reported as a
// widening, and an unknown limit as not found.
func TestLowerLimitBumpsTheVersionAndNeverRaises(t *testing.T) {
	limit := uuid.Must(uuid.NewV7())

	tx, mock := scriptedTx(t)
	mock.ExpectExec(lowerLimit).WithArgs(tenantA, limit, int64(10)).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := tx.LowerLimit(context.Background(), limit, 10); err != nil {
		t.Fatal(err)
	}
	served(t, "lower a limit", mock)

	tx, mock = scriptedTx(t)
	mock.ExpectExec(lowerLimit).WithArgs(tenantA, limit, int64(101)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT EXISTS (SELECT 1 FROM authority_limits WHERE tenant_id = $1 AND limit_id = $2)").WithArgs(tenantA, limit).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	wantWidens(t, "raise a limit", tx.LowerLimit(context.Background(), limit, 101), "limit_value")
	served(t, "raise a limit", mock)

	tx, mock = scriptedTx(t)
	mock.ExpectExec(lowerLimit).WithArgs(tenantA, limit, int64(1)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT EXISTS (SELECT 1 FROM authority_limits").WithArgs(tenantA, limit).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	wantErr(t, "lower an unknown limit", tx.LowerLimit(context.Background(), limit, 1), ErrNotFound)
	served(t, "lower an unknown limit", mock)

	tx, mock = scriptedTx(t)
	wantErr(t, "a negative limit", tx.LowerLimit(context.Background(), limit, -1), ErrInvalid)
	served(t, "a negative limit", mock)
}

var limitColumnNames = []string{"limit_id", "mandate_id", "unit", "measure", "window_kind", "limit_value", "span", "version"}

func limitRow(id uuid.UUID, mandate uuid.UUID, value int64) []driver.Value {
	return []driver.Value{id.String(), mandate.String(), "effects", "count", "day", value, int64(1), int64(1)}
}

// Allowed and forbidden: SetLimit lowers a limit the mandate already has and
// keeps one at its value, and refuses a value above the lowest stored one
// before it updates anything.
func TestSetLimitLowersOrKeepsAndRefusesToRaise(t *testing.T) {
	mandate := uuid.Must(uuid.NewV7())
	limit := uuid.Must(uuid.NewV7())
	read := func(mock sqlmock.Sqlmock) {
		mock.ExpectQuery("SELECT true FROM authority_mandates WHERE tenant_id = $1 AND mandate_id = $2 FOR NO KEY UPDATE").
			WithArgs(tenantA, mandate.String()).WillReturnRows(sqlmock.NewRows([]string{"found"}).AddRow(true))
		mock.ExpectQuery("FROM authority_limits WHERE tenant_id = $1 AND mandate_id IS NOT DISTINCT FROM $2").
			WithArgs(tenantA, mandate.String(), "effects", "count", "day", int64(1)).
			WillReturnRows(sqlmock.NewRows(limitColumnNames).AddRow(limitRow(limit, mandate, 100)...))
	}
	reread := func(mock sqlmock.Sqlmock, value int64) {
		mock.ExpectQuery("FROM authority_limits WHERE tenant_id = $1 AND limit_id = $2").WithArgs(tenantA, limit.String()).
			WillReturnRows(sqlmock.NewRows(limitColumnNames).AddRow(limitRow(limit, mandate, value)...))
	}

	tx, mock := scriptedTx(t)
	read(mock)
	mock.ExpectExec(lowerLimit).WithArgs(tenantA, limit, int64(40)).WillReturnResult(sqlmock.NewResult(0, 1))
	reread(mock, 40)
	got, err := tx.SetLimit(context.Background(), dayCount(&mandate, 40))
	if err != nil || got.Spec.Value != 40 {
		t.Fatalf("lower to 40: %+v, %v", got, err)
	}
	served(t, "lower by SetLimit", mock)

	tx, mock = scriptedTx(t)
	read(mock)
	reread(mock, 100)
	if _, err := tx.SetLimit(context.Background(), dayCount(&mandate, 100)); err != nil {
		t.Fatalf("keep at 100: %v", err)
	}
	served(t, "keep by SetLimit", mock)

	tx, mock = scriptedTx(t)
	read(mock)
	_, err = tx.SetLimit(context.Background(), dayCount(&mandate, 101))
	wantWidens(t, "raise by SetLimit", err, "limit_value")
	served(t, "raise by SetLimit", mock)
}

func approvalReads(mock sqlmock.Sqlmock, requester, approver string, eligible bool) {
	mock.ExpectQuery("SELECT EXISTS (SELECT 1 FROM authority_principals WHERE tenant_id = $1 AND principal_id = $2 AND status = 'active') "+
		"AND EXISTS (SELECT 1 FROM authority_principals WHERE tenant_id = $1 AND principal_id = $3 AND status = 'active' AND kind = 'human')").
		WithArgs(tenantA, requester, approver).WillReturnRows(sqlmock.NewRows([]string{"eligible"}).AddRow(eligible))
}

// Allowed and forbidden: a root mandate is stored only with an approval that
// names a requester and an approver who differ, an approver who is not the
// holder, and an approver the tenant knows as an active human.
func TestCreateMandateNeedsAnApprovalByADistinctEligibleApprover(t *testing.T) {
	terms := ceilingTerms()
	root := WideningApproval{RequesterID: "agent-b", ApproverID: "human-a"}

	tx, mock := scriptedTx(t)
	approvalReads(mock, "agent-b", "human-a", true)
	mock.ExpectQuery("SELECT status FROM authority_principals WHERE tenant_id = $1 AND principal_id = $2").WithArgs(tenantA, "agent-a").
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("active"))
	mock.ExpectQuery("SELECT count(*) FROM authority_effect_types").WithArgs(tenantA, arrayValue(terms.EffectTypes)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(len(terms.EffectTypes))))
	mock.ExpectExec("INSERT INTO authority_mandates").WithArgs(tenantA, sqlmock.AnyArg(), "agent-a", nil, int64(0),
		arrayValue(terms.EffectTypes), int64(100), int64(50), sqlmock.AnyArg(), sqlmock.AnyArg(), "agent-b", "human-a",
		sqlmock.AnyArg(), nil, sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	got, err := tx.CreateMandate(context.Background(), "agent-a", terms, root)
	if err != nil {
		t.Fatal(err)
	}
	if got.ParentID != nil || got.Depth != 0 || got.CreatedBy != "agent-b" || got.ApprovedBy != "human-a" || !got.Active {
		t.Fatalf("root mandate = %+v", got)
	}
	served(t, "a root mandate", mock)

	for name, test := range map[string]struct {
		holder   string
		approval WideningApproval
		want     error
	}{
		"no approval":            {"agent-a", WideningApproval{}, ErrApprovalRequired},
		"no approver":            {"agent-a", WideningApproval{RequesterID: "agent-b"}, ErrApprovalRequired},
		"self-approved":          {"agent-a", WideningApproval{RequesterID: "human-a", ApproverID: "human-a"}, ErrApproverNotDistinct},
		"approved by its holder": {"human-b", WideningApproval{RequesterID: "agent-b", ApproverID: "human-b"}, ErrApproverNotDistinct},
	} {
		tx, mock := scriptedTx(t)
		_, err := tx.CreateMandate(context.Background(), test.holder, terms, test.approval)
		wantErr(t, name, err, test.want)
		served(t, name, mock)
	}

	tx, mock = scriptedTx(t)
	approvalReads(mock, "agent-b", "agent-c", false) // agent-c is no human
	_, err = tx.CreateMandate(context.Background(), "agent-a", terms, WideningApproval{RequesterID: "agent-b", ApproverID: "agent-c"})
	wantErr(t, "an approver who is not an active human", err, ErrApproverNotEligible)
	served(t, "an approver who is not an active human", mock)
}
