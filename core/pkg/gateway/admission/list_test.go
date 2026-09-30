package admission

// ListAttempts without a database (HELM-751): a malformed request is refused
// before anything is read, a page token belongs to one listing, and no request
// value reaches the statement other than as a parameter. The Postgres proofs
// are in list_postgres_test.go.
//
// quantum_posture: compares SHA-256 filter digests carried in page tokens;
// signs nothing and makes no post-quantum claim.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// tokenFor is the page token a listing with filters in would issue after
// last, for caller.
func tokenFor(t *testing.T, caller Caller, in ListInput, last listPosition) string {
	t.Helper()
	q, err := parseList(caller, in)
	must(t, err)
	return encodePageToken(last, q.digest, somewhere.updatedAt.Add(-MaxTransaction-settledMargin))
}

var somewhere = listPosition{updatedAt: time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC), id: uuid.MustParse("0192f0c4-7a1e-7c3b-9d2a-1234567890ab")}

// untouchable is a database that counts the connections asked of it, notes the
// deadline of the context each was asked under (Unix nanoseconds, 0 for none),
// and gives none.
type untouchable struct {
	asked    *atomic.Int32
	deadline *atomic.Int64
}

func (u untouchable) Connect(ctx context.Context) (driver.Conn, error) {
	u.asked.Add(1)
	if d, ok := ctx.Deadline(); ok {
		u.deadline.Store(d.UnixNano())
	} else {
		u.deadline.Store(0)
	}
	return nil, errors.New("the database was touched")
}

func (untouchable) Driver() driver.Driver { return nil }

func TestListAttemptsRefusesMalformedRequestsBeforeTheDatabase(t *testing.T) {
	// A Service over a database nothing may reach: a refusal, with no
	// connection asked for, proves the request was validated before anything
	// was read.
	var asked atomic.Int32
	svc, err := New(sql.OpenDB(untouchable{&asked, new(atomic.Int64)}), Config{})
	must(t, err)
	ctx := context.Background()
	filters := ListInput{States: []string{"ESCALATED"}, EffectType: noteType}
	good := tokenFor(t, human, filters, somewhere)
	raw, err := base64.RawURLEncoding.DecodeString(good)
	must(t, err)
	withByte := func(i int, b byte) string {
		edited := append([]byte(nil), raw...)
		edited[i] = b
		return base64.RawURLEncoding.EncodeToString(edited)
	}
	q, err := parseList(human, filters)
	must(t, err)
	farFuture := encodePageToken(listPosition{updatedAt: time.UnixMicro(math.MaxInt64).UTC(), id: somewhere.id}, q.digest, somewhere.updatedAt)
	other := human
	other.WorkspaceID = "ws-b"

	for _, test := range []struct {
		name   string
		caller Caller
		in     ListInput
	}{
		{"an unknown state", human, ListInput{States: []string{"ESCALATED", "BOGUS"}}},
		{"a state in lower case", human, ListInput{States: []string{"escalated"}}},
		{"an empty state", human, ListInput{States: []string{""}}},
		{"both work references", human, ListInput{CommitmentID: "c", CaseID: "k"}},
		{"a commitment id over 255 bytes", human, ListInput{CommitmentID: strings.Repeat("c", 256)}},
		{"a case id over 255 bytes", human, ListInput{CaseID: strings.Repeat("k", 256)}},
		{"a requester over 255 bytes", human, ListInput{RequesterPrincipalID: strings.Repeat("p", 256)}},
		{"a NUL in a commitment id", human, ListInput{CommitmentID: "c\x00d"}},
		{"a NUL in a requester", human, ListInput{RequesterPrincipalID: "human-a\x00"}},
		{"a case id that is not UTF-8", human, ListInput{CaseID: "k\xff"}},
		{"an effect type with capitals", human, ListInput{EffectType: "Ops.Note"}},
		{"an effect type with a trailing newline", human, ListInput{EffectType: "ops.note\n"}},
		{"an effect type over 128 bytes", human, ListInput{EffectType: "a" + strings.Repeat("b", 128)}},
		{"an effect type starting with a digit", human, ListInput{EffectType: "1ops"}},
		{"updated_after past year 9999", human, ListInput{UpdatedAfter: timePtr(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))}},
		{"updated_after before year 1", human, ListInput{UpdatedAfter: timePtr(time.Date(0, 12, 31, 23, 59, 59, 0, time.UTC))}},
		{"a page size over 200", human, ListInput{PageSize: 201}},
		{"a negative page size", human, ListInput{PageSize: -1}},
		{"an enormous page size", human, ListInput{PageSize: math.MaxInt32}},
		{"a token that is not base64", human, ListInput{PageToken: "not a token!"}},
		{"a token with padding", human, ListInput{States: filters.States, EffectType: noteType, PageToken: good + "="}},
		{"a token with a newline inside", human, ListInput{States: filters.States, EffectType: noteType, PageToken: good[:10] + "\n" + good[10:]}},
		{"a token of another length", human, ListInput{PageToken: base64.RawURLEncoding.EncodeToString(raw[:len(raw)-1])}},
		{"a token of another version", human, ListInput{States: filters.States, EffectType: noteType, PageToken: withByte(0, pageTokenVersion+1)}},
		{"a token with a position that is no time", human, ListInput{States: filters.States, EffectType: noteType, PageToken: farFuture}},
		{"a token for other states", human, ListInput{States: []string{"ADMITTED"}, EffectType: noteType, PageToken: good}},
		{"a token for another effect type", human, ListInput{States: filters.States, EffectType: "other.type", PageToken: good}},
		{"a token for no filters", human, ListInput{PageToken: good}},
		{"a token for another workspace", other, ListInput{States: filters.States, EffectType: noteType, PageToken: good}},
	} {
		_, err := svc.List(ctx, test.caller, test.in)
		wantRefusal(t, test.name, err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	}

	// The caller comes from the token: one that names no tenant, workspace or
	// principal lists nothing.
	for _, caller := range []Caller{{WorkspaceID: workspace, PrincipalID: "human-a"}, {TenantID: tenantA, PrincipalID: "human-a"}, {TenantID: tenantA, WorkspaceID: workspace}} {
		_, err := svc.List(ctx, caller, ListInput{})
		wantRefusal(t, "a caller without its scope", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	if n := asked.Load(); n != 0 {
		t.Fatalf("%d connections were asked of the database for requests that were refused", n)
	}

	// Known good: the same shapes, well formed, are valid.
	for name, in := range map[string]ListInput{
		"every state":  {States: []string{"PROPOSED", "DENIED", "ESCALATED", "APPROVED", "REJECTED", "EXPIRED", "ADMITTED", "CANCELLED", "DISPATCHING", "DISPATCHED", "UNKNOWN", "OBSERVED", "RECONCILED", "ESCALATED_TO_HUMAN", "SETTLED", "COMPENSATED"}},
		"the caps":     {CommitmentID: strings.Repeat("c", 255), RequesterPrincipalID: strings.Repeat("p", 255), PageSize: 200, EffectType: "a" + strings.Repeat("b", 127)},
		"a case":       {CaseID: "case-1", PageSize: 1},
		"the minimum":  {UpdatedAfter: timePtr(time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC))},
		"the maximum":  {UpdatedAfter: timePtr(time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC))},
		"its own page": {States: filters.States, EffectType: noteType, PageToken: good},
	} {
		if _, err := parseList(human, in); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func timePtr(t time.Time) *time.Time { return &t }

func TestEveryTransactionBeginsUnderTheBound(t *testing.T) {
	// ListAttempts is final for what began before its settled_before, which
	// lies MaxTransaction and a margin back, only if no transaction runs
	// longer. Every one begins under a context that ends at the bound, however
	// it begins: the connector is handed that context, and notes its deadline.
	for _, test := range []struct {
		name   string
		cfg    Config
		caller time.Duration // the caller's own deadline, if it has one
		want   time.Duration // how far off the transaction's deadline is
	}{
		{"the default bound", Config{}, 0, MaxTransaction},
		{"a negative bound is the default", Config{MaxTransaction: -time.Second}, 0, MaxTransaction},
		{"a shorter bound", Config{MaxTransaction: 5 * time.Second}, 0, 5 * time.Second},
		{"a caller's earlier deadline stands", Config{}, 2 * time.Second, 2 * time.Second},
		{"a caller's later deadline does not lift it", Config{MaxTransaction: 5 * time.Second}, time.Hour, 5 * time.Second},
	} {
		var asked atomic.Int32
		var deadline atomic.Int64
		svc, err := New(sql.OpenDB(untouchable{&asked, &deadline}), test.cfg)
		must(t, err)
		caller := context.Background()
		if test.caller > 0 {
			var cancel context.CancelFunc
			caller, cancel = context.WithTimeout(caller, test.caller)
			defer cancel()
		}
		for way, begin := range map[string]func() error{
			"inTenant": func() error { return svc.inTenant(caller, tenantA, func(*sql.Tx) error { return nil }) },
			"List":     func() error { _, err := svc.List(caller, human, ListInput{}); return err },
		} {
			deadline.Store(0)
			if err := begin(); err == nil {
				t.Fatalf("%s, %s: the connector gave a connection", test.name, way)
			}
			at := deadline.Load()
			if at == 0 {
				t.Fatalf("%s, %s: the transaction begins without a deadline", test.name, way)
			}
			if left := time.Until(time.Unix(0, at)); left > test.want || left < test.want/2 {
				t.Fatalf("%s, %s: the transaction begins with %v left, want about %v", test.name, way, left, test.want)
			}
		}
	}
}

func TestListPageTokenIsBoundToItsFilters(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
	base := ListInput{States: []string{"ESCALATED", "ADMITTED"}, CommitmentID: "c1", RequesterPrincipalID: "human-a", EffectType: noteType, UpdatedAfter: &at}
	digest := func(caller Caller, in ListInput) string {
		t.Helper()
		q, err := parseList(caller, in)
		must(t, err)
		return string(q.digest)
	}
	want := digest(human, base)

	// The same listing is the same set of filters, however it is spelled.
	same := map[string]ListInput{
		"the states in another order":        {States: []string{"ADMITTED", "ESCALATED"}, CommitmentID: "c1", RequesterPrincipalID: "human-a", EffectType: noteType, UpdatedAfter: &at},
		"a state twice":                      {States: []string{"ESCALATED", "ADMITTED", "ESCALATED"}, CommitmentID: "c1", RequesterPrincipalID: "human-a", EffectType: noteType, UpdatedAfter: &at},
		"another page size":                  func() ListInput { in := base; in.PageSize = 7; return in }(),
		"the page token itself":              func() ListInput { in := base; in.PageToken = tokenFor(t, human, base, somewhere); return in }(),
		"updated_after in another zone":      func() ListInput { in := base; l := at.In(time.FixedZone("x", 3*3600)); in.UpdatedAfter = &l; return in }(),
		"updated_after with nanoseconds":     func() ListInput { in := base; l := at.Add(999 * time.Nanosecond); in.UpdatedAfter = &l; return in }(),
		"updated_after with a nanosecond":    func() ListInput { in := base; l := at.Add(time.Nanosecond); in.UpdatedAfter = &l; return in }(),
		"updated_after to the same microsec": func() ListInput { in := base; l := at.Add(500 * time.Nanosecond); in.UpdatedAfter = &l; return in }(),
	}
	for name, in := range same {
		if got := digest(human, in); got != want {
			t.Fatalf("%s: the filters digest changed", name)
		}
	}

	// Every filter, and the scope, is part of the binding.
	edit := func(f func(*ListInput)) ListInput { in := base; f(&in); return in }
	after := at.Add(time.Microsecond)
	differ := map[string]string{
		"other states":             digest(human, edit(func(in *ListInput) { in.States = []string{"ESCALATED"} })),
		"no states":                digest(human, edit(func(in *ListInput) { in.States = nil })),
		"another commitment":       digest(human, edit(func(in *ListInput) { in.CommitmentID = "c2" })),
		"the same value as a case": digest(human, edit(func(in *ListInput) { in.CommitmentID, in.CaseID = "", "c1" })),
		"no work reference":        digest(human, edit(func(in *ListInput) { in.CommitmentID = "" })),
		"another requester":        digest(human, edit(func(in *ListInput) { in.RequesterPrincipalID = "human-b" })),
		"another effect type":      digest(human, edit(func(in *ListInput) { in.EffectType = "other.type" })),
		"a later updated_after":    digest(human, edit(func(in *ListInput) { in.UpdatedAfter = &after })),
		"no updated_after":         digest(human, edit(func(in *ListInput) { in.UpdatedAfter = nil })),
		"another tenant":           digest(Caller{TenantID: tenantB, WorkspaceID: workspace, PrincipalID: "human-a"}, base),
		"another workspace":        digest(Caller{TenantID: tenantA, WorkspaceID: "ws-b", PrincipalID: "human-a"}, base),
	}
	seen := map[string]string{string(want): "the base listing"}
	for name, got := range differ {
		if prior, dup := seen[got]; dup {
			t.Fatalf("%s has the same filters digest as %s", name, prior)
		}
		seen[got] = name
	}
	// The principal is not a filter: the same workspace pages across the
	// tokens of different principals.
	if digest(Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-z"}, base) != want {
		t.Fatal("the token binds to the principal that listed, which the workspace's other principals cannot continue")
	}

	// A token round-trips its position to the microsecond, and only under its
	// own filters.
	token := tokenFor(t, human, base, somewhere)
	q, err := parseList(human, edit(func(in *ListInput) { in.PageToken = token }))
	must(t, err)
	if q.cursor == nil || !q.cursor.updatedAt.Equal(somewhere.updatedAt) || q.cursor.id != somewhere.id {
		t.Fatalf("the token continues from %+v, want %+v", q.cursor, somewhere)
	}
	if token == tokenFor(t, human, base, listPosition{updatedAt: somewhere.updatedAt.Add(time.Microsecond), id: somewhere.id}) ||
		token == tokenFor(t, human, base, listPosition{updatedAt: somewhere.updatedAt, id: uuid.MustParse("0192f0c4-7a1e-7c3b-9d2a-1234567890ac")}) {
		t.Fatal("a token does not tell one position from its neighbours")
	}
	// A token from before the epoch and one at the edge of the years the
	// listing accepts still round-trip.
	for _, edge := range []time.Time{time.Date(1969, 12, 31, 23, 59, 59, 999999000, time.UTC), time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)} {
		token := tokenFor(t, human, base, listPosition{updatedAt: edge, id: somewhere.id})
		q, err := parseList(human, edit(func(in *ListInput) { in.PageToken = token }))
		must(t, err)
		if !q.cursor.updatedAt.Equal(edge) {
			t.Fatalf("a token at %v continues from %v", edge, q.cursor.updatedAt)
		}
	}
}

func TestListStatementBindsEveryValueAsAParameter(t *testing.T) {
	hostile := "x'; DROP TABLE authority_effect_attempts; --"
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	in := ListInput{
		States: []string{"ESCALATED"}, CaseID: hostile, RequesterPrincipalID: hostile, EffectType: noteType, UpdatedAfter: &at, PageSize: 7,
	}
	in.PageToken = tokenFor(t, human, in, somewhere)
	q, err := parseList(human, in)
	must(t, err)
	statement, args := q.statement(human)
	if strings.Contains(statement, "x'") || strings.Contains(statement, "DROP") || strings.Contains(statement, human.TenantID) {
		t.Fatalf("a value is in the statement text: %s", statement)
	}
	// Tenant and workspace first, then each filter, the cursor's position, and
	// one row past the page.
	if len(args) != 10 || args[0] != human.TenantID || args[1] != human.WorkspaceID || args[len(args)-1] != 8 {
		t.Fatalf("args = %v", args)
	}
	for _, want := range []string{"tenant_id = $1", "workspace_id = $2", "state = ANY($3)", "case_id = $4", "requester_principal_id = $5", "effect_type = $6",
		"updated_at > $7", "(updated_at, attempt_id) > ($8::timestamptz, $9::uuid)", "ORDER BY updated_at, attempt_id LIMIT $10"} {
		if !strings.Contains(statement, want) {
			t.Fatalf("the statement lacks %q: %s", want, statement)
		}
	}
	// Without filters the statement is the tenant, the workspace and the page.
	q, err = parseList(human, ListInput{})
	must(t, err)
	statement, args = q.statement(human)
	if len(args) != 3 || args[2] != defaultListPageSize+1 || strings.Contains(statement, "state") {
		t.Fatalf("an unfiltered statement = %s %v", statement, args)
	}
}
