package admission

// The statements that read an attempt for a caller hold a caller with an episode
// claim to its own episode and principal (HELM-751 N1). The Postgres proofs show
// the effect; this shows, with no database, that every such statement carries
// the clause and binds the caller's own values to it, so removing the clause from
// any one of them fails here too.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

var errRecorded = errors.New("statement recorded")

type statement struct {
	query string
	args  []driver.NamedValue
}

// recorder is a database/sql driver that records each statement and answers
// every query with an error, so the statement under test is the last thing run.
type recorder struct {
	mu   sync.Mutex
	seen []statement
}

func (r *recorder) Open(string) (driver.Conn, error) { return &recorderConn{r}, nil }

type recorderConn struct{ r *recorder }

func (c *recorderConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (c *recorderConn) Close() error                        { return nil }
func (c *recorderConn) Begin() (driver.Tx, error)           { return recorderTx{}, nil }
func (c *recorderConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return recorderTx{}, nil
}
func (c *recorderConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.r.record(query, args)
	return driver.ResultNoRows, nil
}
func (c *recorderConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.r.record(query, args)
	return nil, errRecorded
}

type recorderTx struct{}

func (recorderTx) Commit() error   { return nil }
func (recorderTx) Rollback() error { return nil }

func (r *recorder) record(query string, args []driver.NamedValue) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, statement{query: strings.Join(strings.Fields(query), " "), args: append([]driver.NamedValue(nil), args...)})
}

// last is the newest statement that reads an attempt.
func (r *recorder) last(t *testing.T, from string) statement {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.seen) - 1; i >= 0; i-- {
		if strings.Contains(r.seen[i].query, from) {
			return r.seen[i]
		}
	}
	t.Fatalf("no statement from %s ran: %v", from, r.seen)
	return statement{}
}

var drivers atomic.Int64

func newRecordingService(t *testing.T) (*Service, *recorder, *sql.DB) {
	t.Helper()
	r := &recorder{}
	// A driver name is registered once per process; each test run takes its own.
	name := fmt.Sprintf("statement-recorder-%d", drivers.Add(1))
	sql.Register(name, r)
	db, err := sql.Open(name, "")
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	svc, err := New(db, Config{})
	must(t, err)
	return svc, r, db
}

const (
	loadClause    = "AND ($4 = '' OR (episode_id = $4 AND requester_principal_id = $5))"
	contentClause = "AND ($4 = '' OR (a.episode_id = $4 AND a.requester_principal_id = $5))"
	lockClause    = "AND ($4 = '' OR (episode_id = $4 AND requester_principal_id = $5)) FOR UPDATE"
	replayClause  = "AND ($4 = '' OR (a.episode_id = $4 AND a.requester_principal_id = $5))"
)

func TestReadStatementsHoldAnEpisodeCallerToItsOwnEpisodeAndPrincipal(t *testing.T) {
	ctx := context.Background()
	const id = "01a0f40b-8a64-7631-a316-836d4af5bb25"
	worker := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a", ActorID: actor,
		Episode: &Episode{EpisodeID: "ep-1", WorkItemID: "work-1"}}
	plain := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: actor}

	for name, test := range map[string]struct {
		from   string
		clause string
		run    func(svc *Service, db *sql.DB, c Caller) error
	}{
		"Get": {"FROM authority_effect_attempts WHERE tenant_id = $1 AND attempt_id = $2", loadClause,
			func(svc *Service, _ *sql.DB, c Caller) error { _, err := svc.Get(ctx, c, id); return err }},
		"GetContent": {"SELECT c.arguments FROM authority_attempt_contents", contentClause,
			func(svc *Service, _ *sql.DB, c Caller) error { _, err := svc.GetContent(ctx, c, id); return err }},
		"the lock that Dispatch, Observe and Cancel take": {"FOR UPDATE", lockClause,
			func(_ *Service, db *sql.DB, c Caller) error {
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					return err
				}
				defer func() { _ = tx.Rollback() }()
				_, err = lockAttempt(ctx, tx, c, id)
				return err
			}},
		"ModelCallReplay": {"FROM authority_model_replays", replayClause,
			func(svc *Service, _ *sql.DB, c Caller) error { _, err := svc.ModelCallReplay(ctx, c, id); return err }},
	} {
		t.Run(name, func(t *testing.T) {
			svc, r, db := newRecordingService(t)
			for caller, want := range map[string]struct {
				c         Caller
				ep, owner string
			}{"a worker": {worker, "ep-1", "agent-a"}, "the Control Plane": {plain, "", actor}} {
				if err := test.run(svc, db, want.c); err == nil || !errors.Is(err, errRecorded) {
					t.Fatalf("%s: the statement did not run to the recorder: %v", caller, err)
				}
				got := r.last(t, test.from)
				if !strings.Contains(got.query, test.clause) {
					t.Fatalf("%s: the statement lacks %q:\n%s", caller, test.clause, got.query)
				}
				// Tenant, attempt and workspace, then the episode and the principal
				// the clause holds the caller to: empty for a caller with no claim,
				// which the clause then lets through.
				values := make([]any, len(got.args))
				for i, a := range got.args {
					values[i] = a.Value
				}
				if len(values) != 5 || values[0] != tenantA || values[1] != id || values[2] != workspace || values[3] != want.ep || values[4] != want.owner {
					t.Fatalf("%s: bound values = %v, want the tenant, attempt, workspace, episode %q and principal %q", caller, values, want.ep, want.owner)
				}
			}
		})
	}
}
