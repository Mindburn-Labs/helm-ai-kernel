package jobs

// HELM-751 s3b against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): the escalation timer and the
// reconciliation polling as River jobs, worked by a runner over a restricted
// role that holds exactly the River grants the chart's 002_grants.sql gives
// helm_gateway.
//
// quantum_posture: computes SHA-256 digests only; signs nothing.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

const (
	tenant    = "tenant-a"
	workspace = "ws-a"
	runner    = "spiffe://helm/control-plane"
	noteType  = "ops.note"
)

var (
	human    = admission.Caller{TenantID: tenant, WorkspaceID: workspace, PrincipalID: "human-a", ActorID: runner}
	approver = admission.Caller{TenantID: tenant, WorkspaceID: workspace, PrincipalID: "human-b", ActorID: runner}
	workload = admission.Caller{TenantID: tenant, WorkspaceID: workspace, PrincipalID: runner}
)

// RiverGrants are the runtime role's privileges on River's tables: the rule
// the chart's 002_grants.sql extension point must give helm_gateway. The
// fixture grants exactly these, so every test here proves they suffice.
var RiverGrants = map[string]string{
	"river_job":          "SELECT, INSERT, UPDATE, DELETE",
	"river_leader":       "SELECT, INSERT, UPDATE, DELETE",
	"river_queue":        "SELECT, INSERT, UPDATE, DELETE",
	"river_notification": "SELECT, INSERT, UPDATE, DELETE",
	"river_migration":    "SELECT",
}

type fixture struct {
	t       *testing.T
	owner   *sql.DB
	runtime *sql.DB
	rows    *authorityrows.Store
	now     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the gateway job proofs")
	}
	schema := fmt.Sprintf("helm_gateway_jobs_%d", time.Now().UnixNano())
	role := schema + "_role"
	admin, err := sql.Open("postgres", base)
	must(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	_, err = admin.Exec(`CREATE SCHEMA ` + schema)
	must(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_, _ = admin.Exec(`DROP ROLE IF EXISTS ` + role)
	})
	owner, err := sql.Open("postgres", dsn(t, base, schema, ""))
	must(t, err)
	t.Cleanup(func() { _ = owner.Close() })
	ctx := context.Background()
	must(t, admission.Migrate(ctx, owner))
	must(t, Migrate(ctx, owner))

	var riverTables []string
	rows, err := owner.Query(`SELECT tablename FROM pg_tables WHERE schemaname = $1 AND tablename LIKE 'river\_%' ORDER BY 1`, schema)
	must(t, err)
	for rows.Next() {
		var name string
		must(t, rows.Scan(&name))
		riverTables = append(riverTables, name)
	}
	must(t, rows.Close())
	statements := []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD 'gateway-probe' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB`,
		`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + role,
		`GRANT SELECT, INSERT, UPDATE ON ` + strings.Join(append(append([]string{}, authorityrows.Tables...), admission.Tables...), ", ") + ` TO ` + role,
		`REVOKE UPDATE ON authority_postings FROM ` + role,
		`GRANT DELETE ON authority_token_replay TO ` + role,
		`GRANT SELECT ON gateway_schema_migrations TO ` + role,
	}
	seqs, err := owner.Query(`SELECT sequencename FROM pg_sequences WHERE schemaname = $1 AND sequencename LIKE 'river\_%'`, schema)
	must(t, err)
	for seqs.Next() {
		var name string
		must(t, seqs.Scan(&name))
		// A bigserial column needs USAGE on its sequence to insert.
		statements = append(statements, `GRANT USAGE ON SEQUENCE `+name+` TO `+role)
	}
	must(t, seqs.Close())
	for _, table := range riverTables {
		grant, ok := RiverGrants[table]
		if !ok {
			t.Fatalf("River table %s has no grant rule; add it to RiverGrants and to the chart's 002_grants.sql", table)
		}
		statements = append(statements, `GRANT `+grant+` ON `+table+` TO `+role)
	}
	for _, statement := range statements {
		_, err := owner.Exec(statement)
		must(t, err)
	}
	runtime, err := sql.Open("postgres", dsn(t, base, schema, role))
	must(t, err)
	t.Cleanup(func() { _ = runtime.Close() })
	store, err := authorityrows.New(owner)
	must(t, err)
	f := &fixture{t: t, owner: owner, runtime: runtime, rows: store}
	must(t, owner.QueryRow(`SELECT now()`).Scan(&f.now))
	must(t, store.CreateTenant(ctx, tenant))
	for id, kind := range map[string]authorityrows.PrincipalKind{"human-a": authorityrows.PrincipalHuman,
		"human-b": authorityrows.PrincipalHuman, "agent-a": authorityrows.PrincipalAgent, runner: authorityrows.PrincipalService} {
		must(t, store.CreatePrincipal(ctx, tenant, id, kind))
	}
	must(t, store.CreateEffectType(ctx, tenant, noteType, authorityrows.RiskLow))
	_, err = store.CreateMandate(ctx, tenant, "human-a", authorityrows.Terms{
		EffectTypes: []string{noteType}, Targets: []string{"ops"}, ValidFrom: f.now.Add(-time.Hour), ValidUntil: f.now.Add(24 * time.Hour),
	}, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-b"})
	must(t, err)
	return f
}

func dsn(t *testing.T, raw, schema, role string) string {
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

// start builds the service and a running job runner over the runtime role.
func (f *fixture) start(adapter adapters.Adapter, cfg Config, fence ...time.Duration) *admission.Service {
	f.t.Helper()
	r, err := New(f.runtime, cfg)
	must(f.t, err)
	acfg := admission.Config{Jobs: r, DispatchTimeout: 30 * time.Second}
	if len(fence) == 1 {
		acfg.DispatchTimeout, acfg.DispatchGrace = fence[0]/2, fence[0]/2
	}
	if adapter != nil {
		acfg.Adapters, acfg.Credentials = []adapters.Adapter{adapter}, credentials{}
	}
	svc, err := admission.New(f.runtime, acfg)
	must(f.t, err)
	r.Bind(svc)
	ctx, cancel := context.WithCancel(context.Background())
	must(f.t, r.Start(ctx))
	f.t.Cleanup(func() {
		cancel()
		stop, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = r.Stop(stop)
	})
	return svc
}

// waitFor polls the attempt until want accepts it.
func waitFor(t *testing.T, svc *admission.Service, id string, want func(admission.Attempt) bool) admission.Attempt {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		a, err := svc.Get(context.Background(), human, id)
		must(t, err)
		if want(a) {
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf("attempt %s stayed %s(%s)", id, a.State, a.Outcome)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func escalatedNote(t *testing.T, svc *admission.Service, key string, expires time.Time) admission.Attempt {
	t.Helper()
	in := admission.ProposeInput{IdempotencyKey: key, CaseID: "case-1", EffectType: noteType, Target: "ops",
		Arguments: []byte(`{"text":"hi"}`), ApprovalExpiresAt: &expires}
	a, _, err := svc.Propose(context.Background(), human, in)
	must(t, err)
	if a.State != "ESCALATED" {
		t.Fatalf("proposal = %s %s", a.State, a.ReasonCode)
	}
	return a
}

var jti atomic.Int64

func decide() admission.Token {
	return admission.Token{Issuer: "https://control-plane.test", ID: fmt.Sprintf("jti-%d", jti.Add(1)), Scope: "helm.gateway.decide",
		ExpiresAt: time.Now().Add(time.Minute)}
}

// approvalRequired makes every note need approval.
func (f *fixture) approvalRequired() {
	f.t.Helper()
	_, err := f.owner.Exec(`UPDATE authority_mandates SET approval_required = ARRAY['ops.note'] WHERE tenant_id = $1`, tenant)
	must(f.t, err)
}

func TestPostgresEscalationExpiresOnItsTimer(t *testing.T) {
	f := newFixture(t)
	f.approvalRequired()
	svc := f.start(nil, Config{PollInterval: 150 * time.Millisecond})
	a := escalatedNote(t, svc, "n1", time.Now().Add(2*time.Second))
	// The timer was inserted with the escalation.
	var jobs int
	must(t, f.owner.QueryRow(`SELECT count(*) FROM river_job WHERE kind = $1 AND args ->> 'attempt_id' = $2`,
		ExpireEscalationArgs{}.Kind(), a.ID).Scan(&jobs))
	if jobs != 1 {
		t.Fatalf("%d expiry jobs for one escalation", jobs)
	}
	expired := waitFor(t, svc, a.ID, func(a admission.Attempt) bool { return a.State != "ESCALATED" })
	if expired.State != "EXPIRED" || expired.ReasonCode != string(contracts.ReasonApprovalTimeout) || expired.Approval != nil {
		t.Fatalf("expired = %+v", expired)
	}
	// Approving an expired attempt changes nothing.
	got, existing, err := svc.Approve(context.Background(), approver, decide(),
		admission.DecideInput{AttemptID: a.ID, ApprovalDigest: a.ApprovalDigest})
	must(t, err)
	if !existing || got.State != "EXPIRED" {
		t.Fatalf("approval after expiry = %s existing=%v", got.State, existing)
	}
}

func TestPostgresApprovalAndExpiryMakeOneTransition(t *testing.T) {
	f := newFixture(t)
	f.approvalRequired()
	svc, err := admission.New(f.runtime, admission.Config{})
	must(t, err)
	ctx := context.Background()
	// Approved first: the timer finds nothing to expire.
	a := escalatedNote(t, svc, "approved", time.Now().Add(time.Hour))
	_, _, err = svc.Approve(ctx, approver, decide(), admission.DecideInput{AttemptID: a.ID, ApprovalDigest: a.ApprovalDigest})
	must(t, err)
	_, err = f.owner.Exec(`UPDATE authority_effect_attempts SET approval_expires_at = now() - interval '1 second' WHERE attempt_id = $1`, a.ID)
	must(t, err)
	_, err = svc.ExpireEscalation(ctx, tenant, workspace, a.ID)
	must(t, err)
	if got, _ := svc.Get(ctx, human, a.ID); got.State != "ADMITTED" {
		t.Fatalf("the timer changed an approved attempt: %s", got.State)
	}
	// Early: the timer reports the window's end and changes nothing.
	b := escalatedNote(t, svc, "early", time.Now().Add(time.Hour))
	notBefore, err := svc.ExpireEscalation(ctx, tenant, workspace, b.ID)
	must(t, err)
	if notBefore.IsZero() {
		t.Fatal("an escalation inside its window was expired")
	}
	// Racing at the boundary: exactly one of the two transitions commits.
	for i := 0; i < 20; i++ {
		c := escalatedNote(t, svc, fmt.Sprintf("race-%d", i), time.Now().Add(time.Hour))
		_, err = f.owner.Exec(`UPDATE authority_effect_attempts SET approval_expires_at = now() + interval '300 milliseconds' WHERE attempt_id = $1`, c.ID)
		must(t, err)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			time.Sleep(300 * time.Millisecond)
			_, _, _ = svc.Approve(ctx, approver, decide(), admission.DecideInput{AttemptID: c.ID, ApprovalDigest: c.ApprovalDigest})
		}()
		go func() {
			defer wg.Done()
			time.Sleep(300 * time.Millisecond)
			_, _ = svc.ExpireEscalation(ctx, tenant, workspace, c.ID)
		}()
		wg.Wait()
		got, err := svc.Get(ctx, human, c.ID)
		must(t, err)
		switch {
		case got.State == "ADMITTED" && got.Approval != nil:
		case got.State == "EXPIRED" && got.Approval == nil:
		case got.State == "ESCALATED" && got.Approval == nil:
			// Both ran just before the boundary by the database clock.
		default:
			t.Fatalf("race %d ended %s with approval %+v", i, got.State, got.Approval)
		}
	}
}

// scripted is a scripted adapter for the reconciliation proofs.
type scripted struct {
	mu       sync.Mutex
	dispatch func() adapters.DispatchResult
	observe  func(n int) adapters.ObserveResult
	observed int
	block    chan struct{}
}

func (s *scripted) Declarations() []adapters.Declaration {
	return []adapters.Declaration{{EffectType: noteType, Idempotent: adapters.IdempotentConditional, Observable: adapters.ObservableYes}}
}

func (s *scripted) Prepare(context.Context, adapters.TokenSource, adapters.Effect) (*adapters.Preparation, error) {
	return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "not used")
}

func (s *scripted) Dispatch(context.Context, adapters.TokenSource, adapters.Effect, []byte) adapters.DispatchResult {
	if s.block != nil {
		<-s.block
	}
	return s.dispatch()
}

func (s *scripted) Observe(context.Context, adapters.TokenSource, adapters.Effect) adapters.ObserveResult {
	s.mu.Lock()
	s.observed++
	n := s.observed
	s.mu.Unlock()
	return s.observe(n)
}

type credentials struct{}

func (credentials) Token(context.Context, string, adapters.Effect) (string, error) {
	return "token", nil
}

func indefinite() adapters.DispatchResult {
	return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: contracts.ReasonProviderError}
}

func succeeded() adapters.ObserveResult {
	digest := sha256.Sum256([]byte("provider bytes"))
	return adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded,
		Observation: &adapters.Observation{Source: "fake", TrustClass: "provider_readback", EvidenceDigest: digest[:]}}
}

func inconclusive() adapters.ObserveResult {
	return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: contracts.ReasonProviderError}
}

func fastPolling(maxAttempts int) Config {
	return Config{FirstPoll: 100 * time.Millisecond, RetryBase: 100 * time.Millisecond, RetryMax: 200 * time.Millisecond,
		MaxAttempts: maxAttempts, PollInterval: 150 * time.Millisecond}
}

func admittedNote(t *testing.T, svc *admission.Service, key string) admission.Attempt {
	t.Helper()
	a, _, err := svc.Propose(context.Background(), human, admission.ProposeInput{IdempotencyKey: key, CaseID: "case-1",
		EffectType: noteType, Target: "ops", Arguments: []byte(`{"text":"hi"}`)})
	must(t, err)
	if a.State != "ADMITTED" {
		t.Fatalf("proposal = %s %s", a.State, a.ReasonCode)
	}
	return a
}

func TestPostgresReconcilePollsUnknownToAnOutcome(t *testing.T) {
	f := newFixture(t)
	fake := &scripted{dispatch: indefinite, observe: func(n int) adapters.ObserveResult {
		if n < 3 {
			return inconclusive()
		}
		return succeeded()
	}}
	svc := f.start(fake, fastPolling(10))
	a := admittedNote(t, svc, "lost")
	got, _, err := svc.Dispatch(context.Background(), workload, a.ID)
	must(t, err)
	if got.State != "UNKNOWN" {
		t.Fatalf("dispatch = %s", got.State)
	}
	// Nobody calls Observe: the job reads back until the outcome is known.
	done := waitFor(t, svc, a.ID, func(a admission.Attempt) bool { return a.State != "UNKNOWN" })
	if done.State != "RECONCILED" || done.Outcome != "SUCCEEDED" {
		t.Fatalf("reconciled = %s(%s)", done.State, done.Outcome)
	}
}

func TestPostgresReconcileHandsAnUnresolvableAttemptToAHuman(t *testing.T) {
	f := newFixture(t)
	fake := &scripted{dispatch: indefinite, observe: func(int) adapters.ObserveResult { return inconclusive() }}
	svc := f.start(fake, fastPolling(3))
	a := admittedNote(t, svc, "lost")
	_, _, err := svc.Dispatch(context.Background(), workload, a.ID)
	must(t, err)
	done := waitFor(t, svc, a.ID, func(a admission.Attempt) bool { return a.State != "UNKNOWN" })
	if done.State != "ESCALATED_TO_HUMAN" || done.Outcome != "" {
		t.Fatalf("after the retry limit = %s(%s)", done.State, done.Outcome)
	}
	fake.mu.Lock()
	reads := fake.observed
	fake.mu.Unlock()
	if reads != 3 {
		t.Fatalf("%d read-backs, want the limit of 3", reads)
	}
}

func TestPostgresReconcileWaitsForTheDispatchFence(t *testing.T) {
	f := newFixture(t)
	release := make(chan struct{})
	fake := &scripted{block: release, dispatch: indefinite, observe: func(int) adapters.ObserveResult { return succeeded() }}
	svc := f.start(fake, fastPolling(10), 3*time.Second)
	a := admittedNote(t, svc, "hung")
	go func() { _, _, _ = svc.Dispatch(context.Background(), workload, a.ID) }()
	waitFor(t, svc, a.ID, func(a admission.Attempt) bool { return a.State == "DISPATCHING" })
	// Inside the fence the job waits: the dispatch may still be in flight.
	time.Sleep(500 * time.Millisecond)
	if got, _ := svc.Get(context.Background(), human, a.ID); got.State != "DISPATCHING" || fake.observed != 0 {
		t.Fatalf("the job read back inside the fence: %s, %d reads", got.State, fake.observed)
	}
	// Past the fence (a dead gateway) it reconciles, and never dispatches.
	done := waitFor(t, svc, a.ID, func(a admission.Attempt) bool { return a.State == "RECONCILED" })
	if done.Outcome != "SUCCEEDED" {
		t.Fatalf("reconciled = %s(%s)", done.State, done.Outcome)
	}
	close(release)
}
