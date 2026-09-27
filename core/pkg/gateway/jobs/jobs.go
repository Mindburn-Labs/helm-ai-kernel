// Package jobs runs the effect gateway's timers and polling as River jobs in
// the gateway's own Postgres (target architecture §6.1-6.3, HELM-751 s3b):
//
//   - expire_escalation, enqueued in the transaction that escalates an
//     attempt, due at its approval_expires_at: it writes EXPIRED, fenced
//     against Approve by the attempt's row lock;
//   - reconcile, enqueued in the dispatch claim's transaction: it reads the
//     attempt back with backoff until it has an outcome, and hands it to a
//     human (ESCALATED_TO_HUMAN) when the attempts run out. It never
//     dispatches.
//
// River is the target architecture's named job runner. The gateway uses its
// database/sql driver over the same lib/pq pool as admission, so a job is
// inserted in the admission transaction itself (transactional enqueueing),
// and works it in poll-only mode, since that driver has no LISTEN. River's
// tables carry no tenant data beyond the IDs in job arguments; every job
// binds its own transaction to the tenant it names, as a request does.
package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// ExpireEscalationArgs is an expire_escalation job.
type ExpireEscalationArgs struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	AttemptID   string `json:"attempt_id"`
}

// Kind implements river.JobArgs.
func (ExpireEscalationArgs) Kind() string { return "helm_gateway_expire_escalation" }

// ReconcileArgs is a reconcile job.
type ReconcileArgs struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	AttemptID   string `json:"attempt_id"`
}

// Kind implements river.JobArgs.
func (ReconcileArgs) Kind() string { return "helm_gateway_reconcile" }

// Config tunes the jobs. Zero values take the defaults.
type Config struct {
	// FirstPoll is how long after the claim the first read-back runs.
	// Default 30s.
	FirstPoll time.Duration
	// RetryBase is the first retry's delay; each retry doubles it, up to
	// RetryMax. Defaults 30s and 30m.
	RetryBase, RetryMax time.Duration
	// MaxAttempts bounds the read-backs before an attempt is handed to a
	// human. Default 12 (about four hours with the default backoff).
	MaxAttempts int
	// PollInterval is how often the queue is polled. Default 1s.
	PollInterval time.Duration
}

func (c *Config) defaults() {
	if c.FirstPoll <= 0 {
		c.FirstPoll = 30 * time.Second
	}
	if c.RetryBase <= 0 {
		c.RetryBase = 30 * time.Second
	}
	if c.RetryMax <= 0 {
		c.RetryMax = 30 * time.Minute
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 12
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Second
	}
}

// Service is what the workers drive: *admission.Service.
type Service interface {
	ExpireEscalation(ctx context.Context, tenantID, workspaceID, attemptID string) (time.Time, error)
	Reconcile(ctx context.Context, tenantID, workspaceID, attemptID string, final bool) (bool, time.Time, error)
}

// Runner enqueues and works the gateway's jobs. It implements
// admission.Enqueuer. Bind the admission service before Start.
type Runner struct {
	cfg    Config
	client *river.Client[*sql.Tx]
	svc    atomic.Value // Service
}

// New builds a Runner over db, whose River tables Migrate has created.
func New(db *sql.DB, cfg Config) (*Runner, error) {
	cfg.defaults()
	r := &Runner{cfg: cfg}
	workers := river.NewWorkers()
	river.AddWorker(workers, &expireWorker{r: r})
	river.AddWorker(workers, &reconcileWorker{r: r})
	client, err := river.NewClient(riverdatabasesql.New(db), &river.Config{
		Queues:            map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 10}},
		Workers:           workers,
		PollOnly:          true,
		FetchPollInterval: cfg.PollInterval,
		// A read-back is bounded by the gateway's dispatch timeout (2m).
		JobTimeout: 5 * time.Minute,
		Logger:     slog.Default(),
	})
	if err != nil {
		return nil, err
	}
	r.client = client
	return r, nil
}

// Bind gives the workers the service they drive.
func (r *Runner) Bind(svc Service) { r.svc.Store(&svc) }

func (r *Runner) service() Service { return *r.svc.Load().(*Service) }

// Start works jobs until Stop.
func (r *Runner) Start(ctx context.Context) error {
	if r.svc.Load() == nil {
		return errors.New("jobs: Bind the admission service before Start")
	}
	return r.client.Start(ctx)
}

// Run starts the runner, retrying every retry while the database is
// unreachable or its River tables are not migrated yet (serve keeps its
// health port up and /readyz says why), until ctx ends.
func (r *Runner) Run(ctx context.Context, retry time.Duration) {
	for {
		err := r.Start(ctx)
		if err == nil {
			return
		}
		slog.WarnContext(ctx, "the job runner could not start; retrying", "error", err, "retry", retry)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
	}
}

// Stop waits for running jobs to finish.
func (r *Runner) Stop(ctx context.Context) error { return r.client.Stop(ctx) }

// EnqueueTx implements admission.Enqueuer: the job is inserted in tx.
func (r *Runner) EnqueueTx(ctx context.Context, tx *sql.Tx, job admission.Job) error {
	var args river.JobArgs
	opts := &river.InsertOpts{ScheduledAt: job.RunAt}
	switch job.Kind {
	case admission.JobExpireEscalation:
		args = ExpireEscalationArgs{TenantID: job.TenantID, WorkspaceID: job.WorkspaceID, AttemptID: job.AttemptID}
	case admission.JobReconcile:
		args = ReconcileArgs{TenantID: job.TenantID, WorkspaceID: job.WorkspaceID, AttemptID: job.AttemptID}
		opts.MaxAttempts = r.cfg.MaxAttempts
		if job.RunAt.IsZero() {
			opts.ScheduledAt = time.Now().Add(r.cfg.FirstPoll)
		}
	default:
		return fmt.Errorf("jobs: unknown job kind %q", job.Kind)
	}
	_, err := r.client.InsertTx(ctx, tx, args, opts)
	return err
}

// expireWorker writes EXPIRED once the window has passed.
type expireWorker struct {
	river.WorkerDefaults[ExpireEscalationArgs]
	r *Runner
}

func (w *expireWorker) Work(ctx context.Context, job *river.Job[ExpireEscalationArgs]) error {
	a := job.Args
	notBefore, err := w.r.service().ExpireEscalation(ctx, a.TenantID, a.WorkspaceID, a.AttemptID)
	if err != nil {
		return err
	}
	if !notBefore.IsZero() {
		return river.JobSnooze(time.Until(notBefore) + time.Second)
	}
	return nil
}

// errUnresolved retries a reconcile job whose read-back was inconclusive.
var errUnresolved = errors.New("the attempt is still unresolved; reading back again later")

// reconcileWorker reads an attempt back until it has an outcome; its last
// attempt hands an unresolved attempt to a human.
type reconcileWorker struct {
	river.WorkerDefaults[ReconcileArgs]
	r *Runner
}

func (w *reconcileWorker) Work(ctx context.Context, job *river.Job[ReconcileArgs]) error {
	a := job.Args
	final := job.Attempt >= job.MaxAttempts
	resolved, notBefore, err := w.r.service().Reconcile(ctx, a.TenantID, a.WorkspaceID, a.AttemptID, final)
	switch {
	case err != nil:
		return err
	case !notBefore.IsZero():
		// A dispatch possibly in flight: wait for its fence, spending no
		// attempt.
		return river.JobSnooze(time.Until(notBefore) + time.Second)
	case resolved:
		return nil
	}
	return errUnresolved
}

// NextRetry doubles the delay from RetryBase up to RetryMax.
func (w *reconcileWorker) NextRetry(job *river.Job[ReconcileArgs]) time.Time {
	return time.Now().Add(Backoff(w.r.cfg.RetryBase, w.r.cfg.RetryMax, job.Attempt))
}

// Backoff is the delay before read-back attempt+1: base doubled per attempt,
// capped at max.
func Backoff(base, maxDelay time.Duration, attempt int) time.Duration {
	d := base
	for i := 1; i < attempt && d < maxDelay; i++ {
		d *= 2
	}
	return min(d, maxDelay)
}

// Migrate applies River's migrations to db (helm-gateway migrate).
func Migrate(ctx context.Context, db *sql.DB) error {
	migrator, err := rivermigrate.New(riverdatabasesql.New(db), nil)
	if err != nil {
		return err
	}
	_, err = migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	return err
}

// Ready reports whether River's schema in db is at this binary's version
// (/readyz).
func Ready(ctx context.Context, db *sql.DB) error {
	migrator, err := rivermigrate.New(riverdatabasesql.New(db), nil)
	if err != nil {
		return err
	}
	res, err := migrator.Validate(ctx, nil)
	if err != nil {
		return err
	}
	if !res.OK {
		return fmt.Errorf("river schema is not current: %v; run helm-gateway migrate", res.Messages)
	}
	return nil
}
