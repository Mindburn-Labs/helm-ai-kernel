package admission

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// The jobs the gateway enqueues (TA §6.1-6.3): River jobs in the same
// Postgres, enqueued in the transaction that makes them due.
const (
	// JobExpireEscalation writes EXPIRED for an escalation past its window.
	JobExpireEscalation = "expire_escalation"
	// JobReconcile drives a dispatched attempt to an outcome by read-back.
	JobReconcile = "reconcile"
)

// Job is one job to enqueue. RunAt is when it is due; zero lets the queue
// apply its own first delay.
type Job struct {
	Kind        string
	TenantID    string
	WorkspaceID string
	AttemptID   string
	RunAt       time.Time
}

// Enqueuer inserts jobs in the caller's transaction, so a job exists exactly
// when the state change that needs it commits.
type Enqueuer interface {
	EnqueueTx(ctx context.Context, tx *sql.Tx, job Job) error
}

func (s *Service) enqueue(ctx context.Context, tx *sql.Tx, job Job) error {
	if s.cfg.Jobs == nil {
		return nil
	}
	return s.cfg.Jobs.EnqueueTx(ctx, tx, job)
}

// ExpireEscalation writes EXPIRED (APPROVAL_TIMEOUT) for an ESCALATED
// attempt whose approval window has passed. It locks the attempt FOR UPDATE,
// as Approve does, so an approval and the expiry make exactly one transition:
// whichever locks second finds the attempt no longer ESCALATED and changes
// nothing. It returns a non-zero time when the window has not passed yet by
// the database clock, for the job to run again then.
func (s *Service) ExpireEscalation(ctx context.Context, tenantID, workspaceID, attemptID string) (notBefore time.Time, err error) {
	err = s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		a, err := lockAttempt(ctx, tx, Caller{TenantID: tenantID, WorkspaceID: workspaceID}, attemptID)
		if err != nil {
			return err
		}
		if a.state != "ESCALATED" {
			return nil
		}
		if a.now.Before(a.approvalExpiresAt) {
			notBefore = a.approvalExpiresAt
			return nil
		}
		return transition(ctx, tx, tenantID, attemptID, "ESCALATED", "EXPIRED", contracts.ReasonApprovalTimeout)
	})
	return notBefore, err
}

// Reconcile reads a dispatched attempt back once, as Observe does, with no
// caller: the gateway itself drives it (TA §4.3). resolved is true once the
// attempt has an outcome or needs nothing more. A DISPATCHING attempt inside
// its fence returns the fence as notBefore. With final set, an attempt still
// unresolved is handed to a human (ESCALATED_TO_HUMAN, its reservation held)
// in a transaction of its own, whatever made the read-back fail: a missing
// adapter, lost content or a cancelled context must not leave it UNKNOWN with
// no job.
func (s *Service) Reconcile(ctx context.Context, tenantID, workspaceID, attemptID string, final bool) (resolved bool, notBefore time.Time, err error) {
	_, fence, readErr := s.observeAttempt(ctx, tenantID, workspaceID, attemptID)
	switch {
	case readErr == nil && !fence.IsZero():
		return false, fence, nil
	case readErr != nil && !final:
		return false, time.Time{}, readErr
	case readErr != nil:
		slog.ErrorContext(ctx, "the last reconciliation read-back failed; handing the attempt to a human",
			"attempt_id", attemptID, "error", readErr)
	}
	handoff, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	err = s.inTenant(handoff, tenantID, func(tx *sql.Tx) error {
		a, err := lockAttempt(handoff, tx, Caller{TenantID: tenantID, WorkspaceID: workspaceID}, attemptID)
		if err != nil {
			return err
		}
		switch a.state {
		case "UNKNOWN", "DISPATCHED", "DISPATCHING":
		default:
			resolved = true
			return nil
		}
		if !final {
			return nil
		}
		if a.state != "UNKNOWN" {
			if err := transition(handoff, tx, tenantID, attemptID, a.state, "UNKNOWN", ""); err != nil {
				return err
			}
		}
		resolved = true
		return transition(handoff, tx, tenantID, attemptID, "UNKNOWN", "ESCALATED_TO_HUMAN", "")
	})
	return resolved, time.Time{}, err
}
