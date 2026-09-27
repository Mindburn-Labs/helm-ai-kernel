package admission

import (
	"context"
	"database/sql"
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
// unresolved after the read-back is handed to a human: ESCALATED_TO_HUMAN,
// its reservation held.
func (s *Service) Reconcile(ctx context.Context, tenantID, workspaceID, attemptID string, final bool) (resolved bool, notBefore time.Time, err error) {
	if _, fence, err := s.observeAttempt(ctx, tenantID, workspaceID, attemptID); err != nil {
		return false, time.Time{}, err
	} else if !fence.IsZero() {
		return false, fence, nil
	}
	err = s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		a, err := lockAttempt(ctx, tx, Caller{TenantID: tenantID, WorkspaceID: workspaceID}, attemptID)
		if err != nil {
			return err
		}
		switch a.state {
		case "UNKNOWN", "DISPATCHED":
		default:
			resolved = true
			return nil
		}
		if !final {
			return nil
		}
		if a.state == "DISPATCHED" {
			if err := transition(ctx, tx, tenantID, attemptID, "DISPATCHED", "UNKNOWN", ""); err != nil {
				return err
			}
		}
		resolved = true
		return transition(ctx, tx, tenantID, attemptID, "UNKNOWN", "ESCALATED_TO_HUMAN", "")
	})
	return resolved, time.Time{}, err
}
