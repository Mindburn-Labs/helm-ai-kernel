package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type fakeService struct {
	notBefore time.Time
	resolved  bool
	finals    []bool
}

func (f *fakeService) ExpireEscalation(context.Context, string, string, string) (time.Time, error) {
	return f.notBefore, nil
}

func (f *fakeService) Reconcile(_ context.Context, _, _, _ string, final bool) (bool, time.Time, error) {
	f.finals = append(f.finals, final)
	return f.resolved, f.notBefore, nil
}

func reconcileJob(attempt, maxAttempts int) *river.Job[ReconcileArgs] {
	return &river.Job[ReconcileArgs]{JobRow: &rivertype.JobRow{Attempt: attempt, MaxAttempts: maxAttempts}}
}

func TestReconcileWorkerEscalatesOnlyOnTheLastAttempt(t *testing.T) {
	svc := &fakeService{}
	r := &Runner{cfg: Config{RetryBase: time.Second, RetryMax: time.Minute}}
	r.Bind(svc)
	w := &reconcileWorker{r: r}
	// Unresolved before the limit: retried, not escalated.
	if err := w.Work(context.Background(), reconcileJob(1, 3)); !errors.Is(err, errUnresolved) {
		t.Fatalf("an unresolved read-back = %v, want a retry", err)
	}
	// The last attempt asks the service to hand the attempt to a human.
	svc.resolved = true
	if err := w.Work(context.Background(), reconcileJob(3, 3)); err != nil {
		t.Fatal(err)
	}
	if len(svc.finals) != 2 || svc.finals[0] || !svc.finals[1] {
		t.Fatalf("final flags = %v, want [false true]", svc.finals)
	}
	// Inside a dispatch fence: snoozed, spending no attempt.
	svc.notBefore = time.Now().Add(time.Minute)
	var snooze *river.JobSnoozeError
	if err := w.Work(context.Background(), reconcileJob(1, 3)); !errors.As(err, &snooze) {
		t.Fatalf("inside the fence = %v, want a snooze", err)
	}
	e := &expireWorker{r: r}
	if err := e.Work(context.Background(), &river.Job[ExpireEscalationArgs]{JobRow: &rivertype.JobRow{}}); !errors.As(err, &snooze) {
		t.Fatalf("an early expiry = %v, want a snooze", err)
	}
}

func TestBackoffDoublesToItsCap(t *testing.T) {
	for attempt, want := range map[int]time.Duration{1: 30 * time.Second, 2: time.Minute, 3: 2 * time.Minute, 7: 30 * time.Minute, 20: 30 * time.Minute} {
		if got := Backoff(30*time.Second, 30*time.Minute, attempt); got != want {
			t.Errorf("attempt %d: %s, want %s", attempt, got, want)
		}
	}
}
