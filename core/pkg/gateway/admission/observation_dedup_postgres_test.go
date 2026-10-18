package admission

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// Two read-backs can both leave the database while an attempt is UNKNOWN.
// Their provider facts are retained by digest, while the exposure settles
// only once. The provider event ingress and its delivery ID are external to
// this service; this test does not pretend to authenticate an event.
func TestPostgresConcurrentObservationsDeduplicateAndKeepDistinctFacts(t *testing.T) {
	for _, mode := range []string{"duplicate", "distinct-same", "distinct-conflicting"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.notesLimit(5)
			entered, release := make(chan struct{}, 2), make(chan struct{})
			var calls atomic.Int32
			fake := &scripted{}
			fake.set(func(adapters.Effect) adapters.DispatchResult {
				return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: contracts.ReasonProviderError}
			}, func(effect adapters.Effect) adapters.ObserveResult {
				n := calls.Add(1)
				entered <- struct{}{}
				<-release
				result := succeeded(effect)
				if mode != "duplicate" {
					digest := sha256.Sum256([]byte(fmt.Sprintf("provider fact %d", n)))
					result.Observation.EvidenceDigest = digest[:]
				}
				if mode == "distinct-conflicting" && n == 2 {
					result.Outcome, result.Reason = adapters.OutcomeFailed, contracts.ReasonReadbackMismatch
				}
				return result
			})
			svc := f.withAdapter(fake)
			a := f.propose(human, quotaNote("parallel-observe"))
			unknown, _, err := svc.Dispatch(context.Background(), workload, a.ID)
			must(t, err)
			if unknown.State != "UNKNOWN" || unknown.Exposures[0].Kind != "held" {
				t.Fatalf("before observations = %+v", unknown)
			}
			type answer struct {
				a        Attempt
				existing bool
				err      error
			}
			answers := make(chan answer, 2)
			for range 2 {
				go func() {
					got, existing, err := svc.Observe(context.Background(), workload, a.ID)
					answers <- answer{got, existing, err}
				}()
			}
			<-entered
			<-entered
			close(release)
			var replayed int
			var settledOutcome string
			for range 2 {
				result := <-answers
				must(t, result.err)
				if result.a.State != "RECONCILED" ||
					(result.a.Outcome != "SUCCEEDED" && result.a.Outcome != "FAILED") ||
					(result.a.LatestObservation != nil && result.a.LatestObservation.Outcome != result.a.Outcome) {
					t.Fatalf("concurrent Observe = %+v", result.a)
				}
				if settledOutcome != "" && result.a.Outcome != settledOutcome {
					t.Fatalf("two callers saw different settlements: %s and %s", settledOutcome, result.a.Outcome)
				}
				settledOutcome = result.a.Outcome
				if result.existing {
					replayed++
				}
			}
			if replayed != 1 {
				t.Fatalf("%d Observe calls reported existing, want one", replayed)
			}
			wantRows := 1
			if mode != "duplicate" {
				wantRows = 2
			}
			if n := f.count(tenantA, `SELECT count(*) FROM authority_observations WHERE attempt_id = $1`, a.ID); n != wantRows {
				t.Fatalf("%d facts stored, want %d", n, wantRows)
			}
			if used := f.count(tenantA, `SELECT COALESCE(sum(used), 0)::int FROM authority_counters`); used != 1 {
				t.Fatalf("used = %d, want one settlement", used)
			}
			if reserved := f.count(tenantA, `SELECT COALESCE(sum(reserved), 0)::int FROM authority_counters`); reserved != 0 {
				t.Fatalf("reserved = %d, want zero", reserved)
			}
			again, existing, err := svc.Observe(context.Background(), workload, a.ID)
			must(t, err)
			if !existing || again.Version != unknown.Version+1 || calls.Load() != 2 {
				t.Fatalf("terminal replay = %+v existing=%t readbacks=%d", again, existing, calls.Load())
			}
			f.ledgerBalances()
		})
	}
}

func TestPostgresReconcileAndManualObserveRaceSettlesOnce(t *testing.T) {
	f := newFixture(t)
	f.notesLimit(5)
	entered, release := make(chan struct{}, 2), make(chan struct{})
	fake := &scripted{}
	fake.set(func(adapters.Effect) adapters.DispatchResult {
		return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: contracts.ReasonProviderError}
	}, func(effect adapters.Effect) adapters.ObserveResult {
		entered <- struct{}{}
		<-release
		return succeeded(effect)
	})
	svc := f.withAdapter(fake)
	a := f.propose(human, quotaNote("job-manual-race"))
	_, _, err := svc.Dispatch(context.Background(), workload, a.ID)
	must(t, err)
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _, err := svc.Reconcile(context.Background(), tenantA, workspace, a.ID, false)
		errCh <- err
	}()
	go func() {
		defer wg.Done()
		_, _, err := svc.Observe(context.Background(), workload, a.ID)
		errCh <- err
	}()
	<-entered
	<-entered
	close(release)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		must(t, err)
	}
	settled, err := svc.Get(context.Background(), human, a.ID)
	must(t, err)
	if settled.State != "RECONCILED" || settled.Outcome != "SUCCEEDED" || settled.Exposures[0].Kind != "confirmed" ||
		f.count(tenantA, `SELECT count(*) FROM authority_observations WHERE attempt_id = $1`, a.ID) != 1 ||
		f.count(tenantA, `SELECT COALESCE(sum(used), 0)::int FROM authority_counters`) != 1 {
		t.Fatalf("job/manual race = %+v", settled)
	}
	f.ledgerBalances()
}
