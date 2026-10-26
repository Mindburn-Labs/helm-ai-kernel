package admission

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// The adapter replaces only the external provider transport. Admission,
// consumed permit, dispatch claim and recovery state are native PostgreSQL.
type recoveryProcessAdapter struct {
	scripted
	endpoint string
}

func (a *recoveryProcessAdapter) Dispatch(ctx context.Context, _ adapters.TokenSource, e adapters.Effect, digest []byte) adapters.DispatchResult {
	if r := adapters.CheckPermitDigest(e.Arguments, digest); r != nil {
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: r.Reason}
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/"+e.Invocation.AttemptID, strings.NewReader(string(e.Arguments)))
	if err == nil {
		var response *http.Response
		response, err = http.DefaultClient.Do(r)
		if response != nil {
			_ = response.Body.Close()
		}
	}
	if err != nil {
		return adapters.DispatchResult{Status: adapters.DispatchIndefinite}
	}
	return adapters.DispatchResult{Status: adapters.DispatchSent}
}

func (a *recoveryProcessAdapter) Observe(ctx context.Context, _ adapters.TokenSource, e adapters.Effect) adapters.ObserveResult {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/"+e.Invocation.AttemptID, nil)
	if err != nil {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown}
	}
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown}
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != e.Invocation.AttemptID {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown}
	}
	return succeeded(e)
}

func TestRecoveryDispatchChildProcess(t *testing.T) {
	dsn := os.Getenv("HELM_RECOVERY_CHILD_DSN")
	if dsn == "" {
		return
	}
	db, err := sql.Open("postgres", dsn)
	must(t, err)
	defer func() { _ = db.Close() }()
	adapter := &recoveryProcessAdapter{endpoint: os.Getenv("HELM_RECOVERY_CHILD_PROVIDER")}
	svc, err := New(db, Config{Adapters: []adapters.Adapter{adapter}, DispatchTimeout: time.Second, DispatchGrace: 10 * time.Millisecond})
	must(t, err)
	_, _, err = svc.Dispatch(context.Background(), episodeWorker("crash", "recovery-v1"), os.Getenv("HELM_RECOVERY_CHILD_ATTEMPT"))
	must(t, err)
}

func TestPostgresRecoveryProcessCrashReconcilesOriginalWithoutDuplicate(t *testing.T) {
	f, svc, _, in := recoveryFixture(t)
	ctx := context.Background()
	worker := episodeWorker("crash", "recovery-v1")
	a := f.propose(worker, workerNote("process-crash"))
	accepted := make(chan struct{}, 1)
	release := make(chan struct{})
	releaseProvider := sync.OnceFunc(func() { close(release) })
	var writes atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+a.ID {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost {
			writes.Add(1)
			accepted <- struct{}{}
			<-release
			return
		}
		_, _ = fmt.Fprint(w, a.ID)
	}))
	defer provider.Close()
	defer releaseProvider()
	var schema, role string
	must(t, f.runtime.QueryRow(`SELECT current_schema(),current_user`).Scan(&schema, &role))
	child := exec.Command(os.Args[0], "-test.run=^TestRecoveryDispatchChildProcess$", "-test.timeout=15s")
	child.Env = append(os.Environ(), "HELM_RECOVERY_CHILD_DSN="+withSearchPath(t, os.Getenv("HELM_TEST_POSTGRES_URL"), schema, role), "HELM_RECOVERY_CHILD_PROVIDER="+provider.URL, "HELM_RECOVERY_CHILD_ATTEMPT="+a.ID)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill() }()
	select {
	case <-accepted:
	case <-time.After(10 * time.Second):
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatal("child never reached provider after native claim")
	}
	fence, _, err := svc.FenceRecovery(ctx, operator, stopToken(), in)
	must(t, err)
	if fence.UnresolvedCount != 1 {
		t.Fatalf("accepted original not inventoried: %+v", fence)
	}
	must(t, child.Process.Kill())
	if err := child.Wait(); err == nil {
		t.Fatal("dispatch child did not terminate at injected crash")
	}
	releaseProvider()
	restarted, err := New(f.runtime, Config{Adapters: []adapters.Adapter{&recoveryProcessAdapter{endpoint: provider.URL}}})
	must(t, err)
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _, err := restarted.Observe(ctx, worker, a.ID)
		must(t, err)
		if got.State == "RECONCILED" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("original attempt stayed unresolved after provider readback: %+v", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, existing, err := restarted.Dispatch(ctx, worker, a.ID)
	must(t, err)
	if !existing || got.ID != a.ID || writes.Load() != 1 {
		t.Fatalf("crash replay duplicated effect: existing=%v writes=%d", existing, writes.Load())
	}
}
