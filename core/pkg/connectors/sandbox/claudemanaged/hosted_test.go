package claudemanaged

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	connsandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	"github.com/stretchr/testify/require"
)

const testToken = "tok-secret-123"

func fakeWorker(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

func okWorker(t *testing.T, seen *[]string) *httptest.Server {
	return fakeWorker(t, func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = append(*seen, r.Header.Get("Authorization"))
		}
		if r.URL.Path == "/v1/terminate" {
			var req remoteTerminateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(remoteTerminateResponse{Terminated: true, Tenant: req.Tenant})
			return
		}
		var req remoteExecRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = json.NewEncoder(w).Encode(remoteExecResponse{ExitCode: 3, Stdout: "out:" + strings.Join(req.Command, " "), DurationMS: 5,
			Tenant: req.Tenant, SpecApplied: req.Spec != nil})
	})
}

func TestRemoteRunnerHappyPathAndTokenOnlyInHeader(t *testing.T) {
	var auth []string
	s := okWorker(t, &auth)
	r, err := NewRemoteRunner(s.URL, s.Client())
	require.NoError(t, err)
	res, err := r.Run(ContextWithToken(context.Background(), testToken), ExecutionContext{SandboxID: "sb1"},
		&actuators.ExecRequest{Command: []string{"echo", "hi"}})
	require.NoError(t, err)
	require.Equal(t, 3, res.ExitCode)
	require.Equal(t, "out:echo hi", string(res.Stdout))
	require.Equal(t, []string{"Bearer " + testToken}, auth)
}

func TestRemoteRunnerRefusesWithoutTokenBeforeIO(t *testing.T) {
	var hits atomic.Int32
	s := fakeWorker(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
	r, err := NewRemoteRunner(s.URL, s.Client())
	require.NoError(t, err)
	_, err = r.Run(context.Background(), ExecutionContext{}, &actuators.ExecRequest{Command: []string{"x"}})
	require.Error(t, err)
	require.Zero(t, hits.Load())
}

func TestRemoteRunnerRefusesEnvAndBadEndpoints(t *testing.T) {
	s := okWorker(t, nil)
	r, err := NewRemoteRunner(s.URL, s.Client())
	require.NoError(t, err)
	_, err = r.Run(ContextWithToken(context.Background(), testToken), ExecutionContext{},
		&actuators.ExecRequest{Command: []string{"x"}, Env: map[string]string{"A": "b"}})
	require.Error(t, err)
	for _, e := range []string{"http://worker.example.com", "https://u:p@w.example.com", "https://w.example.com/?q=1", "https://w.example.com/#f", "ftp://x", ""} {
		_, err := NewRemoteRunner(e, nil)
		require.Error(t, err, e)
	}
}

func TestRemoteRunnerClassifiesAndBoundsAnswers(t *testing.T) {
	run := func(h http.HandlerFunc) error {
		s := fakeWorker(t, h)
		r, err := NewRemoteRunner(s.URL, s.Client())
		require.NoError(t, err)
		_, err = r.Run(ContextWithToken(context.Background(), testToken), ExecutionContext{}, &actuators.ExecRequest{Command: []string{"x"}})
		return err
	}
	err := run(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope "+testToken, 403) })
	ce := connsandbox.AsCallError(err)
	require.NotNil(t, ce)
	require.True(t, ce.Refused)
	require.NotContains(t, err.Error(), testToken)
	err = run(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", 502) })
	ce = connsandbox.AsCallError(err)
	require.NotNil(t, ce)
	require.False(t, ce.Refused)
	err = run(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", int(remoteLimit)+10)))
	})
	ce = connsandbox.AsCallError(err)
	require.NotNil(t, ce)
	require.True(t, ce.TooLarge || ce.Drift)
	require.False(t, ce.Refused)
	err = run(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) })
	ce = connsandbox.AsCallError(err)
	require.NotNil(t, ce)
	require.True(t, ce.Drift)
}

func TestRemoteRunnerDoesNotFollowRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	other := fakeWorker(t, func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) })
	s := fakeWorker(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	})
	r, err := NewRemoteRunner(s.URL, s.Client())
	require.NoError(t, err)
	_, err = r.Run(ContextWithToken(context.Background(), testToken), ExecutionContext{}, &actuators.ExecRequest{Command: []string{"x"}})
	require.Error(t, err)
	require.Zero(t, elsewhere.Load())
}

func TestHostedRefusesLocalAndNilRunners(t *testing.T) {
	cfg := testConfig(t)
	for _, r := range []CommandRunner{nil, LocalCommandRunner{}, &LocalCommandRunner{}} {
		_, err := NewHosted(cfg, r, testReceiptSigner{}, nil)
		require.Error(t, err)
	}
}

func TestHostedLifecycleThroughInventoryAndShim(t *testing.T) {
	s := okWorker(t, nil)
	runner, err := NewRemoteRunner(s.URL, s.Client())
	require.NoError(t, err)
	cfg := testConfig(t)
	h, err := NewHosted(cfg, runner, testReceiptSigner{}, nil)
	require.NoError(t, err)
	ctx := ContextWithToken(context.Background(), testToken)
	labels := map[string]string{connsandbox.LabelTenant: "t1", connsandbox.LabelAttempt: "a1"}
	handle, err := h.Create(ctx, &actuators.SandboxSpec{Runtime: "default", Labels: labels, Egress: actuators.EgressPolicy{Disabled: true}})
	require.NoError(t, err)

	found, err := h.Find(ctx, labels)
	require.NoError(t, err)
	require.Len(t, found, 1)
	require.Equal(t, handle.ID, found[0].ID)
	other, err := h.Find(ctx, map[string]string{connsandbox.LabelTenant: "t2"})
	require.NoError(t, err)
	require.Empty(t, other)
	info, err := h.Lookup(ctx, handle.ID)
	require.NoError(t, err)
	require.Equal(t, actuators.StatusRunning, info.Status)
	require.Equal(t, labels, info.Labels)

	res, err := h.Exec(ctx, handle.ID, &actuators.ExecRequest{Command: []string{"echo", "x"}, WorkDir: "/workspace"})
	require.NoError(t, err)
	require.Equal(t, 3, res.ExitCode)
	require.Equal(t, "out:echo x", string(res.Stdout))
	require.NotEmpty(t, res.Receipt.StdoutHash)
	require.NotEmpty(t, res.Receipt.StderrHash)
	require.NotEmpty(t, res.Receipt.RequestHash)

	require.NoError(t, h.Terminate(ctx, handle.ID))
	info, err = h.Lookup(ctx, handle.ID)
	require.NoError(t, err)
	require.Equal(t, actuators.StatusTerminated, info.Status)
	_, err = h.Lookup(ctx, "missing")
	require.ErrorIs(t, err, actuators.ErrSandboxNotFound)
}

func TestHostedRefusesBadIDsAndPreviewSigner(t *testing.T) {
	s := okWorker(t, nil)
	runner, _ := NewRemoteRunner(s.URL, s.Client())
	h, err := NewHosted(testConfig(t), runner, testReceiptSigner{}, nil)
	require.NoError(t, err)
	ctx := ContextWithToken(context.Background(), testToken)
	_, err = h.Lookup(ctx, "../etc")
	require.ErrorIs(t, err, connsandbox.ErrBadID)
	_, err = h.Exec(ctx, "../etc", &actuators.ExecRequest{Command: []string{"x"}})
	require.ErrorIs(t, err, connsandbox.ErrBadID)

	weak, err := NewHosted(testConfig(t), runner, nil, nil)
	require.NoError(t, err)
	_, err = weak.Create(ctx, &actuators.SandboxSpec{Runtime: "default", Egress: actuators.EgressPolicy{Disabled: true}})
	require.ErrorIs(t, err, actuators.ErrPreflightFailed)
}

// A counter id repeated across processes: two replicas handed two tenants the
// same sandbox id, and the worker keys its workspace by the id.
func TestSandboxIDsAreRandomAndDoNotRepeatAcrossAdapters(t *testing.T) {
	s := okWorker(t, nil)
	runner, _ := NewRemoteRunner(s.URL, s.Client())
	ctx := ContextWithToken(context.Background(), testToken)
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		h, err := NewHosted(testConfig(t), runner, testReceiptSigner{}, nil)
		require.NoError(t, err)
		handle, err := h.Create(ctx, &actuators.SandboxSpec{Runtime: "default", Egress: actuators.EgressPolicy{Disabled: true}})
		require.NoError(t, err)
		require.True(t, connsandbox.ValidID(handle.ID))
		require.False(t, seen[handle.ID], "the second adapter handed out %s again", handle.ID)
		seen[handle.ID] = true
	}
}

// The worker is told the tenant and the spec on every exec and terminate, and
// an answer that does not echo them is drift.
func TestRemoteRunnerCarriesTheTenantAndSpecAndVerifiesTheEcho(t *testing.T) {
	var got []remoteExecRequest
	var terminates []remoteTerminateRequest
	echo := true
	s := fakeWorker(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/terminate" {
			var req remoteTerminateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			terminates = append(terminates, req)
			resp := remoteTerminateResponse{Terminated: echo, Tenant: req.Tenant}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		var req remoteExecRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		got = append(got, req)
		resp := remoteExecResponse{Stdout: "ok"}
		if echo {
			resp.Tenant, resp.SpecApplied = req.Tenant, true
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	runner, err := NewRemoteRunner(s.URL, s.Client())
	require.NoError(t, err)
	ctx := ContextWithToken(context.Background(), testToken)
	spec := &actuators.SandboxSpec{Egress: actuators.EgressPolicy{Disabled: true},
		Resources: actuators.ResourceSpec{CPUMillis: 500, MemoryMB: 256, DiskMB: 10, MaxProcesses: 64}}
	ec := ExecutionContext{SandboxID: "sb1", Tenant: "tenant-digest", Spec: spec}

	_, err = runner.Run(ctx, ec, &actuators.ExecRequest{Command: []string{"x"}})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "tenant-digest", got[0].Tenant)
	require.Equal(t, &remoteSpec{EgressDisabled: true, CPUMillis: 500, MemoryMB: 256, DiskMB: 10, MaxProcesses: 64}, got[0].Spec)
	require.NoError(t, runner.Terminate(ctx, ec))
	require.Equal(t, []remoteTerminateRequest{{SandboxID: "sb1", Tenant: "tenant-digest"}}, terminates)

	echo = false
	_, err = runner.Run(ctx, ec, &actuators.ExecRequest{Command: []string{"x"}})
	ce := connsandbox.AsCallError(err)
	require.NotNil(t, ce)
	require.True(t, ce.Drift, "a worker that does not echo the tenant has not checked it")
	ce = connsandbox.AsCallError(runner.Terminate(ctx, ec))
	require.NotNil(t, ce)
	require.True(t, ce.Drift)
}

// A worker that applies the tenant binding refuses a request for the sandbox
// from another tenant, and the refusal is definite.
func TestRemoteRunnerWorkerRefusalOfAnotherTenantIsDefinite(t *testing.T) {
	s := fakeWorker(t, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "wrong tenant", http.StatusForbidden) })
	runner, err := NewRemoteRunner(s.URL, s.Client())
	require.NoError(t, err)
	_, err = runner.Run(ContextWithToken(context.Background(), testToken), ExecutionContext{SandboxID: "sb1", Tenant: "other"},
		&actuators.ExecRequest{Command: []string{"x"}})
	ce := connsandbox.AsCallError(err)
	require.NotNil(t, ce)
	require.True(t, ce.Refused)
}

// Terminate asks the worker first; a worker that fails leaves the record
// running, so the read-back does not report a sandbox terminated that the
// worker still holds.
func TestHostedTerminateReachesTheWorkerBeforeTheRecordChanges(t *testing.T) {
	var terminates atomic.Int32
	fail := true
	s := fakeWorker(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/terminate" {
			http.Error(w, "unexpected", 500)
			return
		}
		terminates.Add(1)
		var req remoteTerminateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if fail {
			http.Error(w, "boom", 502)
			return
		}
		_ = json.NewEncoder(w).Encode(remoteTerminateResponse{Terminated: true, Tenant: req.Tenant})
	})
	runner, _ := NewRemoteRunner(s.URL, s.Client())
	h, err := NewHosted(testConfig(t), runner, testReceiptSigner{}, nil)
	require.NoError(t, err)
	ctx := ContextWithToken(context.Background(), testToken)
	handle, err := h.Create(ctx, &actuators.SandboxSpec{Runtime: "default", Labels: map[string]string{connsandbox.LabelTenant: "t1"},
		Egress: actuators.EgressPolicy{Disabled: true}})
	require.NoError(t, err)

	require.Error(t, h.Terminate(ctx, handle.ID))
	info, err := h.Lookup(ctx, handle.ID)
	require.NoError(t, err)
	require.Equal(t, actuators.StatusRunning, info.Status)

	fail = false
	require.NoError(t, h.Terminate(ctx, handle.ID))
	require.EqualValues(t, 2, terminates.Load())
	info, _ = h.Lookup(ctx, handle.ID)
	require.Equal(t, actuators.StatusTerminated, info.Status)
}

func TestSandboxLogsAreBounded(t *testing.T) {
	a := New(testConfig(t), WithRunner(&fakeRunner{}), WithReceiptSigner(testReceiptSigner{}))
	handle, err := a.Create(context.Background(), &actuators.SandboxSpec{Runtime: "default", Egress: actuators.EgressPolicy{Disabled: true}})
	require.NoError(t, err)
	big := []byte(strings.Repeat("x", 4*maxLogBytes))
	for i := 0; i < maxLogEntries+50; i++ {
		a.appendLogs(handle.ID, time.Unix(1, 0), big, nil)
	}
	logs, err := a.Logs(context.Background(), handle.ID, nil)
	require.NoError(t, err)
	require.Len(t, logs, maxLogEntries)
	for _, l := range logs {
		require.LessOrEqual(t, len(l.Line), maxLogBytes)
	}
}
