package sandbox_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effectgraph"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/lease"
	sandbox_runtime "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtime/sandbox"
	pkg_sandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

var (
	ctx       = context.Background()
	baseTime  = time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC)
	clockTime = baseTime
)

func clock() time.Time { return clockTime }

func resetClock() { clockTime = baseTime }

// mockRunner implements SandboxRunner for testing.
type mockRunner struct {
	runCalled      bool
	validateCalled bool
	failValidate   bool
	failRun        bool
}

func (m *mockRunner) Run(spec *pkg_sandbox.SandboxSpec) (*pkg_sandbox.Result, *pkg_sandbox.ExecutionReceipt, error) {
	m.runCalled = true
	if m.failRun {
		return nil, nil, errMock("run failed")
	}
	return &pkg_sandbox.Result{
			ExitCode: 0,
			Stdout:   []byte("ok"),
		}, &pkg_sandbox.ExecutionReceipt{
			ExecutionID: "exec-1",
		}, nil
}

func (m *mockRunner) Validate(spec *pkg_sandbox.SandboxSpec) error {
	m.validateCalled = true
	if m.failValidate {
		return errMock("validation failed")
	}
	return nil
}

type errMock string

func (e errMock) Error() string { return string(e) }

type failingCompleteLeaseManager struct {
	*lease.InMemoryLeaseManager
}

func (m failingCompleteLeaseManager) Complete(context.Context, string) error {
	return fmt.Errorf("complete failed")
}

func setupBroker() (*sandbox_runtime.SandboxBroker, *lease.InMemoryLeaseManager, *mockRunner) {
	resetClock()
	credBroker := sandbox_runtime.NewCredentialBroker(3600).WithClock(clock)
	leaseManager := lease.NewInMemoryLeaseManager().WithClock(clock)
	broker := sandbox_runtime.NewSandboxBroker(credBroker, leaseManager).WithClock(clock)
	runner := &mockRunner{}
	broker.RegisterRunner("docker", runner)
	return broker, leaseManager, runner
}

func acquireLease(t *testing.T, lm *lease.InMemoryLeaseManager) *lease.ExecutionLease {
	t.Helper()
	l, err := lm.Acquire(ctx, lease.LeaseRequest{
		RunID:           "run-1",
		WorkspacePath:   "/workspace",
		Backend:         "docker",
		ProfileName:     "net-limited",
		TTL:             1 * time.Hour,
		EffectGraphHash: "sha256:abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func testVerdict() *effectgraph.NodeVerdict {
	return &effectgraph.NodeVerdict{
		StepID: "step-1",
		Decision: &contracts.DecisionRecord{
			Verdict: string(contracts.VerdictAllow),
		},
		Intent: &contracts.AuthorizedExecutionIntent{ID: "intent-step-1"},
		Profile: &effectgraph.ExecutionProfile{
			Backend:     "docker",
			ProfileName: "net-limited",
		},
	}
}

func TestPrepareExecutionRejectsPrivilegedDeniedBeforeLeaseCredentialsOrRunner(t *testing.T) {
	resetClock()
	credBroker := sandbox_runtime.NewCredentialBroker(3600).WithClock(clock)
	leaseManager := lease.NewInMemoryLeaseManager().WithClock(clock)
	broker := sandbox_runtime.NewSandboxBroker(credBroker, leaseManager).WithClock(clock)
	runner := &mockRunner{}
	broker.RegisterRunner("docker", runner)
	l := acquireLease(t, leaseManager)
	verdict := testVerdict()
	verdict.Profile.ProfileName = "privileged-denied"

	if _, err := broker.PrepareExecution(ctx, l, verdict); err == nil {
		t.Fatal("privileged-denied profile reached sandbox preparation")
	}
	got, err := leaseManager.Get(ctx, l.LeaseID)
	if err != nil || got.Status != lease.LeaseStatusPending {
		t.Fatalf("rejected profile changed lease state: lease=%+v err=%v", got, err)
	}
	if len(credBroker.GetIssuances()) != 0 {
		t.Fatal("rejected profile received scoped credentials")
	}
	if runner.validateCalled || runner.runCalled {
		t.Fatal("rejected profile reached sandbox runner")
	}
}

func TestExecuteRejectsCallerConstructedPreparedExecution(t *testing.T) {
	broker, leaseManager, runner := setupBroker()
	execLease := acquireLease(t, leaseManager)
	prepared := &sandbox_runtime.PreparedExecution{
		Lease:      execLease,
		Spec:       &pkg_sandbox.SandboxSpec{WorkDir: execLease.WorkspacePath},
		Verdict:    testVerdict(),
		PreparedAt: clock(),
	}

	if _, _, err := broker.Execute(ctx, prepared); err == nil {
		t.Fatal("caller-constructed prepared execution reached dispatch")
	}
	if runner.validateCalled || runner.runCalled {
		t.Fatal("caller-constructed prepared execution reached sandbox runner")
	}
	got, err := leaseManager.Get(ctx, execLease.LeaseID)
	if err != nil || got.Status != lease.LeaseStatusPending {
		t.Fatalf("unrecognized execution changed lease state: lease=%+v err=%v", got, err)
	}
}

func TestExecuteRejectsMutatedPreparedExecutionAndConsumesAuthorization(t *testing.T) {
	broker, leaseManager, runner := setupBroker()
	execLease := acquireLease(t, leaseManager)
	prepared, err := broker.PrepareExecution(ctx, execLease, testVerdict())
	if err != nil {
		t.Fatal(err)
	}
	prepared.Verdict.Decision.Verdict = string(contracts.VerdictDeny)

	if _, _, err := broker.Execute(ctx, prepared); err == nil {
		t.Fatal("mutated prepared execution reached dispatch")
	}
	if runner.validateCalled || runner.runCalled {
		t.Fatal("mutated prepared execution reached sandbox runner")
	}
	got, err := leaseManager.Get(ctx, execLease.LeaseID)
	if err != nil || got.Status != lease.LeaseStatusCompleted {
		t.Fatalf("rejected prepared execution was not cleaned up: lease=%+v err=%v", got, err)
	}
	prepared.Verdict.Decision.Verdict = string(contracts.VerdictAllow)
	if _, _, err := broker.Execute(ctx, prepared); err == nil {
		t.Fatal("rejected prepared execution authorization was reusable")
	}
}

func TestExecuteRejectsCopiedPreparedExecution(t *testing.T) {
	broker, leaseManager, runner := setupBroker()
	execLease := acquireLease(t, leaseManager)
	prepared, err := broker.PrepareExecution(ctx, execLease, testVerdict())
	if err != nil {
		t.Fatal(err)
	}
	copied := *prepared

	if _, _, err := broker.Execute(ctx, &copied); err == nil {
		t.Fatal("copied prepared execution reached dispatch")
	}
	if runner.validateCalled || runner.runCalled {
		t.Fatal("copied prepared execution reached sandbox runner")
	}
	if _, _, err := broker.Execute(ctx, prepared); err != nil {
		t.Fatalf("copy attempt consumed the original broker authorization: %v", err)
	}
}

func TestPrepareExecution(t *testing.T) {
	broker, lm, _ := setupBroker()
	l := acquireLease(t, lm)

	prepared, err := broker.PrepareExecution(ctx, l, testVerdict())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Spec == nil {
		t.Fatal("expected sandbox spec")
	}
	if prepared.Spec.WorkDir != "/workspace" {
		t.Fatalf("expected /workspace, got %s", prepared.Spec.WorkDir)
	}

	// Lease should now be ACTIVE.
	got, _ := lm.Get(ctx, l.LeaseID)
	if got.Status != lease.LeaseStatusActive {
		t.Fatalf("expected ACTIVE, got %s", got.Status)
	}
}

func TestPrepareExecution_NoRunner(t *testing.T) {
	broker, lm, _ := setupBroker()
	l, _ := lm.Acquire(ctx, lease.LeaseRequest{
		RunID:   "run-1",
		Backend: "wasi", // no runner registered for wasi
		TTL:     1 * time.Hour,
	})

	_, err := broker.PrepareExecution(ctx, l, testVerdict())
	if err == nil {
		t.Fatal("expected error for missing runner")
	}
}

func TestExecute(t *testing.T) {
	broker, lm, runner := setupBroker()
	l := acquireLease(t, lm)
	prepared, _ := broker.PrepareExecution(ctx, l, testVerdict())

	result, receipt, err := broker.Execute(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !runner.runCalled {
		t.Fatal("expected runner.Run to be called")
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", result.ExitCode)
	}
	if receipt == nil {
		t.Fatal("expected receipt")
	}

	// Lease should be completed.
	got, _ := lm.Get(ctx, l.LeaseID)
	if got.Status != lease.LeaseStatusCompleted {
		t.Fatalf("expected COMPLETED after execute, got %s", got.Status)
	}
}

func TestExecute_RunFailure(t *testing.T) {
	broker, lm, runner := setupBroker()
	runner.failRun = true
	l := acquireLease(t, lm)
	prepared, _ := broker.PrepareExecution(ctx, l, testVerdict())

	_, _, err := broker.Execute(ctx, prepared)
	if err == nil {
		t.Fatal("expected error from failed run")
	}

	// Lease should still be completed (cleanup runs regardless).
	got, _ := lm.Get(ctx, l.LeaseID)
	if got.Status != lease.LeaseStatusCompleted {
		t.Fatalf("expected COMPLETED after failure cleanup, got %s", got.Status)
	}
}

func TestExecute_ValidateFailure(t *testing.T) {
	broker, lm, runner := setupBroker()
	runner.failValidate = true
	l := acquireLease(t, lm)
	prepared, _ := broker.PrepareExecution(ctx, l, testVerdict())

	_, _, err := broker.Execute(ctx, prepared)
	if err == nil {
		t.Fatal("expected error from failed validation")
	}
}

func TestPrepareExecution_NilLease(t *testing.T) {
	broker, _, _ := setupBroker()
	_, err := broker.PrepareExecution(ctx, nil, testVerdict())
	if err == nil {
		t.Fatal("expected error for nil lease")
	}
}

func TestPrepareExecution_NilVerdict(t *testing.T) {
	broker, lm, _ := setupBroker()
	l := acquireLease(t, lm)
	_, err := broker.PrepareExecution(ctx, l, nil)
	if err == nil {
		t.Fatal("expected error for nil verdict")
	}
}

func TestExecute_TokenListMutationIsRejectedAndPreparedCredentialsAreRevoked(t *testing.T) {
	resetClock()
	credBroker := sandbox_runtime.NewCredentialBroker(3600).WithClock(clock)
	lm := lease.NewInMemoryLeaseManager().WithClock(clock)
	broker := sandbox_runtime.NewSandboxBroker(credBroker, lm).WithClock(clock)
	broker.RegisterRunner("docker", &mockRunner{})
	sandboxID := fmt.Sprintf("sbx-docker-%d", clock().UnixNano())
	credBroker.SetScopeAllowlist(sandboxID, []string{"repo:read"})
	l, err := lm.Acquire(ctx, lease.LeaseRequest{
		RunID:         "run-1",
		WorkspacePath: "/workspace",
		Backend:       "docker",
		ProfileName:   "net-limited",
		TTL:           time.Hour,
		SecretBindings: []lease.SecretBinding{{
			SecretRef: "repo-token",
			Scopes:    []string{"repo:read"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := broker.PrepareExecution(ctx, l, testVerdict())
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.TokenIDs) != 1 {
		t.Fatalf("issued token IDs = %d, want 1", len(prepared.TokenIDs))
	}
	prepared.TokenIDs = append(prepared.TokenIDs, "caller-injected-token")

	result, receipt, err := broker.Execute(ctx, prepared)
	if err == nil {
		t.Fatal("mutated credential list reached sandbox execution")
	}
	if result != nil || receipt != nil {
		t.Fatalf("rejected execution returned result=%+v receipt=%+v", result, receipt)
	}
	if valid, reason := credBroker.ValidateToken(prepared.Tokens[0]); valid || reason != "token revoked" {
		t.Fatalf("prepared credential was not revoked after mutation: valid=%v reason=%q", valid, reason)
	}
	got, getErr := lm.Get(ctx, l.LeaseID)
	if getErr != nil || got.Status != lease.LeaseStatusCompleted {
		t.Fatalf("rejected execution lease was not completed: lease=%+v err=%v", got, getErr)
	}
}

func TestExecute_LeaseCompletionFailureIsRecorded(t *testing.T) {
	resetClock()
	credBroker := sandbox_runtime.NewCredentialBroker(3600).WithClock(clock)
	baseManager := lease.NewInMemoryLeaseManager().WithClock(clock)
	broker := sandbox_runtime.NewSandboxBroker(credBroker, failingCompleteLeaseManager{InMemoryLeaseManager: baseManager}).WithClock(clock)
	runner := &mockRunner{}
	broker.RegisterRunner("docker", runner)

	l := acquireLease(t, baseManager)
	prepared, err := broker.PrepareExecution(ctx, l, testVerdict())
	if err != nil {
		t.Fatal(err)
	}

	result, receipt, err := broker.Execute(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !runner.runCalled {
		t.Fatal("expected runner.Run to be called")
	}
	if result.Cleanup.Status != "unknown" {
		t.Fatalf("cleanup status = %#v, want unknown", result.Cleanup)
	}
	if result.Success() {
		t.Fatal("unknown cleanup state must make the result non-success")
	}
	if receipt == nil || receipt.Result.Cleanup.Status != "unknown" {
		t.Fatalf("receipt cleanup = %#v, want unknown", receipt)
	}
}
