package sandbox_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	runCalled       bool
	validateCalled  bool
	failValidate    bool
	failRun         bool
	lastSpec        *pkg_sandbox.SandboxSpec
	lastCredentials []sandbox_runtime.SandboxCredentialMaterial
	credentialCheck func([]sandbox_runtime.SandboxCredentialMaterial) error
}

func (m *mockRunner) Run(spec *pkg_sandbox.SandboxSpec) (*pkg_sandbox.Result, *pkg_sandbox.ExecutionReceipt, error) {
	m.runCalled = true
	m.lastSpec = spec
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

func (m *mockRunner) RunWithCredentials(spec *pkg_sandbox.SandboxSpec, credentials []sandbox_runtime.SandboxCredentialMaterial) (*pkg_sandbox.Result, *pkg_sandbox.ExecutionReceipt, error) {
	m.lastCredentials = append([]sandbox_runtime.SandboxCredentialMaterial(nil), credentials...)
	if m.credentialCheck != nil {
		if err := m.credentialCheck(credentials); err != nil {
			return nil, nil, err
		}
	}
	return m.Run(spec)
}

type specOnlyRunner struct {
	inner *mockRunner
}

func (r specOnlyRunner) Run(spec *pkg_sandbox.SandboxSpec) (*pkg_sandbox.Result, *pkg_sandbox.ExecutionReceipt, error) {
	return r.inner.Run(spec)
}

func (r specOnlyRunner) Validate(spec *pkg_sandbox.SandboxSpec) error {
	return r.inner.Validate(spec)
}

type errMock string

func (e errMock) Error() string { return string(e) }

type mockAuthorizationVerifier struct {
	valid bool
	err   error
}

func (m mockAuthorizationVerifier) VerifyDecision(*contracts.DecisionRecord) (bool, error) {
	return m.valid, m.err
}

func (m mockAuthorizationVerifier) VerifyIntent(*contracts.AuthorizedExecutionIntent) (bool, error) {
	return m.valid, m.err
}

type mutableAuthorizationVerifier struct {
	valid bool
}

func (m *mutableAuthorizationVerifier) VerifyDecision(*contracts.DecisionRecord) (bool, error) {
	return m.valid, nil
}

func (m *mutableAuthorizationVerifier) VerifyIntent(*contracts.AuthorizedExecutionIntent) (bool, error) {
	return m.valid, nil
}

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
	broker := sandbox_runtime.NewSandboxBroker(credBroker, leaseManager).
		WithAuthorizationVerifier(mockAuthorizationVerifier{valid: true}).
		WithClock(clock)
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
		TemplateRef:     "example.invalid/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
			ID:           "decision-step-1",
			Action:       contracts.EffectTypeRunSandboxedCode,
			EffectDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Verdict:      string(contracts.VerdictAllow),
			InputContext: map[string]any{},
		},
		Intent: &contracts.AuthorizedExecutionIntent{
			ID:               "intent-step-1",
			DecisionID:       "decision-step-1",
			EffectDigestHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			IssuedAt:         baseTime.Add(-time.Minute),
			ExpiresAt:        baseTime.Add(time.Hour),
			AllowedTool:      contracts.EffectTypeRunSandboxedCode,
		},
		Profile: &effectgraph.ExecutionProfile{
			Backend:     "docker",
			ProfileName: "net-limited",
		},
	}
}

func authorizedVerdict(t *testing.T, execLease *lease.ExecutionLease, workload *sandbox_runtime.SandboxWorkload) *effectgraph.NodeVerdict {
	t.Helper()
	verdict := testVerdict()
	authorization := sandboxAuthorization(t, execLease, verdict.Profile, workload)
	verdict.Decision.InputContext[sandbox_runtime.SandboxExecutionDecisionContextKey] = authorization
	return verdict
}

func sandboxAuthorization(t *testing.T, execLease *lease.ExecutionLease, profile *effectgraph.ExecutionProfile, workload *sandbox_runtime.SandboxWorkload) sandbox_runtime.SandboxExecutionAuthorization {
	t.Helper()
	authorization, err := sandbox_runtime.BuildSandboxExecutionAuthorization(execLease, profile, workload)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func testWorkload() *sandbox_runtime.SandboxWorkload {
	return &sandbox_runtime.SandboxWorkload{
		Command: []string{"/usr/bin/example"},
		Args:    []string{"serve", ""},
		Env:     map[string]string{"MODE": "test"},
		Labels:  map[string]string{"helm.test": "sandbox-broker"},
	}
}

func TestPrepareExecutionRejectsPrivilegedDeniedBeforeLeaseCredentialsOrRunner(t *testing.T) {
	resetClock()
	credBroker := sandbox_runtime.NewCredentialBroker(3600).WithClock(clock)
	leaseManager := lease.NewInMemoryLeaseManager().WithClock(clock)
	broker := sandbox_runtime.NewSandboxBroker(credBroker, leaseManager).
		WithAuthorizationVerifier(mockAuthorizationVerifier{valid: true}).
		WithClock(clock)
	runner := &mockRunner{}
	broker.RegisterRunner("docker", runner)
	l := acquireLease(t, leaseManager)
	verdict := testVerdict()
	verdict.Profile.ProfileName = "privileged-denied"

	if _, err := broker.PrepareExecutionWithWorkload(ctx, l, verdict, testWorkload()); err == nil {
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
	prepared, err := broker.PrepareExecutionWithWorkload(ctx, execLease, authorizedVerdict(t, execLease, testWorkload()), testWorkload())
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
	prepared, err := broker.PrepareExecutionWithWorkload(ctx, execLease, authorizedVerdict(t, execLease, testWorkload()), testWorkload())
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

func TestExecuteRejectsWorkloadMutationAfterPreparation(t *testing.T) {
	broker, leaseManager, runner := setupBroker()
	execLease := acquireLease(t, leaseManager)
	prepared, err := broker.PrepareExecutionWithWorkload(ctx, execLease, authorizedVerdict(t, execLease, testWorkload()), testWorkload())
	if err != nil {
		t.Fatal(err)
	}
	prepared.Spec.Command[0] = "/usr/bin/substituted"

	if _, _, err := broker.Execute(ctx, prepared); err == nil {
		t.Fatal("post-authorization workload mutation reached dispatch")
	}
	if runner.validateCalled || runner.runCalled {
		t.Fatal("post-authorization workload mutation reached sandbox runner")
	}
	got, getErr := leaseManager.Get(ctx, execLease.LeaseID)
	if getErr != nil || got.Status != lease.LeaseStatusCompleted {
		t.Fatalf("mutated workload lease was not cleaned up: lease=%+v err=%v", got, getErr)
	}
}

func TestExecuteRejectsExpiredPreparedAuthorization(t *testing.T) {
	broker, leaseManager, runner := setupBroker()
	execLease := acquireLease(t, leaseManager)
	prepared, err := broker.PrepareExecutionWithWorkload(ctx, execLease, authorizedVerdict(t, execLease, testWorkload()), testWorkload())
	if err != nil {
		t.Fatal(err)
	}
	clockTime = baseTime.Add(2 * time.Hour)

	if _, _, err := broker.Execute(ctx, prepared); err == nil {
		t.Fatal("expired prepared authorization reached dispatch")
	}
	if runner.validateCalled || runner.runCalled {
		t.Fatal("expired prepared authorization reached sandbox runner")
	}
	got, getErr := leaseManager.Get(ctx, execLease.LeaseID)
	if getErr != nil || got.Status != lease.LeaseStatusCompleted {
		t.Fatalf("expired prepared authorization was not cleaned up: lease=%+v err=%v", got, getErr)
	}
}

func TestExecuteRechecksTrustRootBeforeRunner(t *testing.T) {
	resetClock()
	credBroker := sandbox_runtime.NewCredentialBroker(3600).WithClock(clock)
	leaseManager := lease.NewInMemoryLeaseManager().WithClock(clock)
	verifier := &mutableAuthorizationVerifier{valid: true}
	broker := sandbox_runtime.NewSandboxBroker(credBroker, leaseManager).
		WithAuthorizationVerifier(verifier).
		WithClock(clock)
	runner := &mockRunner{}
	broker.RegisterRunner("docker", runner)
	execLease := acquireLease(t, leaseManager)
	prepared, err := broker.PrepareExecutionWithWorkload(ctx, execLease, authorizedVerdict(t, execLease, testWorkload()), testWorkload())
	if err != nil {
		t.Fatal(err)
	}

	verifier.valid = false
	if _, _, err := broker.Execute(ctx, prepared); err == nil {
		t.Fatal("revoked sandbox authority reached dispatch")
	}
	if runner.validateCalled || runner.runCalled {
		t.Fatal("revoked sandbox authority reached runner")
	}
}

func TestExecuteRejectsSourceLeaseExpansionAfterAuthorization(t *testing.T) {
	broker, leaseManager, runner := setupBroker()
	execLease := acquireLease(t, leaseManager)
	prepared, err := broker.PrepareExecutionWithWorkload(ctx, execLease, authorizedVerdict(t, execLease, testWorkload()), testWorkload())
	if err != nil {
		t.Fatal(err)
	}
	if err := leaseManager.Extend(ctx, execLease.LeaseID, time.Hour); err != nil {
		t.Fatal(err)
	}

	if _, _, err := broker.Execute(ctx, prepared); err == nil {
		t.Fatal("expanded source lease reached dispatch under the prior decision")
	}
	if runner.validateCalled || runner.runCalled {
		t.Fatal("expanded source lease reached runner")
	}
}

func TestPrepareExecutionRequiresExplicitWorkload(t *testing.T) {
	broker, leaseManager, runner := setupBroker()
	execLease := acquireLease(t, leaseManager)

	if _, err := broker.PrepareExecution(ctx, execLease, testVerdict()); err == nil {
		t.Fatal("implicit empty workload reached preparation")
	}
	if runner.validateCalled || runner.runCalled {
		t.Fatal("implicit empty workload reached sandbox runner")
	}
	got, err := leaseManager.Get(ctx, execLease.LeaseID)
	if err != nil || got.Status != lease.LeaseStatusPending {
		t.Fatalf("implicit workload rejection changed lease state: lease=%+v err=%v", got, err)
	}
}

func TestPrepareExecutionWithWorkload(t *testing.T) {
	broker, lm, _ := setupBroker()
	l := acquireLease(t, lm)

	prepared, err := broker.PrepareExecutionWithWorkload(ctx, l, authorizedVerdict(t, l, testWorkload()), testWorkload())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Spec == nil {
		t.Fatal("expected sandbox spec")
	}
	if prepared.Spec.WorkDir != "/workspace" {
		t.Fatalf("expected /workspace, got %s", prepared.Spec.WorkDir)
	}
	if prepared.Spec.Image != l.TemplateRef || prepared.Spec.Network.Disabled || !prepared.Spec.Network.DNSAllowed {
		t.Fatalf("prepared image/network are not the approved runtime: %#v", prepared.Spec)
	}
	if prepared.Spec.Limits.CPUMillis != 2000 || prepared.Spec.Limits.MemoryMB != 1024 || prepared.Spec.Limits.Timeout != 30*time.Minute {
		t.Fatalf("prepared resource limits are not the approved runtime: %#v", prepared.Spec.Limits)
	}
	if len(prepared.Spec.Command) != 1 || prepared.Spec.Command[0] != "/usr/bin/example" || len(prepared.Spec.Args) != 2 || prepared.Spec.Args[1] != "" {
		t.Fatalf("prepared workload command/args = %#v/%#v", prepared.Spec.Command, prepared.Spec.Args)
	}
	if prepared.Spec.Env["MODE"] != "test" || prepared.Spec.Labels["helm.test"] != "sandbox-broker" {
		t.Fatalf("prepared workload env/labels = %#v/%#v", prepared.Spec.Env, prepared.Spec.Labels)
	}

	// Lease should now be ACTIVE.
	got, _ := lm.Get(ctx, l.LeaseID)
	if got.Status != lease.LeaseStatusActive {
		t.Fatalf("expected ACTIVE, got %s", got.Status)
	}
}

func TestPrepareExecutionWithWorkloadRejectsIncompleteWorkloadBeforeLeaseActivation(t *testing.T) {
	broker, leaseManager, runner := setupBroker()
	for name, workload := range map[string]*sandbox_runtime.SandboxWorkload{
		"nil":           nil,
		"empty command": {},
		"empty program": {Command: []string{""}},
	} {
		t.Run(name, func(t *testing.T) {
			execLease := acquireLease(t, leaseManager)
			if _, err := broker.PrepareExecutionWithWorkload(ctx, execLease, testVerdict(), workload); err == nil {
				t.Fatal("incomplete workload reached preparation")
			}
			got, err := leaseManager.Get(ctx, execLease.LeaseID)
			if err != nil || got.Status != lease.LeaseStatusPending {
				t.Fatalf("incomplete workload changed lease state: lease=%+v err=%v", got, err)
			}
		})
	}
	if runner.validateCalled || runner.runCalled {
		t.Fatal("incomplete workload reached sandbox runner")
	}
}

func TestPrepareExecutionRejectsDetachedWorkloadBeforeLeaseActivation(t *testing.T) {
	broker, leaseManager, runner := setupBroker()
	execLease := acquireLease(t, leaseManager)
	workload := testWorkload()
	workload.Detached = true

	if _, err := broker.PrepareExecutionWithWorkload(ctx, execLease, testVerdict(), workload); err == nil {
		t.Fatal("detached workload escaped the supervised lease lifecycle")
	}
	assertLeasePendingAndRunnerUnused(t, leaseManager, execLease, runner)
}

func TestPrepareExecutionWithWorkloadRequiresVerifiedAuthorizationAndExactSignedWorkload(t *testing.T) {
	resetClock()
	credBroker := sandbox_runtime.NewCredentialBroker(3600).WithClock(clock)
	leaseManager := lease.NewInMemoryLeaseManager().WithClock(clock)
	broker := sandbox_runtime.NewSandboxBroker(credBroker, leaseManager).WithClock(clock)
	broker.RegisterRunner("docker", &mockRunner{})

	withoutVerifier := acquireLease(t, leaseManager)
	if _, err := broker.PrepareExecutionWithWorkload(ctx, withoutVerifier, authorizedVerdict(t, withoutVerifier, testWorkload()), testWorkload()); err == nil {
		t.Fatal("sandbox preparation accepted missing authorization verifier")
	}

	broker.WithAuthorizationVerifier(mockAuthorizationVerifier{valid: true})
	changedWorkload := testWorkload()
	changedWorkload.Command[0] = "/usr/bin/substituted"
	mismatched := acquireLease(t, leaseManager)
	if _, err := broker.PrepareExecutionWithWorkload(ctx, mismatched, authorizedVerdict(t, mismatched, testWorkload()), changedWorkload); err == nil {
		t.Fatal("sandbox preparation accepted workload absent from signed decision context")
	}

	broker.WithAuthorizationVerifier(mockAuthorizationVerifier{valid: false})
	unverified := acquireLease(t, leaseManager)
	if _, err := broker.PrepareExecutionWithWorkload(ctx, unverified, authorizedVerdict(t, unverified, testWorkload()), testWorkload()); err == nil {
		t.Fatal("sandbox preparation accepted unverified decision and intent")
	}

	for _, execLease := range []*lease.ExecutionLease{withoutVerifier, mismatched, unverified} {
		got, err := leaseManager.Get(ctx, execLease.LeaseID)
		if err != nil || got.Status != lease.LeaseStatusPending {
			t.Fatalf("authorization rejection changed lease state: lease=%+v err=%v", got, err)
		}
	}
}

func TestPrepareExecutionRequiresSignedFullRuntimeAndExactLeaseIdentity(t *testing.T) {
	t.Run("missing full execution authorization", func(t *testing.T) {
		broker, leaseManager, runner := setupBroker()
		execLease := acquireLease(t, leaseManager)
		if _, err := broker.PrepareExecutionWithWorkload(ctx, execLease, testVerdict(), testWorkload()); err == nil {
			t.Fatal("sandbox preparation accepted a workload-only decision")
		}
		assertLeasePendingAndRunnerUnused(t, leaseManager, execLease, runner)
	})

	t.Run("different valid source-owned lease", func(t *testing.T) {
		broker, leaseManager, runner := setupBroker()
		authorizedLease := acquireLease(t, leaseManager)
		substitutedLease := acquireLease(t, leaseManager)
		verdict := authorizedVerdict(t, authorizedLease, testWorkload())
		if _, err := broker.PrepareExecutionWithWorkload(ctx, substitutedLease, verdict, testWorkload()); err == nil {
			t.Fatal("sandbox preparation paired a signed decision with another acquired lease")
		}
		assertLeasePendingAndRunnerUnused(t, leaseManager, authorizedLease, runner)
		assertLeasePendingAndRunnerUnused(t, leaseManager, substitutedLease, runner)
	})

	t.Run("arbitrary signed sandbox instance ID", func(t *testing.T) {
		broker, leaseManager, runner := setupBroker()
		execLease := acquireLease(t, leaseManager)
		verdict := authorizedVerdict(t, execLease, testWorkload())
		authorization := verdict.Decision.InputContext[sandbox_runtime.SandboxExecutionDecisionContextKey].(sandbox_runtime.SandboxExecutionAuthorization)
		authorization.SandboxID = "sbx-caller-selected"
		verdict.Decision.InputContext[sandbox_runtime.SandboxExecutionDecisionContextKey] = authorization
		if _, err := broker.PrepareExecutionWithWorkload(ctx, execLease, verdict, testWorkload()); err == nil {
			t.Fatal("sandbox preparation accepted an instance ID not derived from the exact lease")
		}
		assertLeasePendingAndRunnerUnused(t, leaseManager, execLease, runner)
	})

	t.Run("unsigned network policy", func(t *testing.T) {
		broker, leaseManager, runner := setupBroker()
		execLease := acquireLease(t, leaseManager)
		verdict := authorizedVerdict(t, execLease, testWorkload())
		verdict.Profile.NetworkPolicy = &pkg_sandbox.NetworkPolicy{
			DNSAllowed:      true,
			EgressAllowlist: []string{"0.0.0.0/0"},
		}
		if _, err := broker.PrepareExecutionWithWorkload(ctx, execLease, verdict, testWorkload()); err == nil {
			t.Fatal("sandbox preparation accepted a network policy absent from the signed decision")
		}
		assertLeasePendingAndRunnerUnused(t, leaseManager, execLease, runner)
	})

	t.Run("unsigned in-place network allowlist mutation", func(t *testing.T) {
		broker, leaseManager, runner := setupBroker()
		execLease := acquireLease(t, leaseManager)
		verdict := testVerdict()
		verdict.Profile.NetworkPolicy = &pkg_sandbox.NetworkPolicy{
			DNSAllowed:      true,
			EgressAllowlist: []string{"api.example.invalid:443"},
		}
		authorization, err := sandbox_runtime.BuildSandboxExecutionAuthorization(execLease, verdict.Profile, testWorkload())
		if err != nil {
			t.Fatal(err)
		}
		verdict.Decision.InputContext[sandbox_runtime.SandboxExecutionDecisionContextKey] = authorization
		verdict.Profile.NetworkPolicy.EgressAllowlist[0] = "0.0.0.0/0"
		if _, err := broker.PrepareExecutionWithWorkload(ctx, execLease, verdict, testWorkload()); err == nil {
			t.Fatal("sandbox preparation accepted an in-place allowlist mutation absent from the signed decision")
		}
		assertLeasePendingAndRunnerUnused(t, leaseManager, execLease, runner)
	})

	t.Run("unsigned resource limits", func(t *testing.T) {
		broker, leaseManager, runner := setupBroker()
		execLease := acquireLease(t, leaseManager)
		verdict := authorizedVerdict(t, execLease, testWorkload())
		verdict.Profile.Limits = &pkg_sandbox.ResourceLimits{
			CPUMillis: 8000, MemoryMB: 16384, DiskMB: 100000, Timeout: 24 * time.Hour, MaxProcesses: 10000,
		}
		if _, err := broker.PrepareExecutionWithWorkload(ctx, execLease, verdict, testWorkload()); err == nil {
			t.Fatal("sandbox preparation accepted resource limits absent from the signed decision")
		}
		assertLeasePendingAndRunnerUnused(t, leaseManager, execLease, runner)
	})
}

func assertLeasePendingAndRunnerUnused(t *testing.T, leaseManager *lease.InMemoryLeaseManager, execLease *lease.ExecutionLease, runner *mockRunner) {
	t.Helper()
	got, err := leaseManager.Get(ctx, execLease.LeaseID)
	if err != nil || got.Status != lease.LeaseStatusPending {
		t.Fatalf("rejected runtime changed lease state: lease=%+v err=%v", got, err)
	}
	if runner.validateCalled || runner.runCalled {
		t.Fatal("rejected runtime reached sandbox runner")
	}
}

func TestPrepareExecutionWithWorkloadRejectsLeaseSubstitutionBeforeSideEffects(t *testing.T) {
	broker, leaseManager, runner := setupBroker()
	sourceLease := acquireLease(t, leaseManager)
	substituted := *sourceLease
	substituted.TemplateRef = "example.invalid/substituted@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	if _, err := broker.PrepareExecutionWithWorkload(ctx, &substituted, authorizedVerdict(t, sourceLease, testWorkload()), testWorkload()); err == nil {
		t.Fatal("substituted lease reached preparation")
	}
	if runner.validateCalled || runner.runCalled {
		t.Fatal("substituted lease reached sandbox runner")
	}
	got, err := leaseManager.Get(ctx, sourceLease.LeaseID)
	if err != nil || got.Status != lease.LeaseStatusPending {
		t.Fatalf("lease substitution changed source-owned state: lease=%+v err=%v", got, err)
	}
}

func TestPrepareExecution_NoRunner(t *testing.T) {
	broker, lm, _ := setupBroker()
	l, _ := lm.Acquire(ctx, lease.LeaseRequest{
		RunID:       "run-1",
		Backend:     "wasi", // no runner registered for wasi
		ProfileName: "net-limited",
		TemplateRef: "example.invalid/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TTL:         1 * time.Hour,
	})
	verdict := testVerdict()
	verdict.Profile.Backend = "wasi"
	authorization, authErr := sandbox_runtime.BuildSandboxExecutionAuthorization(l, verdict.Profile, testWorkload())
	if authErr != nil {
		t.Fatal(authErr)
	}
	verdict.Decision.InputContext[sandbox_runtime.SandboxExecutionDecisionContextKey] = authorization

	_, err := broker.PrepareExecutionWithWorkload(ctx, l, verdict, testWorkload())
	if err == nil {
		t.Fatal("expected error for missing runner")
	}
}

func TestExecute(t *testing.T) {
	broker, lm, runner := setupBroker()
	l := acquireLease(t, lm)
	prepared, _ := broker.PrepareExecutionWithWorkload(ctx, l, authorizedVerdict(t, l, testWorkload()), testWorkload())

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
	if runner.lastSpec == nil || len(runner.lastSpec.Command) != 1 || runner.lastSpec.Command[0] != "/usr/bin/example" || runner.lastSpec.Env["MODE"] != "test" {
		t.Fatalf("runner received incomplete authorized workload: %#v", runner.lastSpec)
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
	prepared, _ := broker.PrepareExecutionWithWorkload(ctx, l, authorizedVerdict(t, l, testWorkload()), testWorkload())

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
	prepared, _ := broker.PrepareExecutionWithWorkload(ctx, l, authorizedVerdict(t, l, testWorkload()), testWorkload())

	_, _, err := broker.Execute(ctx, prepared)
	if err == nil {
		t.Fatal("expected error from failed validation")
	}
}

func TestPrepareExecution_NilLease(t *testing.T) {
	broker, _, _ := setupBroker()
	_, err := broker.PrepareExecutionWithWorkload(ctx, nil, testVerdict(), testWorkload())
	if err == nil {
		t.Fatal("expected error for nil lease")
	}
}

func TestPrepareExecution_NilVerdict(t *testing.T) {
	broker, lm, _ := setupBroker()
	l := acquireLease(t, lm)
	_, err := broker.PrepareExecutionWithWorkload(ctx, l, nil, testWorkload())
	if err == nil {
		t.Fatal("expected error for nil verdict")
	}
}

func TestExecute_TokenListMutationIsRejectedAndPreparedCredentialsAreRevoked(t *testing.T) {
	resetClock()
	credBroker := sandbox_runtime.NewCredentialBroker(3600).WithClock(clock)
	lm := lease.NewInMemoryLeaseManager().WithClock(clock)
	broker := sandbox_runtime.NewSandboxBroker(credBroker, lm).
		WithAuthorizationVerifier(mockAuthorizationVerifier{valid: true}).
		WithClock(clock)
	runner := &mockRunner{}
	broker.RegisterRunner("docker", runner)
	l, err := lm.Acquire(ctx, lease.LeaseRequest{
		RunID:         "run-1",
		WorkspacePath: "/workspace",
		Backend:       "docker",
		ProfileName:   "net-limited",
		TemplateRef:   "example.invalid/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TTL:           time.Hour,
		SecretBindings: []lease.SecretBinding{{
			SecretRef: "repo-token",
			Scopes:    []string{"repo:read"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	verdict := authorizedVerdict(t, l, testWorkload())
	authorization := verdict.Decision.InputContext[sandbox_runtime.SandboxExecutionDecisionContextKey].(sandbox_runtime.SandboxExecutionAuthorization)
	credBroker.SetScopeAllowlist(authorization.SandboxID, []string{"repo:read"})
	prepared, err := broker.PrepareExecutionWithWorkload(ctx, l, verdict, testWorkload())
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
	if len(runner.lastCredentials) != 0 {
		t.Fatal("rejected execution released broker credentials to the runner")
	}
	if len(credBroker.GetIssuances()) != 1 {
		t.Fatal("expected one auditable credential issuance")
	}
	got, getErr := lm.Get(ctx, l.LeaseID)
	if getErr != nil || got.Status != lease.LeaseStatusCompleted {
		t.Fatalf("rejected execution lease was not completed: lease=%+v err=%v", got, getErr)
	}
}

func TestExecuteCredentialsStayInsideBrokerRunnerBoundary(t *testing.T) {
	resetClock()
	credBroker := sandbox_runtime.NewCredentialBroker(3600).WithClock(clock)
	lm := lease.NewInMemoryLeaseManager().WithClock(clock)
	broker := sandbox_runtime.NewSandboxBroker(credBroker, lm).
		WithAuthorizationVerifier(mockAuthorizationVerifier{valid: true}).
		WithClock(clock)
	runner := &mockRunner{}
	runner.credentialCheck = func(credentials []sandbox_runtime.SandboxCredentialMaterial) error {
		if len(credentials) != 1 || credentials[0].SecretRef != "repo-token" || len(credentials[0].Scopes) != 1 || credentials[0].Scopes[0] != "repo:read" {
			return fmt.Errorf("unexpected credential binding")
		}
		if valid, reason := credBroker.ValidateToken(credentials[0].BearerToken); !valid {
			return fmt.Errorf("runner received invalid credential: %s", reason)
		}
		return nil
	}
	broker.RegisterRunner("docker", runner)
	l, err := lm.Acquire(ctx, lease.LeaseRequest{
		RunID:         "run-credential-boundary",
		WorkspacePath: "/workspace",
		Backend:       "docker",
		ProfileName:   "net-limited",
		TemplateRef:   "example.invalid/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TTL:           time.Hour,
		SecretBindings: []lease.SecretBinding{{
			SecretRef: "repo-token",
			EnvVar:    "REPO_TOKEN",
			Scopes:    []string{"repo:read"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	verdict := authorizedVerdict(t, l, testWorkload())
	authorization := verdict.Decision.InputContext[sandbox_runtime.SandboxExecutionDecisionContextKey].(sandbox_runtime.SandboxExecutionAuthorization)
	credBroker.SetScopeAllowlist(authorization.SandboxID, []string{"repo:read"})
	prepared, err := broker.PrepareExecutionWithWorkload(ctx, l, verdict, testWorkload())
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), "hsk_") || strings.Contains(string(serialized), "bearer_token") {
		t.Fatal("caller-visible prepared execution serialized broker credential material")
	}
	if _, _, err := broker.Execute(ctx, prepared); err != nil {
		t.Fatal(err)
	}
	if len(runner.lastCredentials) != 1 {
		t.Fatal("trusted runner did not receive the broker-sealed credential")
	}
	if valid, reason := credBroker.ValidateToken(runner.lastCredentials[0].BearerToken); valid || reason != "token revoked" {
		t.Fatalf("credential remained valid after execution cleanup: valid=%v reason=%q", valid, reason)
	}
}

func TestPrepareExecutionRejectsCredentialsForSpecOnlyRunnerBeforeSideEffects(t *testing.T) {
	resetClock()
	credBroker := sandbox_runtime.NewCredentialBroker(3600).WithClock(clock)
	lm := lease.NewInMemoryLeaseManager().WithClock(clock)
	broker := sandbox_runtime.NewSandboxBroker(credBroker, lm).
		WithAuthorizationVerifier(mockAuthorizationVerifier{valid: true}).
		WithClock(clock)
	inner := &mockRunner{}
	broker.RegisterRunner("docker", specOnlyRunner{inner: inner})
	l, err := lm.Acquire(ctx, lease.LeaseRequest{
		RunID:         "run-unsupported-credential-runner",
		WorkspacePath: "/workspace",
		Backend:       "docker",
		ProfileName:   "net-limited",
		TemplateRef:   "example.invalid/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TTL:           time.Hour,
		SecretBindings: []lease.SecretBinding{{
			SecretRef: "repo-token",
			EnvVar:    "REPO_TOKEN",
			Scopes:    []string{"repo:read"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.PrepareExecutionWithWorkload(ctx, l, authorizedVerdict(t, l, testWorkload()), testWorkload()); err == nil {
		t.Fatal("spec-only runner accepted a lease containing credentials")
	}
	got, getErr := lm.Get(ctx, l.LeaseID)
	if getErr != nil || got.Status != lease.LeaseStatusPending {
		t.Fatalf("unsupported credential runner changed lease state: lease=%+v err=%v", got, getErr)
	}
	if len(credBroker.GetIssuances()) != 0 || inner.validateCalled || inner.runCalled {
		t.Fatal("unsupported credential runner triggered a credential or runner side effect")
	}
}

func TestExecute_LeaseCompletionFailureIsRecorded(t *testing.T) {
	resetClock()
	credBroker := sandbox_runtime.NewCredentialBroker(3600).WithClock(clock)
	baseManager := lease.NewInMemoryLeaseManager().WithClock(clock)
	broker := sandbox_runtime.NewSandboxBroker(credBroker, failingCompleteLeaseManager{InMemoryLeaseManager: baseManager}).
		WithAuthorizationVerifier(mockAuthorizationVerifier{valid: true}).
		WithClock(clock)
	runner := &mockRunner{}
	broker.RegisterRunner("docker", runner)

	l := acquireLease(t, baseManager)
	prepared, err := broker.PrepareExecutionWithWorkload(ctx, l, authorizedVerdict(t, l, testWorkload()), testWorkload())
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
