package sandbox

import (
	"context"
	"errors"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

func TestRegisteredSandboxConformanceFailureBranches(t *testing.T) {
	errCreate := errors.New("create failed")
	errExec := errors.New("exec failed")
	errWrite := errors.New("write failed")
	errRead := errors.New("read failed")
	errPreflight := errors.New("preflight failed")
	errPause := errors.New("pause failed")
	errResume := errors.New("resume failed")
	errEgress := errors.New("egress failed")

	expectCaseError(t, "SBX-L1-LIFECYCLE-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), createErr: errCreate})
	expectCaseFailure(t, "SBX-L1-LIFECYCLE-001", &sandboxCaseActuator{
		MockActuator: NewMockActuator(),
		createPatch: func(handle *actuators.SandboxHandle) {
			handle.ID = ""
			handle.Status = actuators.StatusPaused
			handle.Provider = "other"
		},
	})

	expectCaseError(t, "SBX-L1-EXEC-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), createErr: errCreate})
	expectCaseError(t, "SBX-L1-EXEC-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), execErrs: []error{errExec}})
	expectCaseFailure(t, "SBX-L1-EXEC-001", &sandboxCaseActuator{
		MockActuator: NewMockActuator(),
		execResults:  []*actuators.ExecResult{{ExitCode: 42}},
	})

	expectCaseError(t, "SBX-L1-FS-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), createErr: errCreate})
	expectCaseError(t, "SBX-L1-FS-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), writeErr: errWrite})
	expectCaseError(t, "SBX-L1-FS-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), readErr: errRead})
	expectCaseFailure(t, "SBX-L1-FS-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), readData: []byte("different")})

	expectCaseError(t, "SBX-L1-RECEIPT-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), createErr: errCreate})
	expectCaseError(t, "SBX-L1-RECEIPT-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), execErrs: []error{errExec}})
	expectCaseFailure(t, "SBX-L1-RECEIPT-001", &sandboxCaseActuator{
		MockActuator: NewMockActuator(),
		execResults:  []*actuators.ExecResult{{Receipt: actuators.ReceiptFragment{}}},
	})

	expectCaseError(t, "SBX-L2-PREFLIGHT-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), preflightErr: errPreflight})
	expectCaseFailure(t, "SBX-L2-PREFLIGHT-001", &sandboxCaseActuator{
		MockActuator:    NewMockActuator(),
		preflightReport: &actuators.PreflightReport{Provider: "other", StrictPassed: true},
	})

	expectCaseError(t, "SBX-L2-TIMEOUT-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), createErr: errCreate})
	expectCaseFailure(t, "SBX-L2-TIMEOUT-001", &sandboxCaseActuator{
		MockActuator: NewMockActuator(),
		execResults:  []*actuators.ExecResult{{ExitCode: 0, TimedOut: false}},
	})

	expectCaseError(t, "SBX-L2-PERSISTENCE-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), createErr: errCreate})
	expectCaseClean(t, "SBX-L2-PERSISTENCE-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), pauseErr: actuators.ErrNotSupported})
	expectCaseError(t, "SBX-L2-PERSISTENCE-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), pauseErr: errPause})
	expectCaseError(t, "SBX-L2-PERSISTENCE-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), resumeErr: errResume})
	expectCaseFailure(t, "SBX-L2-PERSISTENCE-001", &sandboxCaseActuator{
		MockActuator: NewMockActuator(),
		resumeHandle: &actuators.SandboxHandle{ID: "resumed", Status: actuators.StatusPaused, Provider: "mock"},
	})

	expectCaseError(t, "SBX-L3-EGRESS-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), createErr: errCreate})
	expectCaseClean(t, "SBX-L3-EGRESS-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), allowEgressErr: actuators.ErrNotSupported})
	expectCaseError(t, "SBX-L3-EGRESS-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), allowEgressErr: errEgress})

	expectCaseError(t, "SBX-L3-TAMPER-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), createErr: errCreate})
	expectCaseError(t, "SBX-L3-TAMPER-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), execErrs: []error{errExec}})
	expectCaseError(t, "SBX-L3-TAMPER-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), execErrs: []error{nil, errExec}})
	expectCaseFailure(t, "SBX-L3-TAMPER-001", &sandboxCaseActuator{
		MockActuator: NewMockActuator(),
		execResults: []*actuators.ExecResult{
			{Receipt: actuators.ReceiptFragment{RequestHash: "sha256:a", StdoutHash: "sha256:a"}},
			{Receipt: actuators.ReceiptFragment{RequestHash: "sha256:b", StdoutHash: "sha256:b"}},
		},
	})

	for _, id := range []string{
		"SBX-L3-AUTH-001",
		"SBX-L3-EGRESS-002",
		"SBX-L3-TIMEOUT-001",
		"SBX-L3-NETERR-001",
		"SBX-L3-MALFORMED-001",
		"SBX-L3-RESUME-001",
	} {
		expectCaseClean(t, id, &sandboxCaseActuator{MockActuator: NewMockActuator()})
	}

	expectCaseError(t, "SBX-L3-RECEIPT-SPEC-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), createErr: errCreate})
	expectCaseError(t, "SBX-L3-RECEIPT-SPEC-001", &sandboxCaseActuator{MockActuator: NewMockActuator(), execErrs: []error{errExec}})
	expectCaseFailure(t, "SBX-L3-RECEIPT-SPEC-001", &sandboxCaseActuator{
		MockActuator: NewMockActuator(),
		execResults:  []*actuators.ExecResult{{Receipt: actuators.ReceiptFragment{}}},
	})
}

func expectCaseError(t *testing.T, id string, actuator actuators.SandboxActuator) {
	t.Helper()
	failed, err := runSandboxConformanceCase(t, id, actuator)
	if err == nil {
		t.Fatalf("%s: expected error, failed=%v", id, failed)
	}
}

func expectCaseFailure(t *testing.T, id string, actuator actuators.SandboxActuator) {
	t.Helper()
	failed, err := runSandboxConformanceCase(t, id, actuator)
	if err != nil || !failed {
		t.Fatalf("%s: expected assertion failure, failed=%v err=%v", id, failed, err)
	}
}

func expectCaseClean(t *testing.T, id string, actuator actuators.SandboxActuator) {
	t.Helper()
	failed, err := runSandboxConformanceCase(t, id, actuator)
	if err != nil || failed {
		t.Fatalf("%s: expected clean result, failed=%v err=%v", id, failed, err)
	}
}

func runSandboxConformanceCase(t *testing.T, id string, actuator actuators.SandboxActuator) (bool, error) {
	t.Helper()
	suite := conformance.NewSuite()
	RegisterSandboxTests(suite, actuator)
	for _, tc := range suite.TestsForLevel(conformance.LevelL3) {
		if tc.ID != id {
			continue
		}
		ctx := &conformance.TestContext{Level: tc.Level, Category: tc.Category}
		err := tc.Run(ctx)
		return ctx.Failed(), err
	}
	t.Fatalf("sandbox conformance case %s not registered", id)
	return false, nil
}

type sandboxCaseActuator struct {
	*MockActuator
	provider        string
	createErr       error
	createPatch     func(*actuators.SandboxHandle)
	terminateErr    error
	execErrs        []error
	execResults     []*actuators.ExecResult
	execCalls       int
	writeErr        error
	readErr         error
	readData        []byte
	preflightErr    error
	preflightReport *actuators.PreflightReport
	pauseErr        error
	resumeErr       error
	resumeHandle    *actuators.SandboxHandle
	allowEgressErr  error
}

func (a *sandboxCaseActuator) Provider() string {
	if a.provider != "" {
		return a.provider
	}
	return a.MockActuator.Provider()
}

func (a *sandboxCaseActuator) Create(ctx context.Context, spec *actuators.SandboxSpec) (*actuators.SandboxHandle, error) {
	if a.createErr != nil {
		return nil, a.createErr
	}
	handle, err := a.MockActuator.Create(ctx, spec)
	if err != nil {
		return nil, err
	}
	if a.createPatch != nil {
		a.createPatch(handle)
	}
	return handle, nil
}

func (a *sandboxCaseActuator) Terminate(ctx context.Context, id string) error {
	if a.terminateErr != nil {
		return a.terminateErr
	}
	return a.MockActuator.Terminate(ctx, id)
}

func (a *sandboxCaseActuator) Exec(ctx context.Context, id string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	call := a.execCalls
	a.execCalls++
	if call < len(a.execErrs) && a.execErrs[call] != nil {
		return nil, a.execErrs[call]
	}
	if call < len(a.execResults) && a.execResults[call] != nil {
		return a.execResults[call], nil
	}
	return a.MockActuator.Exec(ctx, id, req)
}

func (a *sandboxCaseActuator) WriteFile(ctx context.Context, id string, path string, data []byte) error {
	if a.writeErr != nil {
		return a.writeErr
	}
	return a.MockActuator.WriteFile(ctx, id, path, data)
}

func (a *sandboxCaseActuator) ReadFile(ctx context.Context, id string, path string) ([]byte, error) {
	if a.readErr != nil {
		return nil, a.readErr
	}
	if a.readData != nil {
		return a.readData, nil
	}
	return a.MockActuator.ReadFile(ctx, id, path)
}

func (a *sandboxCaseActuator) Preflight(ctx context.Context) (*actuators.PreflightReport, error) {
	if a.preflightErr != nil {
		return nil, a.preflightErr
	}
	if a.preflightReport != nil {
		return a.preflightReport, nil
	}
	return a.MockActuator.Preflight(ctx)
}

func (a *sandboxCaseActuator) Pause(ctx context.Context, id string) error {
	if a.pauseErr != nil {
		return a.pauseErr
	}
	return a.MockActuator.Pause(ctx, id)
}

func (a *sandboxCaseActuator) Resume(ctx context.Context, id string) (*actuators.SandboxHandle, error) {
	if a.resumeErr != nil {
		return nil, a.resumeErr
	}
	if a.resumeHandle != nil {
		return a.resumeHandle, nil
	}
	return a.MockActuator.Resume(ctx, id)
}

func (a *sandboxCaseActuator) AllowEgress(ctx context.Context, id string, rules []actuators.EgressRule) error {
	if a.allowEgressErr != nil {
		return a.allowEgressErr
	}
	return a.MockActuator.AllowEgress(ctx, id, rules)
}

func TestMockActuatorAllowEgressMissingSandbox(t *testing.T) {
	if err := NewMockActuator().AllowEgress(context.Background(), "missing", nil); !errors.Is(err, actuators.ErrSandboxNotFound) {
		t.Fatalf("expected missing egress sandbox error, got %v", err)
	}
}

func TestSandboxCaseActuatorProviderOverride(t *testing.T) {
	actuator := &sandboxCaseActuator{MockActuator: NewMockActuator(), provider: "custom"}
	if actuator.Provider() != "custom" {
		t.Fatalf("provider override failed")
	}
}
