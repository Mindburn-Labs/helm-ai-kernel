package sandbox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

func TestMockActuatorCoreBranches(t *testing.T) {
	ctx := context.Background()
	fixed := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	mock := NewMockActuator().WithClock(func() time.Time { return fixed })

	handle, err := mock.Create(ctx, defaultSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !handle.CreatedAt.Equal(fixed) {
		t.Fatalf("expected fixed clock timestamp, got %v", handle.CreatedAt)
	}

	result, err := mock.Exec(ctx, handle.ID, &actuators.ExecRequest{Command: []string{"echo", "hello", "world"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Stdout) != "hello world\n" {
		t.Fatalf("unexpected echo stdout: %q", result.Stdout)
	}
	if got := computeRequestHash(&actuators.ExecRequest{Command: []string{"echo", "hello", "world"}}); got != result.Receipt.RequestHash {
		t.Fatalf("computeRequestHash mismatch: got %s want %s", got, result.Receipt.RequestHash)
	}

	if _, err := mock.Exec(ctx, "missing", &actuators.ExecRequest{}); !errors.Is(err, actuators.ErrSandboxNotFound) {
		t.Fatalf("expected missing exec sandbox error, got %v", err)
	}
	if err := mock.Pause(ctx, handle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := mock.Exec(ctx, handle.ID, &actuators.ExecRequest{Command: []string{"echo", "paused"}}); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("expected paused exec to fail, got %v", err)
	}
	if err := mock.Terminate(ctx, handle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := mock.Resume(ctx, handle.ID); !errors.Is(err, actuators.ErrSandboxTerminated) {
		t.Fatalf("expected terminated resume error, got %v", err)
	}
}

func TestMockActuatorFileListingLogsAndMissingPaths(t *testing.T) {
	ctx := context.Background()
	fixed := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	mock := NewMockActuator().WithClock(func() time.Time { return fixed })
	handle, err := mock.Create(ctx, defaultSpec())
	if err != nil {
		t.Fatal(err)
	}

	if err := mock.WriteFile(ctx, "missing", "/tmp/a.txt", []byte("a")); !errors.Is(err, actuators.ErrSandboxNotFound) {
		t.Fatalf("expected missing write sandbox error, got %v", err)
	}
	if _, err := mock.ReadFile(ctx, "missing", "/tmp/a.txt"); !errors.Is(err, actuators.ErrSandboxNotFound) {
		t.Fatalf("expected missing read sandbox error, got %v", err)
	}
	if _, err := mock.ReadFile(ctx, handle.ID, "/tmp/missing.txt"); err == nil || !strings.Contains(err.Error(), "file not found") {
		t.Fatalf("expected missing file error, got %v", err)
	}

	if err := mock.WriteFile(ctx, handle.ID, "/tmp/a.txt", []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	if err := mock.WriteFile(ctx, handle.ID, "/tmp/b.txt", []byte("bravo")); err != nil {
		t.Fatal(err)
	}
	entries, err := mock.ListFiles(ctx, handle.ID, "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %+v", entries)
	}
	for _, entry := range entries {
		if entry.IsDir || !entry.ModTime.Equal(fixed) {
			t.Fatalf("unexpected file entry: %+v", entry)
		}
	}
	if _, err := mock.ListFiles(ctx, "missing", "/tmp"); !errors.Is(err, actuators.ErrSandboxNotFound) {
		t.Fatalf("expected missing list sandbox error, got %v", err)
	}

	if _, err := mock.Exec(ctx, handle.ID, &actuators.ExecRequest{Command: []string{"echo", "first"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := mock.Exec(ctx, handle.ID, &actuators.ExecRequest{Command: []string{"echo", "second"}}); err != nil {
		t.Fatal(err)
	}
	logs, err := mock.Logs(ctx, handle.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected all logs, got %+v", logs)
	}
	tail, err := mock.Logs(ctx, handle.ID, &actuators.LogOptions{Tail: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 1 || !strings.Contains(tail[0].Line, "second") {
		t.Fatalf("unexpected tail logs: %+v", tail)
	}
	if _, err := mock.Logs(ctx, "missing", nil); !errors.Is(err, actuators.ErrSandboxNotFound) {
		t.Fatalf("expected missing logs sandbox error, got %v", err)
	}
}

func TestMockFaultAndDeterminismErrorBranches(t *testing.T) {
	ctx := context.Background()
	mock := NewMockActuator()
	mock.InjectFault(FaultConfig{})
	report, err := mock.Preflight(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !report.StrictPassed {
		t.Fatalf("empty fault config should not fail preflight: %+v", report)
	}
	handle, err := mock.Create(ctx, defaultSpec())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mock.Exec(ctx, handle.ID, &actuators.ExecRequest{Command: []string{"echo", "ok"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := mock.Resume(ctx, handle.ID); err != nil {
		t.Fatal(err)
	}
	mock.ClearFaults()

	createErr := errors.New("create failed")
	if ok, err := VerifyReceiptDeterminism(&determinismFaultActuator{MockActuator: NewMockActuator(), createErr: createErr}, &actuators.ExecRequest{}); err != createErr || ok {
		t.Fatalf("expected create determinism error, ok=%v err=%v", ok, err)
	}

	execErr := errors.New("exec failed")
	if ok, err := VerifyReceiptDeterminism(&determinismFaultActuator{MockActuator: NewMockActuator(), execErrs: []error{execErr}}, &actuators.ExecRequest{}); err != execErr || ok {
		t.Fatalf("expected first exec determinism error, ok=%v err=%v", ok, err)
	}
	if ok, err := VerifyReceiptDeterminism(&determinismFaultActuator{MockActuator: NewMockActuator(), execErrs: []error{nil, execErr}}, &actuators.ExecRequest{}); err != execErr || ok {
		t.Fatalf("expected second exec determinism error, ok=%v err=%v", ok, err)
	}
}

type determinismFaultActuator struct {
	*MockActuator
	createErr error
	execErrs  []error
	execCalls int
}

func (a *determinismFaultActuator) Create(ctx context.Context, spec *actuators.SandboxSpec) (*actuators.SandboxHandle, error) {
	if a.createErr != nil {
		return nil, a.createErr
	}
	return a.MockActuator.Create(ctx, spec)
}

func (a *determinismFaultActuator) Exec(ctx context.Context, id string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	call := a.execCalls
	a.execCalls++
	if call < len(a.execErrs) && a.execErrs[call] != nil {
		return nil, a.execErrs[call]
	}
	return a.MockActuator.Exec(ctx, id, req)
}
