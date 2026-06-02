package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	inner "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

func TestBranchFS(t *testing.T) {
	restore := replaceBranchFSHooks()
	defer restore()

	root := t.TempDir()
	branchFSTempDir = func() string { return root }

	fs, err := NewBranchFS("/workspace", "branch-1")
	if err != nil {
		t.Fatalf("NewBranchFS: %v", err)
	}
	if fs.BaseDir != "/workspace" {
		t.Fatalf("BaseDir = %q", fs.BaseDir)
	}
	if want := filepath.Join(root, "helm-branchfs", "branch-1"); fs.BranchDir != want {
		t.Fatalf("BranchDir = %q, want %q", fs.BranchDir, want)
	}
	if _, err := os.Stat(fs.BranchDir); err != nil {
		t.Fatalf("branch dir was not created: %v", err)
	}
	if err := fs.Mount(context.Background()); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if err := fs.Unmount(context.Background()); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	hash, err := fs.Commit(context.Background())
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if hash != "sha256:branchfs_commit_hash_placeholder" {
		t.Fatalf("unexpected commit hash %q", hash)
	}
	if err := fs.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	branchFSMkdirAll = func(string, os.FileMode) error {
		return errors.New("mkdir failed")
	}
	if _, err := NewBranchFS("/workspace", "branch-2"); err == nil {
		t.Fatal("expected NewBranchFS mkdir error")
	}
	restore()

	branchFSRemoveAll = func(string) error {
		return errors.New("remove failed")
	}
	if err := (&BranchFS{BranchDir: "/tmp/branch"}).Cleanup(); err == nil {
		t.Fatal("expected cleanup error")
	}
}

func TestRunnerBridgePreflightAndProvider(t *testing.T) {
	bridge := NewRunnerBridge(&fakeRunner{}, "legacy")
	instant := time.Unix(100, 0)
	bridge.clock = func() time.Time { return instant }

	if bridge.Provider() != "legacy" {
		t.Fatalf("Provider = %q", bridge.Provider())
	}
	report, err := bridge.Preflight(context.Background())
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if report.Provider != "legacy" || !report.StrictPassed || !report.CheckedAt.Equal(instant) {
		t.Fatalf("unexpected preflight report: %#v", report)
	}
	if len(report.Checks) != 1 || !report.Checks[0].Passed {
		t.Fatalf("unexpected checks: %#v", report.Checks)
	}

	nilBridge := NewRunnerBridge(nil, "missing")
	nilReport, err := nilBridge.Preflight(context.Background())
	if err != nil {
		t.Fatalf("nil Preflight: %v", err)
	}
	if nilReport.Checks[0].Passed {
		t.Fatalf("nil runner should fail preflight: %#v", nilReport.Checks[0])
	}
}

func TestRunnerBridgeCreate(t *testing.T) {
	runner := &fakeRunner{}
	bridge := NewRunnerBridge(runner, "legacy")
	instant := time.Unix(200, 0)
	bridge.clock = func() time.Time { return instant }

	spec := sandboxSpec()
	handle, err := bridge.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if handle.ID != "bridge-200000000000" || handle.Provider != "legacy" || handle.Status != actuators.StatusRunning || !handle.CreatedAt.Equal(instant) {
		t.Fatalf("unexpected handle: %#v", handle)
	}
	if bridge.specs[handle.ID] != spec {
		t.Fatal("created spec was not tracked")
	}
	if runner.validated == nil || runner.validated.Image != "runtime-image" || runner.validated.Network.Disabled != true {
		t.Fatalf("unexpected legacy validation spec: %#v", runner.validated)
	}

	runner.validateErr = errors.New("invalid spec")
	if _, err := bridge.Create(context.Background(), spec); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestRunnerBridgeExec(t *testing.T) {
	runner := &fakeRunner{
		result: &inner.Result{
			ExitCode: 7,
			Stdout:   []byte("out"),
			Stderr:   []byte("err"),
			Duration: time.Second,
			TimedOut: true,
		},
	}
	bridge := NewRunnerBridge(runner, "legacy")
	instant := time.Unix(300, 0)
	bridge.clock = func() time.Time { return instant }
	spec := sandboxSpec()
	handle, err := bridge.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := &actuators.ExecRequest{
		Command: []string{"sh", "-c", "echo ok"},
		WorkDir: "/workspace/app",
		Env:     map[string]string{"A": "B"},
		Timeout: time.Minute,
	}
	result, err := bridge.Exec(context.Background(), handle.ID, req)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if result.ExitCode != 7 || string(result.Stdout) != "out" || string(result.Stderr) != "err" || result.Duration != time.Second || !result.TimedOut {
		t.Fatalf("unexpected exec result: %#v", result)
	}
	if result.Receipt.Provider != "legacy" || !result.Receipt.ExecutedAt.Equal(instant) {
		t.Fatalf("unexpected receipt: %#v", result.Receipt)
	}
	if runner.ran.Command[0] != "sh" || runner.ran.Args[0] != "-c" || runner.ran.Args[1] != "echo ok" || runner.ran.WorkDir != "/workspace/app" {
		t.Fatalf("unexpected run spec: %#v", runner.ran)
	}

	oneArgReq := &actuators.ExecRequest{Command: []string{"true"}}
	if _, err := bridge.Exec(context.Background(), "unknown", oneArgReq); err != nil {
		t.Fatalf("Exec one command: %v", err)
	}
	if len(runner.ran.Args) != 0 {
		t.Fatalf("expected no args for one-word command, got %#v", runner.ran.Args)
	}

	runner.runErr = errors.New("run failed")
	if _, err := bridge.Exec(context.Background(), handle.ID, req); err == nil {
		t.Fatal("expected run error")
	}
}

func TestRunnerBridgeUnsupportedOperations(t *testing.T) {
	bridge := NewRunnerBridge(&fakeRunner{}, "legacy")
	ctx := context.Background()

	if _, err := bridge.Resume(ctx, "id"); !errors.Is(err, actuators.ErrNotSupported) {
		t.Fatalf("Resume error = %v", err)
	}
	if err := bridge.Pause(ctx, "id"); !errors.Is(err, actuators.ErrNotSupported) {
		t.Fatalf("Pause error = %v", err)
	}
	if err := bridge.Terminate(ctx, "id"); err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	if _, err := bridge.ReadFile(ctx, "id", "/tmp/a"); !errors.Is(err, actuators.ErrNotSupported) {
		t.Fatalf("ReadFile error = %v", err)
	}
	if err := bridge.WriteFile(ctx, "id", "/tmp/a", []byte("x")); !errors.Is(err, actuators.ErrNotSupported) {
		t.Fatalf("WriteFile error = %v", err)
	}
	if _, err := bridge.ListFiles(ctx, "id", "/tmp"); !errors.Is(err, actuators.ErrNotSupported) {
		t.Fatalf("ListFiles error = %v", err)
	}
	if err := bridge.AllowEgress(ctx, "id", nil); !errors.Is(err, actuators.ErrNotSupported) {
		t.Fatalf("AllowEgress error = %v", err)
	}
	if _, err := bridge.Logs(ctx, "id", nil); !errors.Is(err, actuators.ErrNotSupported) {
		t.Fatalf("Logs error = %v", err)
	}
}

func TestToLegacySpec(t *testing.T) {
	legacy := toLegacySpec(sandboxSpec())
	if legacy.Image != "runtime-image" || legacy.WorkDir != "/workspace" {
		t.Fatalf("unexpected legacy basics: %#v", legacy)
	}
	if legacy.Limits.CPUMillis != 250 || legacy.Limits.MemoryMB != 512 || legacy.Limits.DiskMB != 1024 || legacy.Limits.Timeout != time.Minute || legacy.Limits.MaxProcesses != 9 {
		t.Fatalf("unexpected legacy limits: %#v", legacy.Limits)
	}
	if !legacy.Network.Disabled {
		t.Fatalf("expected disabled network: %#v", legacy.Network)
	}
}

type fakeRunner struct {
	validated   *inner.SandboxSpec
	ran         *inner.SandboxSpec
	result      *inner.Result
	validateErr error
	runErr      error
}

func (r *fakeRunner) Validate(spec *inner.SandboxSpec) error {
	r.validated = spec
	return r.validateErr
}

func (r *fakeRunner) Run(spec *inner.SandboxSpec) (*inner.Result, *inner.ExecutionReceipt, error) {
	r.ran = spec
	if r.runErr != nil {
		return nil, nil, r.runErr
	}
	if r.result != nil {
		return r.result, nil, nil
	}
	return &inner.Result{ExitCode: 0}, nil, nil
}

func sandboxSpec() *actuators.SandboxSpec {
	return &actuators.SandboxSpec{
		Runtime: "runtime-image",
		Resources: actuators.ResourceSpec{
			CPUMillis:    250,
			MemoryMB:     512,
			DiskMB:       1024,
			Timeout:      time.Minute,
			MaxProcesses: 9,
		},
		Egress: actuators.EgressPolicy{Disabled: true},
	}
}

func replaceBranchFSHooks() func() {
	originalTempDir := branchFSTempDir
	originalMkdirAll := branchFSMkdirAll
	originalRemoveAll := branchFSRemoveAll
	return func() {
		branchFSTempDir = originalTempDir
		branchFSMkdirAll = originalMkdirAll
		branchFSRemoveAll = originalRemoveAll
	}
}
