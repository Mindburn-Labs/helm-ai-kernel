// Package sandbox provides a bridge between the legacy sandbox.Runner interface
// and the modern SandboxActuator contract.
//
// This bridge ensures backward compatibility: code using sandbox.Runner can
// be gradually migrated to the SandboxActuator interface without breakage.
package sandbox

import (
	"context"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
	inner "github.com/Mindburn-Labs/helm-oss/core/pkg/sandbox"
)

// RunnerBridge wraps a legacy sandbox.Runner as a partial SandboxActuator.
// Methods not supported by the Runner interface return ErrNotSupported.
type RunnerBridge struct {
	runner   inner.Runner
	provider string
	clock    func() time.Time
	specs    map[string]*actuators.SandboxSpec // tracks spec per sandbox ID
}

// NewRunnerBridge creates a bridge from a legacy Runner to the actuator interface.
func NewRunnerBridge(runner inner.Runner, provider string) *RunnerBridge {
	return &RunnerBridge{
		runner:   runner,
		provider: provider,
		clock:    time.Now,
		specs:    make(map[string]*actuators.SandboxSpec),
	}
}

func (b *RunnerBridge) Provider() string { return b.provider }

func (b *RunnerBridge) Preflight(_ context.Context) (*actuators.PreflightReport, error) {
	return &actuators.PreflightReport{
		Provider:     b.provider,
		StrictPassed: true,
		Checks: []actuators.PreflightCheck{
			{
				Name:     "legacy_runner_present",
				Passed:   b.runner != nil,
				Required: true,
				Reason:   "legacy sandbox.Runner is configured",
			},
		},
		CheckedAt: b.clock(),
	}, nil
}

// Create validates the spec and returns a handle. The legacy Runner doesn't
// manage lifecycle separately, so we synthesize a handle.
func (b *RunnerBridge) Create(ctx context.Context, spec *actuators.SandboxSpec) (*actuators.SandboxHandle, error) {
	legacySpec := toLegacySpec(spec)
	if err := b.runner.Validate(legacySpec); err != nil {
		return nil, fmt.Errorf("runner bridge: validate failed: %w", err)
	}
	id := fmt.Sprintf("bridge-%d", b.clock().UnixNano())
	b.specs[id] = spec
	return &actuators.SandboxHandle{
		ID:        id,
		Provider:  b.provider,
		Status:    actuators.StatusRunning,
		CreatedAt: b.clock(),
	}, nil
}

// Exec runs a command using the legacy Runner.Run() method.
func (b *RunnerBridge) Exec(_ context.Context, id string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	legacySpec := &inner.SandboxSpec{
		Command: req.Command[:1],
		WorkDir: req.WorkDir,
		Env:     req.Env,
		Limits: inner.ResourceLimits{
			Timeout: req.Timeout,
		},
	}
	if len(req.Command) > 1 {
		legacySpec.Args = req.Command[1:]
	}

	result, _, err := b.runner.Run(legacySpec)
	if err != nil {
		return nil, fmt.Errorf("runner bridge: run failed: %w", err)
	}

	now := b.clock()
	spec := b.specs[id] // may be nil for non-bridge-created sandboxes
	return &actuators.ExecResult{
		ExitCode: result.ExitCode,
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
		Duration: result.Duration,
		TimedOut: result.TimedOut,
		Receipt:  actuators.ComputeReceiptFragment(req, result.Stdout, result.Stderr, b.provider, now, spec, actuators.EffectExecShell),
	}, nil
}

// ── Unsupported by legacy Runner ────────────────────────────────

func (b *RunnerBridge) Resume(_ context.Context, _ string) (*actuators.SandboxHandle, error) {
	return nil, actuators.ErrNotSupported
}

func (b *RunnerBridge) Pause(_ context.Context, _ string) error {
	return actuators.ErrNotSupported
}

func (b *RunnerBridge) Terminate(_ context.Context, _ string) error {
	return nil // No lifecycle to manage in legacy runner.
}

func (b *RunnerBridge) ReadFile(_ context.Context, _ string, _ string) ([]byte, error) {
	return nil, actuators.ErrNotSupported
}

func (b *RunnerBridge) WriteFile(_ context.Context, _ string, _ string, _ []byte) error {
	return actuators.ErrNotSupported
}

func (b *RunnerBridge) ListFiles(_ context.Context, _ string, _ string) ([]actuators.FileEntry, error) {
	return nil, actuators.ErrNotSupported
}

func (b *RunnerBridge) AllowEgress(_ context.Context, _ string, _ []actuators.EgressRule) error {
	return actuators.ErrNotSupported
}

func (b *RunnerBridge) Logs(_ context.Context, _ string, _ *actuators.LogOptions) ([]actuators.LogEntry, error) {
	return nil, actuators.ErrNotSupported
}

// ── Helpers ─────────────────────────────────────────────────────

func toLegacySpec(spec *actuators.SandboxSpec) *inner.SandboxSpec {
	return &inner.SandboxSpec{
		Image:   spec.Runtime,
		WorkDir: "/workspace",
		Limits: inner.ResourceLimits{
			CPUMillis:    spec.Resources.CPUMillis,
			MemoryMB:     spec.Resources.MemoryMB,
			DiskMB:       spec.Resources.DiskMB,
			Timeout:      spec.Resources.Timeout,
			MaxProcesses: spec.Resources.MaxProcesses,
		},
		Network: inner.NetworkPolicy{
			Disabled: spec.Egress.Disabled,
		},
	}
}
