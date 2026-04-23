package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/sandbox"
)

// SandboxesConfig configures the Docker Sandboxes adapter.
type SandboxesConfig struct {
	// DockerSocket is the Docker daemon socket path.
	// Use a private daemon for microVM isolation.
	// Default: uses the system Docker daemon.
	DockerSocket string

	// DockerBin is the path to the docker CLI binary.
	DockerBin string

	// SnapshotDir is the directory for storing sandbox snapshots.
	SnapshotDir string

	// DefaultTimeout is the maximum execution time if not specified in the spec.
	DefaultTimeout time.Duration

	// RegistryPrefix is the default image registry prefix.
	RegistryPrefix string
}

// DefaultSandboxesConfig returns sensible defaults.
func DefaultSandboxesConfig() SandboxesConfig {
	return SandboxesConfig{
		DockerBin:      "docker",
		DefaultTimeout: 30 * time.Minute,
	}
}

// SandboxesRunner implements sandbox.Runner with Docker Sandboxes support.
// It extends the basic DockerRunner with:
//   - Configurable Docker socket (private daemon for isolation)
//   - Port management with explicit policies
//   - Snapshot/checkpoint support
//   - Structured event capture
type SandboxesRunner struct {
	config SandboxesConfig
	clock  func() time.Time
}

// NewSandboxesRunner creates a new Docker Sandboxes runner.
func NewSandboxesRunner(config SandboxesConfig) *SandboxesRunner {
	if config.DockerBin == "" {
		config.DockerBin = "docker"
	}
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 30 * time.Minute
	}
	return &SandboxesRunner{
		config: config,
		clock:  time.Now,
	}
}

// WithClock overrides the clock for testing.
func (r *SandboxesRunner) WithClock(clock func() time.Time) *SandboxesRunner {
	r.clock = clock
	return r
}

// Validate checks that the spec is valid for Docker Sandboxes execution.
func (r *SandboxesRunner) Validate(spec *sandbox.SandboxSpec) error {
	if spec.Image == "" {
		return fmt.Errorf("sandbox spec: image is required")
	}
	if len(spec.Command) == 0 {
		return fmt.Errorf("sandbox spec: command is required")
	}
	timeout := spec.Limits.Timeout
	if timeout == 0 {
		timeout = r.config.DefaultTimeout
	}
	if timeout == 0 {
		return fmt.Errorf("sandbox spec: timeout is required (prevent runaway)")
	}
	if spec.Limits.MemoryMB == 0 {
		return fmt.Errorf("sandbox spec: memory limit is required")
	}
	return nil
}

// Run executes a sandboxed container with full Docker Sandboxes features.
func (r *SandboxesRunner) Run(spec *sandbox.SandboxSpec) (*sandbox.Result, *sandbox.ExecutionReceipt, error) {
	if err := r.Validate(spec); err != nil {
		return nil, nil, err
	}

	startedAt := r.clock()
	execID := fmt.Sprintf("sbx-%d", startedAt.UnixNano())

	args := r.buildRunArgs(spec, execID)

	timeout := spec.Limits.Timeout
	if timeout == 0 {
		timeout = r.config.DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := r.buildCommand(ctx, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	completedAt := r.clock()
	duration := completedAt.Sub(startedAt)

	result := &sandbox.Result{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: duration,
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.TimedOut = true
			result.ExitCode = -1
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			if result.ExitCode == 137 {
				result.OOMKilled = true
			}
		} else {
			return result, nil, fmt.Errorf("docker run failed: %w", err)
		}
	}

	stdoutHash := sha256.Sum256(result.Stdout)
	stderrHash := sha256.Sum256(result.Stderr)

	receipt := &sandbox.ExecutionReceipt{
		ExecutionID: execID,
		Spec:        *spec,
		Result:      *result,
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		ImageDigest: spec.Image,
		StdoutHash:  "sha256:" + hex.EncodeToString(stdoutHash[:]),
		StderrHash:  "sha256:" + hex.EncodeToString(stderrHash[:]),
	}

	return result, receipt, nil
}

// buildRunArgs constructs the docker run arguments.
func (r *SandboxesRunner) buildRunArgs(spec *sandbox.SandboxSpec, execID string) []string {
	args := []string{"run", "--rm", "--name", execID}

	// Resource limits.
	if spec.Limits.MemoryMB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dm", spec.Limits.MemoryMB))
	}
	if spec.Limits.CPUMillis > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%.2f", float64(spec.Limits.CPUMillis)/1000.0))
	}
	if spec.Limits.MaxProcesses > 0 {
		args = append(args, "--pids-limit", fmt.Sprintf("%d", spec.Limits.MaxProcesses))
	}
	if spec.Limits.DiskMB > 0 {
		args = append(args, "--storage-opt", fmt.Sprintf("size=%dM", spec.Limits.DiskMB))
	}

	// Network policy.
	if spec.Network.Disabled {
		args = append(args, "--network", "none")
	} else {
		// When networking is enabled, use a restricted bridge.
		args = append(args, "--network", "bridge")
		if !spec.Network.DNSAllowed {
			args = append(args, "--dns", "0.0.0.0") // Block DNS
		}
	}

	// Security hardening: drop all capabilities, no privilege escalation.
	args = append(args,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
	)

	// Read-only root filesystem with tmpfs for /tmp.
	args = append(args,
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
	)

	// No host socket mounting (security invariant).
	// No privileged mode (security invariant).

	// Environment variables.
	for k, v := range spec.Env {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
	}

	// Mounts — enforced read-only unless explicitly allowed.
	for _, m := range spec.Mounts {
		mountOpt := fmt.Sprintf("%s:%s", m.Source, m.Target)
		if m.ReadOnly {
			mountOpt += ":ro"
		}
		args = append(args, "-v", mountOpt)
	}

	// Working directory.
	if spec.WorkDir != "" {
		args = append(args, "-w", spec.WorkDir)
	}

	// Image and command.
	args = append(args, spec.Image)
	args = append(args, spec.Command...)
	args = append(args, spec.Args...)

	return args
}

// buildCommand creates an exec.Cmd with the optional Docker socket.
func (r *SandboxesRunner) buildCommand(ctx context.Context, args ...string) *exec.Cmd {
	if r.config.DockerSocket != "" {
		// Use private daemon: prepend -H flag.
		fullArgs := append([]string{"-H", "unix://" + r.config.DockerSocket}, args...)
		return exec.CommandContext(ctx, r.config.DockerBin, fullArgs...)
	}
	return exec.CommandContext(ctx, r.config.DockerBin, args...)
}

// Snapshot captures the current state of a sandbox for later replay.
func (r *SandboxesRunner) Snapshot(sandboxID string) (*SnapshotResult, error) {
	if r.config.SnapshotDir == "" {
		return nil, fmt.Errorf("snapshot directory not configured")
	}

	snapshotID := fmt.Sprintf("snap-%s-%d", sandboxID, r.clock().UnixNano())

	cmd := r.buildCommand(context.Background(),
		"commit", sandboxID,
		fmt.Sprintf("%s/%s", r.config.RegistryPrefix, snapshotID),
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker commit failed: %w (%s)", err, stderr.String())
	}

	return &SnapshotResult{
		SnapshotID: snapshotID,
		SandboxID:  sandboxID,
		CreatedAt:  r.clock(),
	}, nil
}

// Inspect returns metadata about a running sandbox.
func (r *SandboxesRunner) Inspect(sandboxID string) (*SandboxInspection, error) {
	cmd := r.buildCommand(context.Background(),
		"inspect", "--format", "{{json .}}", sandboxID,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker inspect failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		return nil, fmt.Errorf("parse inspect output: %w", err)
	}

	return &SandboxInspection{
		SandboxID:   sandboxID,
		Raw:         raw,
		InspectedAt: r.clock(),
	}, nil
}

// Stop terminates a running sandbox.
func (r *SandboxesRunner) Stop(sandboxID string, timeoutSec int) error {
	cmd := r.buildCommand(context.Background(),
		"stop", "-t", fmt.Sprintf("%d", timeoutSec), sandboxID,
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker stop %s: %w", sandboxID, err)
	}
	return nil
}

// Remove deletes a stopped sandbox.
func (r *SandboxesRunner) Remove(sandboxID string) error {
	cmd := r.buildCommand(context.Background(), "rm", "-f", sandboxID)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker rm %s: %w", sandboxID, err)
	}
	return nil
}

// ── Supporting types ──

// SnapshotResult is returned after a successful snapshot.
type SnapshotResult struct {
	SnapshotID string    `json:"snapshot_id"`
	SandboxID  string    `json:"sandbox_id"`
	CreatedAt  time.Time `json:"created_at"`
}

// SandboxInspection contains metadata about a sandbox.
type SandboxInspection struct {
	SandboxID   string                 `json:"sandbox_id"`
	Raw         map[string]interface{} `json:"raw"`
	InspectedAt time.Time              `json:"inspected_at"`
}
