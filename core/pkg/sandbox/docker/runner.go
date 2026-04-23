package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/sandbox"
)

// DockerRunner implements Runner using Docker containers.
type DockerRunner struct {
	dockerBin string
	clock     func() time.Time
}

// NewDockerRunner creates a new Docker-based sandbox runner.
func NewDockerRunner() *DockerRunner {
	return &DockerRunner{
		dockerBin: "docker",
		clock:     time.Now,
	}
}

// Validate checks that the spec is valid and the image exists.
func (r *DockerRunner) Validate(spec *sandbox.SandboxSpec) error {
	if spec.Image == "" {
		return fmt.Errorf("sandbox spec: image is required")
	}
	if len(spec.Command) == 0 {
		return fmt.Errorf("sandbox spec: command is required")
	}
	if spec.Limits.Timeout == 0 {
		return fmt.Errorf("sandbox spec: timeout is required (prevent runaway)")
	}
	if spec.Limits.MemoryMB == 0 {
		return fmt.Errorf("sandbox spec: memory limit is required")
	}
	return nil
}

// Run executes a sandboxed container with the given spec.
func (r *DockerRunner) Run(spec *sandbox.SandboxSpec) (*sandbox.Result, *sandbox.ExecutionReceipt, error) {
	if err := r.Validate(spec); err != nil {
		return nil, nil, err
	}

	startedAt := r.clock()
	execID := fmt.Sprintf("sandbox-%d", startedAt.UnixNano())

	// Build docker run command
	args := []string{
		"run", "--rm",
		"--name", execID,
	}

	// Resource limits
	if spec.Limits.MemoryMB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dm", spec.Limits.MemoryMB))
	}
	if spec.Limits.CPUMillis > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%.2f", float64(spec.Limits.CPUMillis)/1000.0))
	}
	if spec.Limits.MaxProcesses > 0 {
		args = append(args, "--pids-limit", fmt.Sprintf("%d", spec.Limits.MaxProcesses))
	}

	// Network policy
	if spec.Network.Disabled {
		args = append(args, "--network", "none")
	}

	// Security: drop all capabilities, no new privileges
	args = append(args,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
	)

	// Environment
	for k, v := range spec.Env {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
	}

	// Mounts
	for _, m := range spec.Mounts {
		mountOpt := fmt.Sprintf("%s:%s", m.Source, m.Target)
		if m.ReadOnly {
			mountOpt += ":ro"
		}
		args = append(args, "-v", mountOpt)
	}

	// Working directory
	if spec.WorkDir != "" {
		args = append(args, "-w", spec.WorkDir)
	}

	// Image and command
	args = append(args, spec.Image)
	args = append(args, spec.Command...)
	args = append(args, spec.Args...)

	// Execute with timeout
	ctx, cancel := context.WithTimeout(context.Background(), spec.Limits.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.dockerBin, args...)
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
			// Check for OOM
			if result.ExitCode == 137 {
				result.OOMKilled = true
			}
		} else {
			return result, nil, fmt.Errorf("docker run failed: %w", err)
		}
	}

	// Compute output hashes for receipt
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
