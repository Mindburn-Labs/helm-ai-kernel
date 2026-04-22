// Package sandbox provides containerized execution for tool invocations.
// All tool executions run in isolated containers with resource limits,
// network restrictions, and deterministic receipts.
package sandbox

import (
	"time"
)

// SandboxSpec defines the execution environment for a tool invocation.
type SandboxSpec struct {
	// Image is the container image to use (must be pinned by digest).
	Image string `json:"image"`

	// Command is the entrypoint command.
	Command []string `json:"command"`

	// Args are the command arguments.
	Args []string `json:"args"`

	// Env is the environment variables to set.
	Env map[string]string `json:"env"`

	// Mounts defines read-only volume mounts (host:container).
	Mounts []Mount `json:"mounts"`

	// Limits are the resource constraints.
	Limits ResourceLimits `json:"limits"`

	// Network defines the network policy.
	Network NetworkPolicy `json:"network"`

	// WorkDir is the working directory inside the container.
	WorkDir string `json:"workdir"`
}

// Mount is a filesystem mount for the sandbox.
type Mount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

// ResourceLimits defines CPU, memory, and time constraints.
type ResourceLimits struct {
	CPUMillis    int64         `json:"cpu_millis"`    // CPU limit in millicores (e.g., 500 = 0.5 CPU)
	MemoryMB     int64         `json:"memory_mb"`     // Memory limit in MB
	DiskMB       int64         `json:"disk_mb"`       // Disk limit in MB
	Timeout      time.Duration `json:"timeout"`       // Maximum execution time
	MaxProcesses int           `json:"max_processes"` // PID limit
}

// NetworkPolicy defines egress restrictions.
type NetworkPolicy struct {
	// Disabled completely disables networking.
	Disabled bool `json:"disabled"`

	// EgressAllowlist is a list of allowed egress destinations (host:port or CIDR).
	EgressAllowlist []string `json:"egress_allowlist"`

	// DNSAllowed enables DNS resolution.
	DNSAllowed bool `json:"dns_allowed"`
}

// Result is the outcome of a sandbox execution.
type Result struct {
	ExitCode  int           `json:"exit_code"`
	Stdout    []byte        `json:"stdout"`
	Stderr    []byte        `json:"stderr"`
	Duration  time.Duration `json:"duration"`
	OOMKilled bool          `json:"oom_killed"`
	TimedOut  bool          `json:"timed_out"`
}

// Success returns true if the execution completed with exit code 0.
func (r *Result) Success() bool {
	return r.ExitCode == 0 && !r.OOMKilled && !r.TimedOut
}

// ExecutionReceipt is a signed record of a sandbox execution.
type ExecutionReceipt struct {
	ExecutionID string      `json:"execution_id"`
	Spec        SandboxSpec `json:"spec"`
	Result      Result      `json:"result"`
	StartedAt   time.Time   `json:"started_at"`
	CompletedAt time.Time   `json:"completed_at"`
	ImageDigest string      `json:"image_digest"`
	StdoutHash  string      `json:"stdout_hash"`
	StderrHash  string      `json:"stderr_hash"`
}

// Runner is the interface for executing sandboxed processes.
type Runner interface {
	// Run executes a SandboxSpec and returns the result with a receipt.
	Run(spec *SandboxSpec) (*Result, *ExecutionReceipt, error)

	// Validate checks if a SandboxSpec is valid and the image is available.
	Validate(spec *SandboxSpec) error
}
