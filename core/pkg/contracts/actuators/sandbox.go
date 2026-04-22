// Package actuators defines the canonical interfaces for external execution surfaces.
// Actuators are the "thin waist" between HELM's governance plane and provider-specific
// APIs (sandboxes, code runners, cloud services).
package actuators

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// ──────────────────────────────────────────────────────────────────
// EffectClass — canonical classification for sandbox effects.
// Policies use these to reason about sandbox actions at method-level
// granularity, the same way they reason about tool effects.
// ──────────────────────────────────────────────────────────────────

// EffectClass classifies a sandbox operation for policy evaluation.
type EffectClass string

const (
	EffectExecShell          EffectClass = "EXEC_SHELL"
	EffectExecCode           EffectClass = "EXEC_CODE"
	EffectFSWrite            EffectClass = "FS_WRITE"
	EffectFSRead             EffectClass = "FS_READ"
	EffectNetExposePort      EffectClass = "NET_EXPOSE_PORT"
	EffectNetEgressChange    EffectClass = "NET_EGRESS_ALLOWLIST_CHANGE"
	EffectLifecycleCreate    EffectClass = "LIFECYCLE_CREATE"
	EffectLifecycleResume    EffectClass = "LIFECYCLE_RESUME"
	EffectLifecycleTerminate EffectClass = "LIFECYCLE_TERMINATE"
)

// ClassifyEffect maps an actuator method name to its EffectClass.
func ClassifyEffect(method string) EffectClass {
	switch method {
	case "Create":
		return EffectLifecycleCreate
	case "Resume":
		return EffectLifecycleResume
	case "Pause", "Terminate":
		return EffectLifecycleTerminate
	case "Exec":
		return EffectExecShell
	case "ReadFile", "ListFiles":
		return EffectFSRead
	case "WriteFile":
		return EffectFSWrite
	case "AllowEgress":
		return EffectNetEgressChange
	default:
		return EffectExecShell // conservative: treat unknown as exec
	}
}

// ──────────────────────────────────────────────────────────────────
// SandboxActuator — the unified interface across all sandbox providers.
// Every provider adapter (OpenSandbox, E2B, Daytona, Docker, …) MUST
// implement this interface to be usable within HELM.
// ──────────────────────────────────────────────────────────────────

// SandboxActuator defines the canonical sandbox execution interface.
// It abstracts lifecycle, execution, filesystem, networking, and
// observability across all sandbox providers.
type SandboxActuator interface {
	// ── Lifecycle ────────────────────────────────────────────────

	// Create provisions a new sandbox from the given spec.
	Create(ctx context.Context, spec *SandboxSpec) (*SandboxHandle, error)

	// Resume restores a previously paused sandbox.
	// Returns ErrNotSupported if the provider lacks persistence.
	Resume(ctx context.Context, id string) (*SandboxHandle, error)

	// Pause suspends a running sandbox, preserving state.
	// Returns ErrNotSupported if the provider lacks persistence.
	Pause(ctx context.Context, id string) error

	// Terminate destroys a sandbox and releases all resources.
	Terminate(ctx context.Context, id string) error

	// ── Execution ───────────────────────────────────────────────

	// Exec runs a command inside the sandbox.
	// Returns a deterministic ExecResult with a receipt fragment.
	Exec(ctx context.Context, id string, req *ExecRequest) (*ExecResult, error)

	// ── Filesystem ──────────────────────────────────────────────

	// ReadFile reads a file from the sandbox filesystem.
	ReadFile(ctx context.Context, id string, path string) ([]byte, error)

	// WriteFile writes data to a file in the sandbox filesystem.
	WriteFile(ctx context.Context, id string, path string, data []byte) error

	// ListFiles lists entries in a sandbox directory.
	ListFiles(ctx context.Context, id string, dir string) ([]FileEntry, error)

	// ── Network ─────────────────────────────────────────────────

	// AllowEgress sets the egress rules for the sandbox.
	AllowEgress(ctx context.Context, id string, rules []EgressRule) error

	// ── Observability ───────────────────────────────────────────

	// Logs retrieves log entries from the sandbox.
	Logs(ctx context.Context, id string, opts *LogOptions) ([]LogEntry, error)

	// ── Preflight ───────────────────────────────────────────────

	// Preflight runs provider-specific security and configuration checks.
	// HELM MUST call Preflight before Create and refuse if StrictPassed is false.
	Preflight(ctx context.Context) (*PreflightReport, error)

	// ── Metadata ────────────────────────────────────────────────

	// Provider returns the provider identifier (e.g. "opensandbox", "e2b", "daytona").
	Provider() string
}

// ──────────────────────────────────────────────────────────────────
// Spec & Result Types
// ──────────────────────────────────────────────────────────────────

// SandboxSpec defines the desired sandbox configuration.
type SandboxSpec struct {
	// Runtime is the sandbox runtime/template (e.g. image tag, template ID).
	Runtime string `json:"runtime"`

	// Resources are the compute constraints.
	Resources ResourceSpec `json:"resources"`

	// Egress defines the default egress policy.
	Egress EgressPolicy `json:"egress"`

	// Mounts defines filesystem mounts into the sandbox.
	Mounts []MountSpec `json:"mounts,omitempty"`

	// Env is the environment variables to inject.
	Env map[string]string `json:"env,omitempty"`

	// WorkDir is the working directory inside the sandbox.
	WorkDir string `json:"workdir,omitempty"`

	// Labels are provider-agnostic metadata tags.
	Labels map[string]string `json:"labels,omitempty"`
}

// ResourceSpec constrains CPU, memory, disk, time, and processes.
type ResourceSpec struct {
	CPUMillis    int64         `json:"cpu_millis"`    // milliCPU (500 = 0.5 vCPU)
	MemoryMB     int64         `json:"memory_mb"`     // RAM cap
	DiskMB       int64         `json:"disk_mb"`       // scratch disk cap
	Timeout      time.Duration `json:"timeout"`       // max wall-clock execution time
	MaxProcesses int           `json:"max_processes"` // PID limit
}

// EgressPolicy defines the default network posture.
type EgressPolicy struct {
	// Disabled blocks all outbound traffic.
	Disabled bool `json:"disabled"`

	// DefaultAllowlist is the initial set of allowed egress destinations.
	DefaultAllowlist []EgressRule `json:"default_allowlist,omitempty"`
}

// EgressRule is a single egress allowlist entry.
type EgressRule struct {
	// Host is the destination hostname or CIDR.
	Host string `json:"host"`

	// Port is the destination port (0 = any).
	Port int `json:"port,omitempty"`

	// Protocol is "tcp" or "udp" (default "tcp").
	Protocol string `json:"protocol,omitempty"`
}

// MountSpec defines a filesystem mount.
type MountSpec struct {
	Source   string `json:"source"` // host/external path or volume name
	Target   string `json:"target"` // path inside sandbox
	ReadOnly bool   `json:"read_only"`
}

// ──────────────────────────────────────────────────────────────────
// Handle
// ──────────────────────────────────────────────────────────────────

// SandboxStatus represents the lifecycle state of a sandbox.
type SandboxStatus string

const (
	StatusCreating   SandboxStatus = "creating"
	StatusRunning    SandboxStatus = "running"
	StatusPaused     SandboxStatus = "paused"
	StatusTerminated SandboxStatus = "terminated"
	StatusError      SandboxStatus = "error"
)

// SandboxHandle is a reference to a provisioned sandbox instance.
type SandboxHandle struct {
	ID        string            `json:"id"`
	Provider  string            `json:"provider"`
	Status    SandboxStatus     `json:"status"`
	CreatedAt time.Time         `json:"created_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// ──────────────────────────────────────────────────────────────────
// Execution
// ──────────────────────────────────────────────────────────────────

// ExecRequest is a command to run inside a sandbox.
type ExecRequest struct {
	Command []string          `json:"command"`
	Env     map[string]string `json:"env,omitempty"`
	Stdin   []byte            `json:"stdin,omitempty"`
	WorkDir string            `json:"workdir,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"` // per-command timeout (overrides spec default)
}

// ExecResult is the outcome of a sandbox command execution.
type ExecResult struct {
	ExitCode  int           `json:"exit_code"`
	Stdout    []byte        `json:"stdout"`
	Stderr    []byte        `json:"stderr"`
	Duration  time.Duration `json:"duration"`
	OOMKilled bool          `json:"oom_killed"`
	TimedOut  bool          `json:"timed_out"`

	// Receipt is the deterministic receipt fragment for this execution.
	Receipt ReceiptFragment `json:"receipt"`
}

// Success returns true if the execution succeeded cleanly.
func (r *ExecResult) Success() bool {
	return r.ExitCode == 0 && !r.OOMKilled && !r.TimedOut
}

// ReceiptFragment is a self-contained proof of execution that maps into
// the HELM contracts.Receipt chain. The preimage binds the full security-
// relevant sandbox state, not just I/O hashes.
type ReceiptFragment struct {
	// RequestHash is SHA-256 of the canonicalized ExecRequest.
	RequestHash string `json:"request_hash"`

	// StdoutHash is SHA-256 of stdout bytes.
	StdoutHash string `json:"stdout_hash"`

	// StderrHash is SHA-256 of stderr bytes.
	StderrHash string `json:"stderr_hash"`

	// Provider is the sandbox provider that executed this.
	Provider string `json:"provider"`

	// ExecutedAt is the wall-clock time of execution start.
	ExecutedAt time.Time `json:"executed_at"`

	// ── Sandbox spec binding (P0 governance fields) ────────────

	// SandboxSpecHash is SHA-256 of the full canonicalized SandboxSpec.
	// Binds the execution environment into the receipt preimage.
	SandboxSpecHash string `json:"sandbox_spec_hash"`

	// ImageDigest is the resolved container/runtime image digest.
	ImageDigest string `json:"image_digest,omitempty"`

	// EgressPolicyHash is SHA-256 of the canonicalized EgressPolicy.
	EgressPolicyHash string `json:"egress_policy_hash"`

	// MountManifestHash is SHA-256 of the sorted mount manifest.
	MountManifestHash string `json:"mount_manifest_hash,omitempty"`

	// ResourceLimitsHash is SHA-256 of the canonicalized ResourceSpec.
	ResourceLimitsHash string `json:"resource_limits_hash"`

	// ExposedPortsHash is SHA-256 of any exposed port manifest.
	ExposedPortsHash string `json:"exposed_ports_hash,omitempty"`

	// Effect is the classified effect type for policy evaluation.
	Effect EffectClass `json:"effect"`
}

// ComputeSandboxSpecHash returns a deterministic SHA-256 hash of the
// full sandbox specification. This binds the execution environment
// into the receipt chain so governance can detect condition changes.
func ComputeSandboxSpecHash(spec *SandboxSpec) string {
	if spec == nil {
		return "sha256:" + hex.EncodeToString(sha256.New().Sum(nil))
	}
	canon, _ := json.Marshal(spec)
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}

// computeFieldHash is an internal helper for hashing arbitrary structs.
func computeFieldHash(v any) string {
	canon, _ := json.Marshal(v)
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}

// ComputeReceiptFragment creates a deterministic receipt fragment from
// an ExecRequest, raw outputs, and the sandbox specification.
// The spec is bound into the receipt preimage so governance can verify
// that execution conditions match policy expectations.
func ComputeReceiptFragment(req *ExecRequest, stdout, stderr []byte, provider string, executedAt time.Time, spec *SandboxSpec, effect EffectClass) ReceiptFragment {
	reqCanon, _ := json.Marshal(req)
	reqHash := sha256.Sum256(reqCanon)
	outHash := sha256.Sum256(stdout)
	errHash := sha256.Sum256(stderr)

	frag := ReceiptFragment{
		RequestHash:        "sha256:" + hex.EncodeToString(reqHash[:]),
		StdoutHash:         "sha256:" + hex.EncodeToString(outHash[:]),
		StderrHash:         "sha256:" + hex.EncodeToString(errHash[:]),
		Provider:           provider,
		ExecutedAt:         executedAt,
		SandboxSpecHash:    ComputeSandboxSpecHash(spec),
		ResourceLimitsHash: "",
		EgressPolicyHash:   "",
		Effect:             effect,
	}

	if spec != nil {
		frag.ResourceLimitsHash = computeFieldHash(spec.Resources)
		frag.EgressPolicyHash = computeFieldHash(spec.Egress)
		if len(spec.Mounts) > 0 {
			frag.MountManifestHash = computeFieldHash(spec.Mounts)
		}
		frag.ImageDigest = spec.Runtime // providers should resolve to digest
	}

	return frag
}

// ──────────────────────────────────────────────────────────────────
// Filesystem
// ──────────────────────────────────────────────────────────────────

// FileEntry is a single entry in a directory listing.
type FileEntry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	IsDir   bool      `json:"is_dir"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// ──────────────────────────────────────────────────────────────────
// Observability
// ──────────────────────────────────────────────────────────────────

// LogOptions controls which logs to retrieve.
type LogOptions struct {
	Since  time.Time `json:"since,omitempty"`
	Tail   int       `json:"tail,omitempty"`   // last N lines (0 = all)
	Stream string    `json:"stream,omitempty"` // "stdout", "stderr", or "" for both
}

// LogEntry is a single log line from a sandbox.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Stream    string    `json:"stream"` // "stdout" or "stderr"
	Line      string    `json:"line"`
}

// ──────────────────────────────────────────────────────────────────
// Preflight
// ──────────────────────────────────────────────────────────────────

// PreflightReport is the result of provider preflight checks.
// HELM enforces fail-closed: if StrictPassed is false, sandbox creation is denied.
type PreflightReport struct {
	Provider     string           `json:"provider"`
	StrictPassed bool             `json:"strict_passed"`
	Checks       []PreflightCheck `json:"checks"`
	CheckedAt    time.Time        `json:"checked_at"`
}

// PreflightCheck is a single preflight verification.
type PreflightCheck struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Required bool   `json:"required"` // if true, failure causes StrictPassed=false
	Reason   string `json:"reason,omitempty"`
}

// ──────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────

// ErrNotSupported is returned when a provider does not support an operation
// (e.g. Pause/Resume on a stateless provider).
var ErrNotSupported = fmt.Errorf("sandbox: operation not supported by provider")

// ErrPreflightFailed is returned when preflight checks fail in strict mode.
var ErrPreflightFailed = fmt.Errorf("sandbox: preflight checks failed — strict mode denies execution")

// ErrSandboxNotFound is returned when the sandbox ID does not exist.
var ErrSandboxNotFound = fmt.Errorf("sandbox: not found")

// ErrSandboxTerminated is returned when an operation targets a terminated sandbox.
var ErrSandboxTerminated = fmt.Errorf("sandbox: already terminated")
