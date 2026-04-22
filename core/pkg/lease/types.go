// Package lease manages the lifecycle of execution leases — bounded,
// time-limited allocations of sandbox resources for approved effect graphs.
//
// An ExecutionLease binds an approved evaluation result to a specific
// sandbox backend, workspace, network policy, and set of scoped credentials.
// Leases follow a strict state machine: PENDING → ACTIVE → COMPLETED/EXPIRED/REVOKED.
package lease

import "time"

// LeaseStatus represents the lifecycle state of an execution lease.
type LeaseStatus string

const (
	LeaseStatusPending   LeaseStatus = "PENDING"
	LeaseStatusActive    LeaseStatus = "ACTIVE"
	LeaseStatusCompleted LeaseStatus = "COMPLETED"
	LeaseStatusExpired   LeaseStatus = "EXPIRED"
	LeaseStatusRevoked   LeaseStatus = "REVOKED"
)

// ExecutionLease binds an approved effect graph to a sandbox execution context.
type ExecutionLease struct {
	// LeaseID is the unique identifier for this lease.
	LeaseID string `json:"lease_id"`

	// RunID links the lease to a specific run.
	RunID string `json:"run_id"`

	// SandboxID is the assigned sandbox identifier (set on activation).
	SandboxID string `json:"sandbox_id,omitempty"`

	// WorkspacePath is the local workspace directory.
	WorkspacePath string `json:"workspace_path"`

	// TemplateRef identifies the sandbox template to use.
	TemplateRef string `json:"template_ref,omitempty"`

	// Backend is the execution backend: "docker", "wasi", "native".
	Backend string `json:"backend"`

	// ProfileName is the sandbox profile.
	ProfileName string `json:"profile_name,omitempty"`

	// NetworkPolicyRef references the network policy configuration.
	NetworkPolicyRef string `json:"network_policy_ref,omitempty"`

	// SecretBindings lists credentials scoped to this lease.
	SecretBindings []SecretBinding `json:"secret_bindings,omitempty"`

	// TTL is the maximum duration before the lease expires.
	TTL time.Duration `json:"ttl"`

	// Status is the current lifecycle state.
	Status LeaseStatus `json:"status"`

	// EffectGraphHash links back to the approved evaluation result.
	EffectGraphHash string `json:"effect_graph_hash"`

	// CreatedAt is when the lease was created.
	CreatedAt time.Time `json:"created_at"`

	// ActivatedAt is when the lease transitioned to ACTIVE.
	ActivatedAt time.Time `json:"activated_at,omitempty"`

	// ExpiresAt is the absolute expiry time.
	ExpiresAt time.Time `json:"expires_at"`

	// CompletedAt is when the lease terminated (completed/expired/revoked).
	CompletedAt time.Time `json:"completed_at,omitempty"`

	// RevokeReason explains why the lease was revoked (if applicable).
	RevokeReason string `json:"revoke_reason,omitempty"`
}

// IsTerminal returns true if the lease is in a terminal state.
func (l *ExecutionLease) IsTerminal() bool {
	switch l.Status {
	case LeaseStatusCompleted, LeaseStatusExpired, LeaseStatusRevoked:
		return true
	}
	return false
}

// SecretBinding maps a credential to a mount path or env var in the sandbox.
type SecretBinding struct {
	// SecretRef is the credential identifier.
	SecretRef string `json:"secret_ref"`

	// MountPath is the filesystem path inside the sandbox (mutually exclusive with EnvVar).
	MountPath string `json:"mount_path,omitempty"`

	// EnvVar is the environment variable name (mutually exclusive with MountPath).
	EnvVar string `json:"env_var,omitempty"`

	// Scopes restricts what the credential can access.
	Scopes []string `json:"scopes,omitempty"`
}

// LeaseRequest is the input for acquiring a new lease.
type LeaseRequest struct {
	// RunID identifies the run.
	RunID string `json:"run_id"`

	// WorkspacePath is the workspace directory.
	WorkspacePath string `json:"workspace_path"`

	// Backend is the requested execution backend.
	Backend string `json:"backend"`

	// ProfileName is the requested sandbox profile.
	ProfileName string `json:"profile_name,omitempty"`

	// TemplateRef identifies the sandbox template.
	TemplateRef string `json:"template_ref,omitempty"`

	// TTL is the requested lease duration.
	TTL time.Duration `json:"ttl"`

	// EffectGraphHash binds to the approved evaluation.
	EffectGraphHash string `json:"effect_graph_hash"`

	// SecretBindings lists credentials to bind.
	SecretBindings []SecretBinding `json:"secret_bindings,omitempty"`
}
