// Package contracts — Isolated worker and phenotype-worker binding.
//
// Per HELM 2030 Spec §6.1.3 / §5.5:
//
//	HELM AI Kernel MUST include isolated worker execution and
//	phenotype-bound worker semantics.
//
// Resolves: GAP-A23, GAP-A9.
package contracts

import "time"

// IsolationLevel defines the degree of worker isolation.
type IsolationLevel string

const (
	IsolationNone      IsolationLevel = "NONE"
	IsolationProcess   IsolationLevel = "PROCESS"
	IsolationContainer IsolationLevel = "CONTAINER"
	IsolationVM        IsolationLevel = "VM"
	IsolationSandbox   IsolationLevel = "SANDBOX"
)

// IsolatedWorker defines a worker with enforced capability boundaries.
type IsolatedWorker struct {
	WorkerID     string         `json:"worker_id"`
	Name         string         `json:"name"`
	Isolation    IsolationLevel `json:"isolation"`
	Spec         WorkerSpec     `json:"spec"`
	PhenotypeID  string         `json:"phenotype_id,omitempty"` // bound phenotype
	AssignedRole string         `json:"assigned_role"`
	TTL          *time.Duration `json:"ttl,omitempty"`
	Status       string         `json:"status"` // "IDLE", "RUNNING", "STOPPED", "FAILED"
}

// WorkerSpec defines resource and capability limits for a worker.
type WorkerSpec struct {
	MaxMemoryMB    int      `json:"max_memory_mb"`
	MaxCPUCores    float64  `json:"max_cpu_cores"`
	MaxDiskMB      int      `json:"max_disk_mb,omitempty"`
	NetworkPolicy  string   `json:"network_policy"` // "NONE", "EGRESS_ONLY", "FULL"
	AllowedPaths   []string `json:"allowed_paths,omitempty"`
	BlockedPaths   []string `json:"blocked_paths,omitempty"`
	AllowedTools   []string `json:"allowed_tools,omitempty"`
	MaxBudgetCents int64    `json:"max_budget_cents,omitempty"`
}

// PhenotypeWorkerBinding binds a phenotype contract to a worker execution scope.
type PhenotypeWorkerBinding struct {
	BindingID   string    `json:"binding_id"`
	PhenotypeID string    `json:"phenotype_id"`
	WorkerID    string    `json:"worker_id"`
	EnforcedAt  time.Time `json:"enforced_at"`
	Active      bool      `json:"active"`
}
