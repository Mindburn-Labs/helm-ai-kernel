// Package contracts — Task Lineage, Spawn Boundary, Phenotype Binding, Idempotency, Retention, Dispute.
//
// Resolves: GAP-8, GAP-12, GAP-13, GAP-19, GAP-20, GAP-23.
package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// ── GAP-19: Task Lineage ─────────────────────────────────────────

// TaskLineageNode is a node in the first-class task lineage graph.
type TaskLineageNode struct {
	TaskID      string     `json:"task_id"`
	ParentID    string     `json:"parent_id,omitempty"`
	ActorID     string     `json:"actor_id"`
	ActionType  string     `json:"action_type"`
	Status      string     `json:"status"` // "PENDING", "RUNNING", "COMPLETED", "FAILED"
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Children    []string   `json:"children,omitempty"`
	ProofRef    string     `json:"proof_ref,omitempty"` // link to ProofGraph node
}

// ── GAP-20: Spawn Boundary ───────────────────────────────────────

// SpawnBoundary defines the constraints for subagent creation.
type SpawnBoundary struct {
	ParentID         string   `json:"parent_id"`
	MaxChildren      int      `json:"max_children"`
	AllowedEffects   []string `json:"allowed_effects"`
	InheritBudget    bool     `json:"inherit_budget"`
	BudgetCapCents   int64    `json:"budget_cap_cents,omitempty"`
	MaxDepth         int      `json:"max_depth"`
	RequiresApproval bool     `json:"requires_approval"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
}

// ── GAP-23: Phenotype-Worker Binding ─────────────────────────────

// PhenotypeBinding maps a phenotype to a worker specification.
type PhenotypeBinding struct {
	PhenotypeID  string            `json:"phenotype_id"`
	WorkerType   string            `json:"worker_type"` // "AGENT", "HUMAN", "SERVICE"
	WorkerID     string            `json:"worker_id"`
	Capabilities []string          `json:"capabilities"`
	Constraints  map[string]string `json:"constraints,omitempty"`
	Priority     int               `json:"priority"`
	ContentHash  string            `json:"content_hash"`
}

// NewPhenotypeBinding creates a binding with hash.
func NewPhenotypeBinding(phenotypeID, workerType, workerID string, capabilities []string) *PhenotypeBinding {
	pb := &PhenotypeBinding{
		PhenotypeID:  phenotypeID,
		WorkerType:   workerType,
		WorkerID:     workerID,
		Capabilities: capabilities,
	}
	canon, _ := json.Marshal(pb)
	h := sha256.Sum256(canon)
	pb.ContentHash = "sha256:" + hex.EncodeToString(h[:])
	return pb
}

// ── GAP-8: Idempotency ──────────────────────────────────────────

// IdempotencyKey tracks an operation to prevent double-execution.
type IdempotencyKey struct {
	Key         string    `json:"key"`
	OperationID string    `json:"operation_id"`
	Status      string    `json:"status"` // "IN_PROGRESS", "COMPLETED", "FAILED"
	ResultHash  string    `json:"result_hash,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// IdempotencyStore defines the interface for idempotency enforcement.
type IdempotencyStore interface {
	Check(key string) (*IdempotencyKey, bool)
	Acquire(key, operationID string, ttl time.Duration) (*IdempotencyKey, error)
	Complete(key, resultHash string) error
	Fail(key string) error
}

// ── GAP-12: Retention Hooks ─────────────────────────────────────

// RetentionPolicy defines evidence retention rules in OSS.
type RetentionPolicy struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	ResourceType  string `json:"resource_type"` // "EVIDENCE_PACK", "RECEIPT", "AUDIT_LOG", "PROOF"
	RetentionDays int    `json:"retention_days"`
	ArchiveAfter  int    `json:"archive_after_days,omitempty"`
	DeleteAfter   int    `json:"delete_after_days,omitempty"`
	ComplianceRef string `json:"compliance_ref,omitempty"` // e.g. "GDPR-Art17", "SOX-802"
}

// RetentionHook is a callback for retention lifecycle events.
type RetentionHook struct {
	Event        string `json:"event"` // "ARCHIVE", "DELETE", "EXTEND"
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	Reason       string `json:"reason"`
	ApprovedBy   string `json:"approved_by,omitempty"`
}

// ── GAP-13: Dispute Protocol ─────────────────────────────────────

// DisputeStatus tracks dispute lifecycle.
type DisputeStatus string

const (
	DisputeStatusOpen     DisputeStatus = "OPEN"
	DisputeStatusReview   DisputeStatus = "IN_REVIEW"
	DisputeStatusResolved DisputeStatus = "RESOLVED"
	DisputeStatusRejected DisputeStatus = "REJECTED"
)

// Dispute is a canonical dispute record.
type Dispute struct {
	ID          string        `json:"id"`
	TenantID    string        `json:"tenant_id"`
	RunID       string        `json:"run_id"`
	DisputedBy  string        `json:"disputed_by"`
	Reason      string        `json:"reason"`
	EvidenceIDs []string      `json:"evidence_ids"`
	Status      DisputeStatus `json:"status"`
	Resolution  string        `json:"resolution,omitempty"`
	ResolvedBy  string        `json:"resolved_by,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	ResolvedAt  *time.Time    `json:"resolved_at,omitempty"`
	ContentHash string        `json:"content_hash"`
}

// NewDispute creates a dispute.
func NewDispute(id, tenantID, runID, disputedBy, reason string, evidenceIDs []string) *Dispute {
	d := &Dispute{
		ID:          id,
		TenantID:    tenantID,
		RunID:       runID,
		DisputedBy:  disputedBy,
		Reason:      reason,
		EvidenceIDs: evidenceIDs,
		Status:      DisputeStatusOpen,
		CreatedAt:   time.Now().UTC(),
	}
	canon, _ := json.Marshal(struct {
		ID     string        `json:"id"`
		RunID  string        `json:"run_id"`
		By     string        `json:"by"`
		Status DisputeStatus `json:"status"`
	}{d.ID, d.RunID, d.DisputedBy, d.Status})
	h := sha256.Sum256(canon)
	d.ContentHash = "sha256:" + hex.EncodeToString(h[:])
	return d
}
