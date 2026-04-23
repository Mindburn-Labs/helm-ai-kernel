// Package memory — LKS/CKS separation for governed knowledge.
//
// Per HELM 2030 Spec §5.4:
//
//	HELM MUST separate untrusted learned memory from trusted curated knowledge.
//	LKS MAY influence plan generation. LKS MUST NOT authorize side effects.
//	Any LKS-derived claim needed for execution MUST be promoted into CKS
//	with provenance and ProofGraph linkage.
//
// Resolves: GAP-A5.
package memory

import "time"

// MemoryTier distinguishes learned vs curated knowledge.
type MemoryTier string

const (
	// TierLKS is the Learned Knowledge Store — untrusted, influence-only.
	TierLKS MemoryTier = "LKS"
	// TierCKS is the Curated Knowledge Store — trusted, may authorize.
	TierCKS MemoryTier = "CKS"
)

// MemoryEntry is a unit of governed knowledge.
type MemoryEntry struct {
	EntryID        string            `json:"entry_id"`
	Tier           MemoryTier        `json:"tier"`
	Namespace      string            `json:"namespace"`
	Key            string            `json:"key"`
	Value          string            `json:"value"`
	Source         string            `json:"source"`
	ProvenanceHash string            `json:"provenance_hash"`
	TrustScore     float64           `json:"trust_score"` // 0.0–1.0
	ReviewState    ReviewState       `json:"review_state"`
	TTL            *time.Duration    `json:"ttl,omitempty"`
	Tags           map[string]string `json:"tags,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	ContentHash    string            `json:"content_hash"`
}

// ReviewState tracks the review lifecycle of a memory entry.
type ReviewState string

const (
	ReviewPending  ReviewState = "PENDING"
	ReviewApproved ReviewState = "APPROVED"
	ReviewRejected ReviewState = "REJECTED"
	ReviewExpired  ReviewState = "EXPIRED"
)

// MemoryStore is the interface for governed knowledge storage.
type MemoryStore interface {
	Get(entryID string) (*MemoryEntry, error)
	Put(entry MemoryEntry) error
	Delete(entryID string) error
	List(tier MemoryTier, namespace string) ([]MemoryEntry, error)
	ByKey(namespace, key string) (*MemoryEntry, error)
}
