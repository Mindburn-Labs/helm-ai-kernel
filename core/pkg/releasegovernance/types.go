// Package releasegovernance defines the public contracts for HELM's release governance.
//
// Release governance provides typed envelopes for signed releases, staged rollout
// manifests, rollback semantics, and trust-preserving migration types. This ensures
// that every version transition maintains the governance chain.
package releasegovernance

import "time"

// ReleaseEnvelope is a signed release artifact with provenance.
type ReleaseEnvelope struct {
	ReleaseID       string            `json:"release_id"`
	Component       string            `json:"component"` // "kernel", "pack", "connector"
	Version         string            `json:"version"`
	ContentHash     string            `json:"content_hash"`
	Compatibility   CompatMetadata    `json:"compatibility"`
	Signature       string            `json:"signature"`
	SignerID        string            `json:"signer_id"`
	SignerPublicKey string            `json:"signer_public_key,omitempty"`
	ReleasedAt      time.Time         `json:"released_at"`
	Provenance      map[string]string `json:"provenance,omitempty"`
}

// CompatMetadata describes version compatibility constraints.
type CompatMetadata struct {
	MinKernelVersion string   `json:"min_kernel_version,omitempty"`
	MaxKernelVersion string   `json:"max_kernel_version,omitempty"`
	RequiredPacks    []string `json:"required_packs,omitempty"`
	BreakingChanges  []string `json:"breaking_changes,omitempty"`
	DeprecatedAPIs   []string `json:"deprecated_apis,omitempty"`
}

// RolloutManifest defines a staged rollout plan.
type RolloutManifest struct {
	ManifestID string         `json:"manifest_id"`
	ReleaseID  string         `json:"release_id"`
	Stages     []RolloutStage `json:"stages"`
	CreatedAt  time.Time      `json:"created_at"`
}

// RolloutStage is a single stage in a rollout plan.
type RolloutStage struct {
	StageID     string        `json:"stage_id"`
	Name        string        `json:"name"`
	Percentage  int           `json:"percentage"` // 0-100
	Duration    time.Duration `json:"duration"`
	GatePolicy  string        `json:"gate_policy,omitempty"` // Policy ref for promotion gate
	Status      string        `json:"status"`                // "PENDING", "ACTIVE", "COMPLETE", "ROLLED_BACK"
}

// RollbackSpec defines the semantics for rolling back a release.
type RollbackSpec struct {
	TargetVersion   string `json:"target_version"`
	PreserveState   bool   `json:"preserve_state"`
	PreserveTruth   bool   `json:"preserve_truth"`
	MigrationPolicy string `json:"migration_policy,omitempty"`
}

// MigrationEnvelope wraps a trust-preserving migration between versions.
type MigrationEnvelope struct {
	MigrationID  string    `json:"migration_id"`
	FromVersion  string    `json:"from_version"`
	ToVersion    string    `json:"to_version"`
	TruthEpoch   string    `json:"truth_epoch"`
	ReceiptChain []string  `json:"receipt_chain"` // Receipt IDs proving governance continuity
	ExecutedAt   time.Time `json:"executed_at"`
	ContentHash  string    `json:"content_hash"`
	Signature    string    `json:"signature,omitempty"`
}
