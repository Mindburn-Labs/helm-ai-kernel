// Package trust implements the Pack Trust Fabric per Addendum 14.X.
// This package provides TUF-based secure software updates, transparency log
// verification, and SLSA provenance validation.
package trust

import (
	"crypto"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// TUFRole represents a TUF role type.
// Per Section 14.X.1: root, timestamp, snapshot, targets, delegations.
type TUFRole string

// TUFRole constants for TUF metadata roles.
const (
	TUFRoleRoot      TUFRole = "root"
	TUFRoleTimestamp TUFRole = "timestamp"
	TUFRoleSnapshot  TUFRole = "snapshot"
	TUFRoleTargets   TUFRole = "targets"
)

// Explicit TUF Metadata Structures (Spec 14.X.1)

type RootMetadata struct {
	Type       string          `json:"_type"`
	Expires    string          `json:"expires"`
	Version    int             `json:"version"`
	Keys       map[string]Key  `json:"keys"`
	Roles      map[string]Role `json:"roles"`
	Consistent bool            `json:"consistent_snapshot"`
}

type Key struct {
	KeyType string `json:"keytype"`
	KeyVal  KeyVal `json:"keyval"`
	Scheme  string `json:"scheme"`
}

type KeyVal struct {
	Public string `json:"public"`
}

type Role struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

type Target struct {
	Hashes map[string]string `json:"hashes"`
	Length int               `json:"length"`
}

// TUFMetadata represents the complete TUF metadata state.
// Per Section 14.X.1: All metadata files are cryptographically signed.
type TUFMetadata struct {
	Root      *SignedRole `json:"root"`
	Timestamp *SignedRole `json:"timestamp"`
	Snapshot  *SignedRole `json:"snapshot"`
	Targets   *SignedRole `json:"targets"`
}

// SignedRole represents a signed TUF role.
type SignedRole struct {
	Signed     json.RawMessage `json:"signed"`
	Signatures []TUFSignature  `json:"signatures"`
}

// TUFSignature represents a signature on TUF metadata.
type TUFSignature struct {
	KeyID     string `json:"keyid"`
	Signature string `json:"sig"`
}

// RoleMetadata contains the common fields for all TUF roles.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type RoleMetadata struct {
	Type        string    `json:"_type"`
	Version     int       `json:"version"`
	Expires     time.Time `json:"expires"`
	SpecVersion string    `json:"spec_version"`
}

// TargetsMetadata represents the targets.json metadata.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type TargetsMetadata struct {
	RoleMetadata
	Targets     map[string]TargetInfo `json:"targets"`
	Delegations *Delegations          `json:"delegations,omitempty"`
}

// TargetInfo represents information about a target file.
type TargetInfo struct {
	Length int64             `json:"length"`
	Hashes map[string]string `json:"hashes"`
	Custom json.RawMessage   `json:"custom,omitempty"`
}

// Delegations represents TUF delegations.
// Per Section 14.X.1: certified/ (HELM-signed) and community/ (publisher).
type Delegations struct {
	Keys  map[string]TUFKey `json:"keys"`
	Roles []DelegatedRole   `json:"roles"`
}

// DelegatedRole represents a delegated TUF role.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type DelegatedRole struct {
	Name        string   `json:"name"`
	KeyIDs      []string `json:"keyids"`
	Threshold   int      `json:"threshold"`
	Paths       []string `json:"paths"`
	Terminating bool     `json:"terminating"`
}

// TUFClient implements the TUF client per Section 14.X.6.
// It handles metadata fetching, verification, and target lookups.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type TUFClient struct {
	// rootKeys are the trusted root keys for bootstrapping
	rootKeys []crypto.PublicKey

	// localMetadata is the currently trusted metadata
	localMetadata *TUFMetadata

	// remoteURL is the TUF repository URL
	remoteURL string

	// trustStore persists trusted metadata across runs
	trustStore TrustStore
}

// Store persists TUF metadata across runs.
//
//nolint:revive // naming: legacy interface name, widely used
type TrustStore interface {
	// Load retrieves stored TUF metadata
	Load() (*TUFMetadata, error)
	// Save persists TUF metadata
	Save(metadata *TUFMetadata) error
}

// TUFClientConfig configures the TUF client.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type TUFClientConfig struct {
	// RemoteURL is the TUF repository URL
	RemoteURL string

	// RootKeys are the trusted root public keys
	RootKeys []crypto.PublicKey

	// TrustStore persists metadata
	TrustStore TrustStore

	// MaxRootRotations limits root key rotations (anti-freeze attack)
	MaxRootRotations int
}

// NewTUFClient creates a new TUF client.
// Per Section 14.X.1: Clients detect rollback, freeze, and mix-and-match attacks.
func NewTUFClient(config TUFClientConfig) (*TUFClient, error) {
	if config.RemoteURL == "" {
		return nil, fmt.Errorf("TUF remote URL is required")
	}
	if len(config.RootKeys) == 0 {
		return nil, fmt.Errorf("at least one root key is required for TUF bootstrapping")
	}
	if config.MaxRootRotations == 0 {
		config.MaxRootRotations = 10 // Reasonable default
	}

	client := &TUFClient{
		rootKeys:   config.RootKeys,
		remoteURL:  config.RemoteURL,
		trustStore: config.TrustStore,
	}

	// Load existing metadata if available
	if config.TrustStore != nil {
		metadata, err := config.TrustStore.Load()
		if err == nil && metadata != nil {
			client.localMetadata = metadata
		}
	}

	return client, nil
}

// Update fetches and verifies fresh TUF metadata.
// Per Section 14.X.1: TUF metadata update sequence.
func (c *TUFClient) Update() error {
	// 1. Fetch and verify timestamp
	newTimestamp, err := c.fetchAndVerify(TUFRoleTimestamp)
	if err != nil {
		return fmt.Errorf("timestamp verification failed: %w", err)
	}

	// 2. Check timestamp freshness
	if err := c.checkFreshness(newTimestamp); err != nil {
		return fmt.Errorf("timestamp freshness check failed: %w", err)
	}

	// 3. Fetch and verify snapshot
	newSnapshot, err := c.fetchAndVerify(TUFRoleSnapshot)
	if err != nil {
		return fmt.Errorf("snapshot verification failed: %w", err)
	}

	// 4. Verify version increases (anti-rollback)
	if c.localMetadata != nil && c.localMetadata.Snapshot != nil {
		if err := c.verifyVersionIncrease(newSnapshot, c.localMetadata.Snapshot); err != nil {
			return fmt.Errorf("rollback attack detected: %w", err)
		}
	}

	// 5. Fetch and verify targets
	newTargets, err := c.fetchAndVerify(TUFRoleTargets)
	if err != nil {
		return fmt.Errorf("targets verification failed: %w", err)
	}

	// 6. Update local metadata
	c.localMetadata = &TUFMetadata{
		Timestamp: newTimestamp,
		Snapshot:  newSnapshot,
		Targets:   newTargets,
	}

	// 7. Persist to trust store
	if c.trustStore != nil {
		if err := c.trustStore.Save(c.localMetadata); err != nil {
			// Log but don't fail - metadata is still valid in memory
			slog.Warn("trust: failed to persist TUF metadata", "error", err)
		}
	}

	return nil
}

// GetTargetInfo retrieves target information for a pack.
// Per Section 14.X.1: Verify pack hash is in targets.
func (c *TUFClient) GetTargetInfo(packName string) (*TargetInfo, error) {
	if c.localMetadata == nil || c.localMetadata.Targets == nil {
		return nil, fmt.Errorf("no targets metadata available")
	}

	// Parse targets metadata
	var targets TargetsMetadata
	if err := json.Unmarshal(c.localMetadata.Targets.Signed, &targets); err != nil {
		return nil, fmt.Errorf("failed to parse targets metadata: %w", err)
	}

	// Look up target
	info, exists := targets.Targets[packName]
	if !exists {
		return nil, fmt.Errorf("pack %s not found in TUF targets", packName)
	}

	return &info, nil
}

// VerifyDelegation verifies that a pack is properly delegated.
// Per Section 14.X.1: certified and community delegations.
func (c *TUFClient) VerifyDelegation(delegationName, packName string) error {
	if c.localMetadata == nil || c.localMetadata.Targets == nil {
		return fmt.Errorf("no targets metadata available")
	}

	// Parse targets metadata
	var targets TargetsMetadata
	if err := json.Unmarshal(c.localMetadata.Targets.Signed, &targets); err != nil {
		return fmt.Errorf("failed to parse targets metadata: %w", err)
	}

	// Check delegations exist
	if targets.Delegations == nil {
		return fmt.Errorf("no delegations in targets metadata")
	}

	// Find the delegation
	var delegation *DelegatedRole
	for i := range targets.Delegations.Roles {
		if targets.Delegations.Roles[i].Name == delegationName {
			delegation = &targets.Delegations.Roles[i]
			break
		}
	}

	if delegation == nil {
		return fmt.Errorf("delegation %s not found", delegationName)
	}

	// Verify pack matches delegation paths
	matched := false
	for _, pattern := range delegation.Paths {
		if matchesPattern(pattern, packName) {
			matched = true
			break
		}
	}

	if !matched {
		return fmt.Errorf("pack %s does not match any delegation paths for %s", packName, delegationName)
	}

	return nil
}

// fetchAndVerify fetches and verifies a TUF role.
func (c *TUFClient) fetchAndVerify(role TUFRole) (*SignedRole, error) {
	// This is a placeholder - actual implementation would fetch from remoteURL
	// and verify signatures against known keys
	return nil, fmt.Errorf("TUF fetch not yet implemented for role: %s", role)
}

// checkFreshness verifies metadata has not expired.
// Per Section 14.X.4: Timestamp role has short expiry.
func (c *TUFClient) checkFreshness(signed *SignedRole) error {
	if signed == nil {
		return fmt.Errorf("nil signed role")
	}

	var meta RoleMetadata
	if err := json.Unmarshal(signed.Signed, &meta); err != nil {
		return fmt.Errorf("failed to parse role metadata: %w", err)
	}

	if time.Now().After(meta.Expires) {
		return fmt.Errorf("TUF metadata expired at %s", meta.Expires)
	}

	return nil
}

// verifyVersionIncrease ensures monotonic versioning.
// Per Section 14.X.4: Version numbers never decrease.
func (c *TUFClient) verifyVersionIncrease(newRole, existingRole *SignedRole) error {
	if existingRole == nil {
		return nil // No existing role to compare
	}

	var newMeta, existingMeta RoleMetadata
	if err := json.Unmarshal(newRole.Signed, &newMeta); err != nil {
		return fmt.Errorf("failed to parse new metadata: %w", err)
	}
	if err := json.Unmarshal(existingRole.Signed, &existingMeta); err != nil {
		return fmt.Errorf("failed to parse existing metadata: %w", err)
	}

	if newMeta.Version < existingMeta.Version {
		return fmt.Errorf("version rollback detected: %d < %d", newMeta.Version, existingMeta.Version)
	}

	return nil
}

// matchesPattern checks if a pack name matches a TUF delegation pattern.
func matchesPattern(pattern, packName string) bool {
	// Simple glob matching - actual implementation would use proper glob
	if pattern == "*" {
		return true
	}
	if pattern == packName {
		return true
	}
	// Add more sophisticated matching as needed
	return false
}
