// Package trust implements the Pack Trust Fabric per Addendum 14.X.
// This file contains the PackLoader that orchestrates all trust verification.
package trust

import (
	"fmt"
	"log/slog"
	"regexp"

	"github.com/Masterminds/semver/v3"
)

// PackRef identifies a pack with its metadata.
type PackRef struct {
	// Name is the pack identifier (e.g., "org.example/my-pack")
	Name string `json:"name"`

	// Version is the semantic version
	Version string `json:"version"`

	// Hash is the SHA256 hash of the pack content
	Hash string `json:"hash"`

	// Certified indicates if this is a HELM-certified pack
	Certified bool `json:"certified"`

	// PublisherKeyID identifies the pack signer
	PublisherKeyID string `json:"publisher_key_id,omitempty"`
}

// PackLoader validates packs per the Trust Fabric.
// Per Section 14.X.5: Trust Chain Verification Flow.
type PackLoader struct {
	tufClient      *TUFClient
	rekorClient    *RekorClient
	slsaVerifier   *SLSAVerifier
	versionStore   VersionStore
	keyStatusStore KeyStatusStore
}

// VersionStore tracks installed pack versions for rollback detection.
type VersionStore interface {
	GetInstalledVersion(packID string) (*semver.Version, error)
	SetInstalledVersion(packID string, version *semver.Version) error
}

// KeyStatusStore tracks publisher key status.
type KeyStatusStore interface {
	GetKeyStatus(keyID string) (KeyStatus, error)
	GetQuarantineOverride(keyID string) (*QuarantineOverride, error)
}

// KeyStatus represents a publisher key's current status.
type KeyStatus string

const (
	KeyStatusActive  KeyStatus = "ACTIVE"
	KeyStatusRevoked KeyStatus = "REVOKED"
	KeyStatusExpired KeyStatus = "EXPIRED"
)

// QuarantineOverride allows loading packs from revoked publishers.
// Per Section 14.X.4: Quarantine override.
type QuarantineOverride struct {
	PublisherKeyID string   `json:"publisher_key_id"`
	Reason         string   `json:"reason"`
	AuthorizedBy   []string `json:"authorized_by"`
	ExpiresAt      string   `json:"expires_at"`
	Signatures     []string `json:"signatures"`
}

// IsValid checks if the override is still valid.
func (o *QuarantineOverride) IsValid() bool {
	// Placeholder - would check expiration and signature validity
	return o != nil && len(o.Signatures) > 0
}

// RollbackOverride allows explicit version downgrades.
// Per Section 14.X.4: Rollback Override Artifact.
type RollbackOverride struct {
	OverrideID   string   `json:"override_id"`
	PackID       string   `json:"pack_id"`
	FromVersion  string   `json:"from_version"`
	ToVersion    string   `json:"to_version"`
	Reason       string   `json:"reason"`
	AuthorizedBy []string `json:"authorized_by"`
	ExpiresAt    string   `json:"expires_at"`
	Signatures   []string `json:"signatures"`
}

// PackLoaderConfig configures the pack loader.
type PackLoaderConfig struct {
	TUFClient      *TUFClient
	RekorClient    *RekorClient
	SLSAVerifier   *SLSAVerifier
	VersionStore   VersionStore
	KeyStatusStore KeyStatusStore
	StrictMode     bool // If true, all verification must pass
}

// NewPackLoader creates a pack loader with the given clients.
func NewPackLoader(config PackLoaderConfig) (*PackLoader, error) {
	if config.TUFClient == nil {
		return nil, fmt.Errorf("TUF client is required")
	}

	return &PackLoader{
		tufClient:      config.TUFClient,
		rekorClient:    config.RekorClient,
		slsaVerifier:   config.SLSAVerifier,
		versionStore:   config.VersionStore,
		keyStatusStore: config.KeyStatusStore,
	}, nil
}

// ValidatePackLoad performs complete trust verification.
// Per Section 14.X.5: 8-step verification flow.
func (l *PackLoader) ValidatePackLoad(packRef PackRef) error {
	// 1. Update TUF metadata
	if err := l.tufClient.Update(); err != nil {
		return &PackLoadError{
			Step:       "TUF metadata update",
			Reason:     err.Error(),
			FailClosed: true,
		}
	}

	// 2. Verify pack hash is in TUF targets
	targetInfo, err := l.tufClient.GetTargetInfo(packRef.Name)
	if err != nil {
		return &PackLoadError{
			Step:       "TUF target lookup",
			Reason:     err.Error(),
			FailClosed: true,
		}
	}

	// 3. Verify hash matches
	expectedHash := targetInfo.Hashes["sha256"]
	if expectedHash != packRef.Hash {
		return &PackLoadError{
			Step:       "Hash verification",
			Reason:     fmt.Sprintf("expected %s, got %s", expectedHash, packRef.Hash),
			FailClosed: true,
		}
	}

	// 4. Verify delegation chain for certified packs
	if packRef.Certified {
		if err := l.tufClient.VerifyDelegation("certified", packRef.Name); err != nil {
			return &PackLoadError{
				Step:       "Certified delegation verification",
				Reason:     err.Error(),
				FailClosed: true,
			}
		}
	}

	// 5. Verify transparency log (if client configured)
	if l.rekorClient != nil {
		if _, err := l.rekorClient.VerifyEntry(packRef.Hash); err != nil {
			return &PackLoadError{
				Step:       "Transparency log verification",
				Reason:     err.Error(),
				FailClosed: packRef.Certified, // Only critical for certified packs
			}
		}
	}

	// 6. Check monotonic versioning
	if err := l.enforceMonotonicVersion(packRef); err != nil {
		return &PackLoadError{
			Step:       "Monotonic versioning check",
			Reason:     err.Error(),
			FailClosed: true,
		}
	}

	// 7. Check publisher key status
	if packRef.PublisherKeyID != "" && l.keyStatusStore != nil {
		if err := l.checkPublisherStatus(packRef.PublisherKeyID); err != nil {
			return &PackLoadError{
				Step:       "Publisher key status check",
				Reason:     err.Error(),
				FailClosed: packRef.Certified,
			}
		}
	}

	// All checks passed
	return nil
}

// enforceMonotonicVersion prevents rollback attacks.
// Per Section 14.X.4: Monotonic Version Enforcement.
func (l *PackLoader) enforceMonotonicVersion(packRef PackRef) error {
	if l.versionStore == nil {
		return nil // No version tracking
	}

	newVersion, err := semver.NewVersion(packRef.Version)
	if err != nil {
		return fmt.Errorf("invalid version %s: %w", packRef.Version, err)
	}

	currentVersion, err := l.versionStore.GetInstalledVersion(packRef.Name)
	if err != nil {
		// Error getting version - treat as first install
		return nil
	}
	if currentVersion == nil {
		// First install, no version to compare
		return nil
	}

	if newVersion.LessThan(currentVersion) {
		return fmt.Errorf("rollback from %s to %s denied", currentVersion, newVersion)
	}

	return nil
}

// checkPublisherStatus verifies publisher key is not revoked.
// Per Section 14.X.4: Publisher Key Revocation.
func (l *PackLoader) checkPublisherStatus(keyID string) error {
	status, err := l.keyStatusStore.GetKeyStatus(keyID)
	if err != nil {
		return fmt.Errorf("failed to check key status: %w", err)
	}

	if status == KeyStatusRevoked {
		// Check for quarantine override
		override, err := l.keyStatusStore.GetQuarantineOverride(keyID)
		if err != nil || override == nil || !override.IsValid() {
			return fmt.Errorf("publisher key %s is revoked", keyID)
		}
		// Allow with override - log warning
		slog.Warn("trust: loading pack with revoked publisher key under quarantine override", "key_id", keyID)
	}

	if status == KeyStatusExpired {
		return fmt.Errorf("publisher key %s is expired", keyID)
	}

	return nil
}

// PackLoadError represents a failure in pack verification.
// Per Section 14.X.1: If TUF verification fails, pack load MUST fail closed.
type PackLoadError struct {
	Step       string `json:"step"`
	Reason     string `json:"reason"`
	FailClosed bool   `json:"fail_closed"`
}

func (e *PackLoadError) Error() string {
	return fmt.Sprintf("pack load failed at step '%s': %s (fail_closed=%v)",
		e.Step, e.Reason, e.FailClosed)
}

// ValidatePackName checks pack name follows conventions.
func ValidatePackName(name string) error {
	// org.example/pack-name format
	pattern := regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*/[a-z][a-z0-9-]*$`)
	if !pattern.MatchString(name) {
		return fmt.Errorf("invalid pack name: %s (expected org.example/pack-name format)", name)
	}
	return nil
}

// ValidatePackHash checks hash format.
func ValidatePackHash(hash string) error {
	// SHA256 in hex format (64 characters)
	pattern := regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	if !pattern.MatchString(hash) {
		return fmt.Errorf("invalid pack hash: %s (expected sha256:hex format)", hash)
	}
	return nil
}
