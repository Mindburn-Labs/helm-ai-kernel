package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"gopkg.in/yaml.v3"
)

// VerificationResult reports the outcome of verifying a pack manifest.
//
// Verified is true when structural parsing and content-hash recomputation
// succeed. It does NOT imply signature cryptographic validity — OSS
// performs integrity-only verification; commercial layers add publisher
// signature checks.
type VerificationResult struct {
	PackID           string   `json:"pack_id"`
	Verified         bool     `json:"verified"`
	VerificationMode string   `json:"verification_mode"` // "signed" | "integrity"
	SignerID         string   `json:"signer_id,omitempty"`
	Algorithm        string   `json:"algorithm"`
	ManifestHash     string   `json:"manifest_hash"`
	Checks           []string `json:"checks"`

	// InstallableChannel reports whether the manifest's channel is
	// installable by the OSS runtime (core or community). Teams and
	// enterprise channels return false here — commercial entitlement
	// logic gates those separately.
	InstallableChannel bool `json:"installable_channel"`
}

// LoadManifest reads a pack manifest from disk, parses it, and computes
// a content-addressed manifest hash. The hash is recomputed from the
// raw file bytes on every load so callers can verify on-disk integrity
// across moves.
//
// Supported formats: YAML (.yaml, .yml) and JSON (anything else). The
// raw file bytes — not the decoded struct — drive the content hash so
// round-trips do not mutate the hash.
func LoadManifest(path string) (contracts.PackManifestV2, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.PackManifestV2{}, "", fmt.Errorf("packs/install: read manifest %q: %w", path, err)
	}

	manifest, err := parseManifestBytes(data, filepath.Ext(path))
	if err != nil {
		return contracts.PackManifestV2{}, "", fmt.Errorf("packs/install: parse manifest %q: %w", path, err)
	}

	return manifest, hashBytes(data), nil
}

// ParseManifest parses raw manifest bytes. The ext argument selects the
// decoder (".yaml"/".yml" → YAML; anything else → JSON). The returned
// hash is content-addressed over the exact bytes passed in.
func ParseManifest(data []byte, ext string) (contracts.PackManifestV2, string, error) {
	manifest, err := parseManifestBytes(data, ext)
	if err != nil {
		return contracts.PackManifestV2{}, "", err
	}
	return manifest, hashBytes(data), nil
}

// Verify runs stateless manifest verification. Returns a
// VerificationResult describing integrity + signature presence and
// whether the manifest is installable by the OSS runtime.
//
// A valid manifest MUST have a non-empty PackID, Name, Version, and
// Channel. Unknown channels are rejected.
func Verify(manifest contracts.PackManifestV2, manifestHash string) (*VerificationResult, error) {
	if manifest.PackID == "" {
		return nil, fmt.Errorf("packs/install: manifest missing pack_id")
	}
	if manifest.Name == "" {
		return nil, fmt.Errorf("packs/install: manifest missing name")
	}
	if manifest.Version == "" {
		return nil, fmt.Errorf("packs/install: manifest missing version")
	}
	if !IsKnownChannel(manifest.Channel) {
		return nil, fmt.Errorf("packs/install: unknown channel %q", manifest.Channel)
	}

	checks := []string{"manifest loaded", "manifest hash recomputed"}
	mode := "integrity"
	signerID := "local-registry"
	algorithm := "sha256"
	if len(manifest.Signatures) > 0 {
		mode = "signed"
		signerID = manifest.Signatures[0].SignerID
		if a := strings.TrimSpace(manifest.Signatures[0].Algorithm); a != "" {
			algorithm = a
		}
		checks = append(checks, "publisher signature present")
	} else {
		checks = append(checks, "no publisher signature; integrity-only verification")
	}

	return &VerificationResult{
		PackID:             manifest.PackID,
		Verified:           true,
		VerificationMode:   mode,
		SignerID:           signerID,
		Algorithm:          algorithm,
		ManifestHash:       manifestHash,
		Checks:             checks,
		InstallableChannel: IsInstallableByOSS(manifest.Channel),
	}, nil
}

// IsKnownChannel reports whether a channel is one of the four recognized
// values (core, community, teams, enterprise).
func IsKnownChannel(ch contracts.PackChannel) bool {
	switch ch {
	case contracts.PackChannelCore,
		contracts.PackChannelCommunity,
		contracts.PackChannelTeams,
		contracts.PackChannelEnterprise:
		return true
	default:
		return false
	}
}

// IsInstallableByOSS reports whether the OSS install runtime can install
// a pack from this channel. Only core and community are installable by
// OSS; teams and enterprise require commercial entitlement logic.
func IsInstallableByOSS(ch contracts.PackChannel) bool {
	return ch == contracts.PackChannelCore || ch == contracts.PackChannelCommunity
}

// ComputeManifestHash returns the canonical content-address for raw
// manifest bytes. Exposed so callers can verify a manifest handed in by
// a caller (not loaded via LoadManifest).
func ComputeManifestHash(data []byte) string {
	return hashBytes(data)
}

func parseManifestBytes(data []byte, ext string) (contracts.PackManifestV2, error) {
	var manifest contracts.PackManifestV2
	switch strings.ToLower(strings.TrimPrefix(ext, ".")) {
	case "yaml", "yml":
		// Route YAML through JSON so the json: struct tags on
		// contracts.PackManifestV2 are honored. yaml.v3 alone maps Go
		// fields by lower-cased name (PackID → packid), which would
		// miss snake-case keys like pack_id.
		var raw map[string]any
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return contracts.PackManifestV2{}, err
		}
		asJSON, err := json.Marshal(raw)
		if err != nil {
			return contracts.PackManifestV2{}, err
		}
		if err := json.Unmarshal(asJSON, &manifest); err != nil {
			return contracts.PackManifestV2{}, err
		}
	default:
		if err := json.Unmarshal(data, &manifest); err != nil {
			return contracts.PackManifestV2{}, err
		}
	}
	// Default channel to community when absent — the original commercial
	// parser infers channel from directory layout; the OSS package takes
	// manifests at face value and requires callers to set Channel
	// explicitly or accept the community default.
	if manifest.Channel == "" {
		manifest.Channel = contracts.PackChannelCommunity
	}
	// Default algorithm + signed_at on signatures that omit them, so
	// VerificationResult is well-formed without requiring callers to
	// fully populate every field.
	now := time.Now().UTC()
	for i, sig := range manifest.Signatures {
		if sig.Algorithm == "" {
			manifest.Signatures[i].Algorithm = "sha256"
		}
		if sig.SignedAt.IsZero() {
			manifest.Signatures[i].SignedAt = now
		}
	}
	return manifest, nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
