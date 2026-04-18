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

	"gopkg.in/yaml.v3"
)

// PackChannel controls where an installable add-on can be surfaced.
type PackChannel string

const (
	// PackChannelCore marks a first-party HELM pack shipping with OSS.
	PackChannelCore PackChannel = "core"
	// PackChannelCommunity marks an unsigned/community-published pack.
	PackChannelCommunity PackChannel = "community"
	// PackChannelTeams marks a paid-tier pack gated by the commercial layer.
	PackChannelTeams PackChannel = "teams"
	// PackChannelEnterprise marks an enterprise-only pack gated by the commercial layer.
	PackChannelEnterprise PackChannel = "enterprise"
)

// PackExtensionPoint is a declared integration seam for installable packs.
type PackExtensionPoint string

const (
	// PackExtensionRoute is a Studio route surface.
	PackExtensionRoute PackExtensionPoint = "route"
	// PackExtensionPanel is a Studio panel surface.
	PackExtensionPanel PackExtensionPoint = "panel"
	// PackExtensionConnector is an execution-side connector surface.
	PackExtensionConnector PackExtensionPoint = "connector"
	// PackExtensionJob is a background job surface.
	PackExtensionJob PackExtensionPoint = "job"
	// PackExtensionSetting is a settings extension point.
	PackExtensionSetting PackExtensionPoint = "setting"
	// PackExtensionPolicy is a policy contribution point.
	PackExtensionPolicy PackExtensionPoint = "policy"
	// PackExtensionDocs is a documentation contribution point.
	PackExtensionDocs PackExtensionPoint = "docs"
)

// PackPermission declares a runtime capability requested by a pack.
type PackPermission struct {
	ID            string `json:"id" yaml:"id"`
	Justification string `json:"justification" yaml:"justification"`
}

// PackSecret declares a secret required during install or runtime.
type PackSecret struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
	Required    bool   `json:"required" yaml:"required"`
}

// PackCheck declares a deterministic install, smoke, or rollback check.
type PackCheck struct {
	ID          string `json:"id" yaml:"id"`
	Description string `json:"description" yaml:"description"`
	Command     string `json:"command,omitempty" yaml:"command,omitempty"`
}

// PackSignature attests to the integrity of a published pack.
type PackSignature struct {
	SignerID  string    `json:"signer_id" yaml:"signer_id"`
	KeyID     string    `json:"key_id,omitempty" yaml:"key_id,omitempty"`
	Algorithm string    `json:"algorithm" yaml:"algorithm"`
	SignedAt  time.Time `json:"signed_at" yaml:"signed_at"`
	Signature string    `json:"signature" yaml:"signature"`
}

// PackManifestV2 is the canonical manifest for one-click installable HELM
// add-ons. MinimumEdition is kept as an untyped string in OSS so this package
// does not depend on commercial Edition/Capability types; entitlement
// enforcement is layered on top in the commercial control plane.
type PackManifestV2 struct {
	PackID          string               `json:"pack_id" yaml:"pack_id"`
	Name            string               `json:"name" yaml:"name"`
	Version         string               `json:"version" yaml:"version"`
	Channel         PackChannel          `json:"channel" yaml:"channel"`
	Summary         string               `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description     string               `json:"description,omitempty" yaml:"description,omitempty"`
	MinimumEdition  string               `json:"minimum_edition" yaml:"minimum_edition"`
	ExtensionPoints []PackExtensionPoint `json:"extension_points,omitempty" yaml:"extension_points,omitempty"`
	Dependencies    []string             `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Permissions     []PackPermission     `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	Secrets         []PackSecret         `json:"secrets,omitempty" yaml:"secrets,omitempty"`
	Migrations      []PackCheck          `json:"migrations,omitempty" yaml:"migrations,omitempty"`
	InstallChecks   []PackCheck          `json:"install_checks,omitempty" yaml:"install_checks,omitempty"`
	SmokeTests      []PackCheck          `json:"smoke_tests,omitempty" yaml:"smoke_tests,omitempty"`
	RollbackChecks  []PackCheck          `json:"rollback_checks,omitempty" yaml:"rollback_checks,omitempty"`
	Docs            []string             `json:"docs,omitempty" yaml:"docs,omitempty"`
	Signatures      []PackSignature      `json:"signatures,omitempty" yaml:"signatures,omitempty"`
}

// InstalledPack is the runtime state of a pack after installation.
type InstalledPack struct {
	PackID      string     `json:"pack_id"`
	Version     string     `json:"version"`
	Status      string     `json:"status"`
	InstalledAt *time.Time `json:"installed_at,omitempty"`
}

// PackInstallPlan describes the canonical install flow served to Studio
// before activation. IneligibleReasons carries plain-string diagnostics so the
// OSS contract is decoupled from the commercial Capability type; the
// commercial wrapper layer maps reasons to enterprise capability tokens.
type PackInstallPlan struct {
	PackID            string   `json:"pack_id"`
	Version           string   `json:"version"`
	Action            string   `json:"action,omitempty"`
	DryRun            bool     `json:"dry_run"`
	Eligible          bool     `json:"eligible"`
	RequiresUpgrade   bool     `json:"requires_upgrade,omitempty"`
	MinimumEdition    string   `json:"minimum_edition,omitempty"`
	CurrentVersion    string   `json:"current_version,omitempty"`
	Steps             []string `json:"steps"`
	IneligibleReasons []string `json:"ineligible_reasons,omitempty"`
	MissingSecrets    []string `json:"missing_secrets,omitempty"`
}

// VerificationResult captures the outcome of verifying a PackManifestV2
// against its raw bytes and optionally a claimed manifest hash.
type VerificationResult struct {
	Verified         bool
	VerificationMode string // "signed" or "integrity"
	ManifestHash     string
	Checks           []string
	Errors           []string
}

// LoadManifest reads a manifest from disk (routing YAML/JSON by file
// extension) and returns the parsed PackManifestV2 plus the raw file bytes.
func LoadManifest(path string) (PackManifestV2, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PackManifestV2{}, nil, fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := ParseManifest(data, filepath.Ext(path))
	if err != nil {
		return PackManifestV2{}, data, err
	}
	return manifest, data, nil
}

// ParseManifest parses manifest bytes as YAML or JSON. ext is the file
// extension (including dot) and routes decoding. YAML is decoded into
// map[string]any, then re-encoded as JSON and decoded into the struct — so
// every field routes through the struct's json tags without a parallel
// yaml-only decoder path.
func ParseManifest(data []byte, ext string) (PackManifestV2, error) {
	var manifest PackManifestV2
	switch strings.ToLower(ext) {
	case ".yaml", ".yml":
		var raw map[string]any
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return manifest, fmt.Errorf("parse yaml manifest: %w", err)
		}
		raw = normalizeYAMLMap(raw)
		bridge, err := json.Marshal(raw)
		if err != nil {
			return manifest, fmt.Errorf("re-encode yaml manifest: %w", err)
		}
		if err := json.Unmarshal(bridge, &manifest); err != nil {
			return manifest, fmt.Errorf("decode yaml manifest: %w", err)
		}
	case ".json", "":
		if err := json.Unmarshal(data, &manifest); err != nil {
			return manifest, fmt.Errorf("parse json manifest: %w", err)
		}
	default:
		return manifest, fmt.Errorf("parse manifest: unsupported extension %q", ext)
	}

	// Default channel to community when absent; matches prior behaviour for
	// unsigned/unclassified packs.
	if strings.TrimSpace(string(manifest.Channel)) == "" {
		manifest.Channel = PackChannelCommunity
	}
	return manifest, nil
}

// Verify checks that data hashes to claimedHash (when non-empty) and that
// the manifest contains the minimum fields required to install it.
func Verify(manifest PackManifestV2, data []byte, claimedHash string) VerificationResult {
	result := VerificationResult{
		Verified:     true,
		ManifestHash: ComputeManifestHash(data),
		Checks:       []string{"manifest loaded", "manifest hash recomputed"},
	}
	if claimedHash != "" && claimedHash != result.ManifestHash {
		result.Verified = false
		result.Errors = append(result.Errors, fmt.Sprintf("manifest hash mismatch: claimed=%s computed=%s", claimedHash, result.ManifestHash))
	}
	if strings.TrimSpace(manifest.PackID) == "" {
		result.Verified = false
		result.Errors = append(result.Errors, "manifest missing pack_id")
	}
	if strings.TrimSpace(manifest.Name) == "" {
		result.Verified = false
		result.Errors = append(result.Errors, "manifest missing name")
	}
	if strings.TrimSpace(manifest.Version) == "" {
		result.Verified = false
		result.Errors = append(result.Errors, "manifest missing version")
	}
	if strings.TrimSpace(string(manifest.Channel)) == "" {
		result.Verified = false
		result.Errors = append(result.Errors, "manifest missing channel")
	}

	if len(manifest.Signatures) > 0 {
		result.VerificationMode = "signed"
		result.Checks = append(result.Checks, "publisher signature present")
	} else {
		result.VerificationMode = "integrity"
		result.Checks = append(result.Checks, "no publisher signature; integrity-only verification")
	}
	return result
}

// ComputeManifestHash returns the "sha256:<hex>" content hash for data.
func ComputeManifestHash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// canonicalManifestBytes returns a stable JSON encoding of manifest for
// hashing. Fields are encoded via the struct's json tags.
func canonicalManifestBytes(manifest PackManifestV2) []byte {
	data, err := json.Marshal(manifest)
	if err != nil {
		// Unreachable for a valid PackManifestV2, but surface a deterministic
		// fallback rather than panic.
		return []byte(fmt.Sprintf("ERROR:%s", err.Error()))
	}
	return data
}

// normalizeYAMLMap recursively converts map[any]any values emitted by
// yaml.v3 for nested maps into map[string]any so downstream json.Marshal
// works without custom marshalers. []any elements are normalized in place.
func normalizeYAMLMap(in map[string]any) map[string]any {
	for k, v := range in {
		in[k] = normalizeYAMLValue(v)
	}
	return in
}

func normalizeYAMLValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return normalizeYAMLMap(t)
	case map[any]any:
		converted := make(map[string]any, len(t))
		for k, inner := range t {
			converted[fmt.Sprintf("%v", k)] = normalizeYAMLValue(inner)
		}
		return converted
	case []any:
		for i, item := range t {
			t[i] = normalizeYAMLValue(item)
		}
		return t
	default:
		return v
	}
}
